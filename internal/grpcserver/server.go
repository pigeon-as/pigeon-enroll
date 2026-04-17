// Package grpcserver implements the four Enroll RPCs over mTLS.
//
// The server has exactly four verbs:
//
// Register - node attestation, issue identity cert (bootstrap CA accepted on TLS)
// Renew    - re-issue identity cert for already-attested caller (identity CA only)
// Read     - read-only resource path -> bytes (identity CA only)
// Write    - mutating resource path (pki/<role>, jwt/<n>) -> bytes (identity CA only)
//
// Caller context for Renew/Read/Write is extracted from the peer TLS cert:
//
// CN  -> subject
// OU  -> policy name  (capability check)
// O   -> identity name (PKI role lookup for Renew)
//
// pki.IssueIdentityCert and pki.SignIdentityCSR are the single authoritative
// shaping points for that encoding.
package grpcserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/attestor"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/identity"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/policy"
	"github.com/pigeon-as/pigeon-enroll/internal/resource"
	enrollv1 "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// serverCAName is the well-known CA under which the server's TLS listener
// cert is issued. It is also the CA whose public cert is shipped to clients
// via ConfigDrive so they can verify the server before Register.
const serverCAName = "identity"

// Options configures the server.
type Options struct {
	Hosts         []string
	ServerCertTTL time.Duration
	Logger        *slog.Logger
}

// Server implements enrollv1.EnrollServer.
type Server struct {
	enrollv1.UnimplementedEnrollServer

	cfg      *config.Config
	engine   *policy.Engine
	registry *identity.Registry
	resolver *resource.Resolver
	ikm      []byte
	serverCA *pki.CA
	log      *slog.Logger
	rotator  *pki.CertRotator
}

// New constructs a Server. The bootstrap CA pool, if any, flows to the
// bootstrap_cert attestor (see attestor.Build) — the server itself never
// needs it directly. Renew/Read/Write require a cert signed by the identity
// CA (enforced in callerFromPeer).
func New(
	cfg *config.Config,
	engine *policy.Engine,
	registry *identity.Registry,
	resolver *resource.Resolver,
	ikm []byte,
	opts Options,
) (*Server, error) {
	if cfg == nil || engine == nil || registry == nil || resolver == nil {
		return nil, errors.New("nil dependency")
	}
	if len(ikm) == 0 {
		return nil, errors.New("empty ikm")
	}
	if opts.ServerCertTTL <= 0 {
		opts.ServerCertTTL = 24 * time.Hour
	}
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}

	serverCA, err := pki.DeriveCAByName(ikm, serverCAName)
	if err != nil {
		return nil, fmt.Errorf("derive server CA %q: %w", serverCAName, err)
	}

	rotator := pki.NewCertRotator(serverCA, opts.Hosts, opts.ServerCertTTL)

	return &Server{
		cfg:      cfg,
		engine:   engine,
		registry: registry,
		resolver: resolver,
		ikm:      ikm,
		serverCA: serverCA,
		log:      opts.Logger,
		rotator:  rotator,
	}, nil
}

// TLSConfig returns the TLS config for the gRPC listener. Client certs are
// requested but not auto-verified; Register accepts any (bootstrap_cert
// attestor verifies explicitly), and Renew/Read/Write verify against the
// identity CA in callerFromPeer.
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: s.rotator.GetCertificate,
		ClientAuth:     tls.RequestClientCert,
	}
}

// GRPCServer returns a grpc.Server with the service registered and TLS
// credentials applied. The caller owns Serve/GracefulStop.
func (s *Server) GRPCServer() *grpc.Server {
	creds := credentials.NewTLS(s.TLSConfig())
	gs := grpc.NewServer(grpc.Creds(creds))
	enrollv1.RegisterEnrollServer(gs, s)
	return gs
}

// -----------------------------------------------------------------------------
// Register

func (s *Server) Register(stream grpc.BidiStreamingServer[enrollv1.RegisterRequest, enrollv1.RegisterResponse]) error {
	ctx := stream.Context()

	first, err := stream.Recv()
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "recv params: %v", err)
	}
	params := first.GetParams()
	if params == nil {
		return status.Error(codes.InvalidArgument, "first message must be params")
	}
	if params.Identity == "" || params.Subject == "" {
		return status.Error(codes.InvalidArgument, "identity and subject required")
	}

	id, err := s.registry.Lookup(params.Identity)
	if err != nil {
		return status.Errorf(codes.NotFound, "%v", err)
	}

	// Bind HMAC evidence to the requested identity. A token issued for
	// identity A must not be usable to register as identity B, even if B
	// also accepts the hmac attestor.
	if params.Hmac != nil && params.Hmac.Scope != params.Identity {
		return status.Error(codes.PermissionDenied, "hmac scope does not match identity")
	}

	ev := attestor.Evidence{
		TPM:           params.Tpm,
		HMAC:          params.Hmac,
		BootstrapCert: params.BootstrapCert,
		PeerCerts:     peerCerts(ctx),
	}
	ch := &streamChallenger{stream: stream}

	for _, a := range id.Attestors {
		if _, err := a.Verify(ctx, ev, params.Subject, ch); err != nil {
			s.log.Warn("register attestor failed",
				"identity", params.Identity,
				"attestor", a.Kind(),
				"error", err,
			)
			return status.Errorf(codes.PermissionDenied, "%s: %v", a.Kind(), err)
		}
	}

	certPEM, keyPEM, caCertPEM, err := s.issueIdentity(id, params.Subject, params.CsrDer)
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}

	s.log.Info("register ok",
		"identity", id.Name,
		"subject", params.Subject,
		"policy", id.Policy,
	)

	return stream.Send(&enrollv1.RegisterResponse{
		Step: &enrollv1.RegisterResponse_Result{
			Result: &enrollv1.RegisterResult{
				CertPem:           certPEM,
				KeyPem:            keyPEM,
				CaBundlePem:       caCertPEM,
				RenewAfterSeconds: uint32(id.PKI.TTL.Seconds()) / 2,
				ExpiresInSeconds:  uint32(id.PKI.TTL.Seconds()),
			},
		},
	})
}

// -----------------------------------------------------------------------------
// Renew

func (s *Server) Renew(ctx context.Context, req *enrollv1.RenewRequest) (*enrollv1.RenewResponse, error) {
	caller, err := s.callerFromPeer(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}
	id, err := s.registry.Lookup(caller.Identity)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	}

	certPEM, keyPEM, caCertPEM, err := s.issueIdentity(id, caller.Subject, req.CsrDer)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	s.log.Info("renew ok", "identity", id.Name, "subject", caller.Subject)
	return &enrollv1.RenewResponse{
		CertPem:           certPEM,
		KeyPem:            keyPEM,
		CaBundlePem:       caCertPEM,
		RenewAfterSeconds: uint32(id.PKI.TTL.Seconds()) / 2,
		ExpiresInSeconds:  uint32(id.PKI.TTL.Seconds()),
	}, nil
}

// issueIdentity is shared by Register and Renew. If csrDER is non-empty, the
// caller's public key is taken from the CSR; otherwise a fresh keypair is
// generated and returned alongside the cert. Subject (CN/O/OU), SANs, EKU
// and TTL are always server-controlled.
func (s *Server) issueIdentity(id *identity.Identity, subject string, csrDER []byte) (certPEM, keyPEM, caCertPEM []byte, err error) {
	ca, err := pki.DeriveCAByName(s.ikm, id.PKI.CARef)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("derive CA: %w", err)
	}
	cn, dnsSANs, ipSANsRaw, err := id.PKI.Resolve(subject)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve pki: %w", err)
	}
	ipSANs, err := parseIPs(ipSANsRaw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ip_sans: %w", err)
	}
	eku, err := pki.ParseExtKeyUsage(id.PKI.ExtKeyUsage)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("ext_key_usage: %w", err)
	}

	if len(csrDER) > 0 {
		csr, err := x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("parse csr: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, nil, nil, fmt.Errorf("csr signature: %w", err)
		}
		certPEM, err = pki.SignIdentityCSR(ca, csr.PublicKey, cn, id.Policy, id.Name, dnsSANs, ipSANs, id.PKI.TTL, eku)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("sign identity csr: %w", err)
		}
		return certPEM, nil, ca.CertPEM, nil
	}

	certPEM, keyPEM, err = pki.IssueIdentityCert(ca, cn, id.Policy, id.Name, dnsSANs, ipSANs, id.PKI.TTL, eku)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issue identity cert: %w", err)
	}
	return certPEM, keyPEM, ca.CertPEM, nil
}

// -----------------------------------------------------------------------------
// Read

func (s *Server) Read(ctx context.Context, req *enrollv1.Request) (*enrollv1.Response, error) {
	caller, err := s.callerFromPeer(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}
	if req.Path == "" {
		return nil, status.Error(codes.InvalidArgument, "path required")
	}
	resp, err := s.resolver.Read(&resource.Caller{
		Identity: caller.Identity,
		Policy:   caller.Policy,
		Subject:  caller.Subject,
	}, req.Path)
	if err != nil {
		return nil, mapResolveError(err)
	}
	return &enrollv1.Response{
		Content:     resp.Content,
		ContentType: resp.ContentType,
		TtlSeconds:  resp.TTLSeconds,
	}, nil
}

// -----------------------------------------------------------------------------
// Write

func (s *Server) Write(ctx context.Context, req *enrollv1.Request) (*enrollv1.Response, error) {
	caller, err := s.callerFromPeer(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "%v", err)
	}
	if req.Path == "" {
		return nil, status.Error(codes.InvalidArgument, "path required")
	}
	resp, err := s.resolver.Write(&resource.Caller{
		Identity: caller.Identity,
		Policy:   caller.Policy,
		Subject:  caller.Subject,
	}, req.Path, req.Data)
	if err != nil {
		return nil, mapResolveError(err)
	}
	return &enrollv1.Response{
		Content:     resp.Content,
		ContentType: resp.ContentType,
		TtlSeconds:  resp.TTLSeconds,
	}, nil
}

// -----------------------------------------------------------------------------
// helpers

type callerContext struct {
	Identity string
	Policy   string
	Subject  string
}

// callerFromPeer extracts identity/policy/subject from the peer TLS cert and
// verifies the cert was issued by the identity CA (rejecting bootstrap certs
// on Renew/Read/Write).
func (s *Server) callerFromPeer(ctx context.Context) (*callerContext, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, errors.New("no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, errors.New("peer is not TLS")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, errors.New("no client cert")
	}
	leaf := tlsInfo.State.PeerCertificates[0]

	pool := x509.NewCertPool()
	pool.AddCert(s.serverCA.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("client cert not signed by identity CA: %w", err)
	}

	if leaf.Subject.CommonName == "" || len(leaf.Subject.OrganizationalUnit) == 0 || len(leaf.Subject.Organization) == 0 {
		return nil, errors.New("client cert missing CN/OU/O")
	}
	return &callerContext{
		Identity: leaf.Subject.Organization[0],
		Policy:   leaf.Subject.OrganizationalUnit[0],
		Subject:  leaf.Subject.CommonName,
	}, nil
}

func peerCerts(ctx context.Context) []*x509.Certificate {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return tlsInfo.State.PeerCertificates
}

func parseIPs(raw []string) ([]net.IP, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]net.IP, 0, len(raw))
	for _, s := range raw {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP %q", s)
		}
		out = append(out, ip)
	}
	return out, nil
}

// mapResolveError turns a resource.Resolve error into a gRPC status.
func mapResolveError(err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "permission denied"):
		return status.Error(codes.PermissionDenied, msg)
	case strings.Contains(msg, "not found"):
		return status.Error(codes.NotFound, msg)
	default:
		return status.Error(codes.InvalidArgument, msg)
	}
}

// streamChallenger implements attestor.Challenger over the Register stream.
type streamChallenger struct {
	stream grpc.BidiStreamingServer[enrollv1.RegisterRequest, enrollv1.RegisterResponse]
}

func (c *streamChallenger) Challenge(_ context.Context, ch *enrollv1.TPMChallenge) ([]byte, error) {
	if err := c.stream.Send(&enrollv1.RegisterResponse{
		Step: &enrollv1.RegisterResponse_Challenge{Challenge: ch},
	}); err != nil {
		return nil, err
	}
	req, err := c.stream.Recv()
	if err != nil {
		return nil, err
	}
	resp, ok := req.Step.(*enrollv1.RegisterRequest_ChallengeResponse)
	if !ok {
		return nil, errors.New("expected challenge response")
	}
	return resp.ChallengeResponse, nil
}
