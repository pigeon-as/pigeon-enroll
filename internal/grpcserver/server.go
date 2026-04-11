// Package grpcserver implements the enrollment gRPC service.
// Follows the SPIRE AttestAgent bidirectional stream pattern:
// TPM attestation happens inline on the stream (no session store).
package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/go-attestation/attest"
	attestpkg "github.com/pigeon-as/pigeon-enroll/internal/attest"
	"github.com/pigeon-as/pigeon-enroll/internal/audit"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	jwtpkg "github.com/pigeon-as/pigeon-enroll/internal/jwt"
	"github.com/pigeon-as/pigeon-enroll/internal/nonce"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	pb "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// Server implements the EnrollmentService gRPC service.
type Server struct {
	pb.UnimplementedEnrollmentServiceServer

	cfg       config.Config
	secrets   map[string]string
	ca        map[string]secrets.CAEntry
	hmacKey   []byte
	audit     *audit.Log
	nonces    *nonce.Store
	limiter   *ipRateLimiter
	scopes    map[string]string
	caScopes  map[string][]string
	certCAs   map[string]*pki.CA
	certSpecs []config.CertSpec
	jwtKeys   map[string]secrets.JWTKeyEntry
	jwtSpecs  []config.JWTSpec
	logger    *slog.Logger
	ek        *attestpkg.EKValidator
}

// New creates a new enrollment gRPC server.
func New(logger *slog.Logger, cfg config.Config, hmacKey []byte, derivedSecrets map[string]string, cas map[string]secrets.CAEntry, jwtKeys map[string]secrets.JWTKeyEntry, al *audit.Log) (*Server, error) {
	scopes := make(map[string]string, len(cfg.Secrets))
	for _, s := range cfg.Secrets {
		if s.Scope != "" {
			scopes[s.Name] = s.Scope
		}
	}
	caScopes := make(map[string][]string, len(cfg.CAs))
	for _, ca := range cfg.CAs {
		if len(ca.Scope) > 0 {
			caScopes[ca.Name] = ca.Scope
		}
	}

	certCAs := make(map[string]*pki.CA, len(cfg.Certs))
	for _, c := range cfg.Certs {
		if _, ok := certCAs[c.CA]; ok {
			continue
		}
		caEntry, ok := cas[c.CA]
		if !ok {
			return nil, fmt.Errorf("cert %q references unknown CA %q", c.Name, c.CA)
		}
		pemData := append([]byte(caEntry.CertPEM), []byte(caEntry.PrivateKeyPEM)...)
		loadedCA, loadErr := pki.LoadCA(pemData)
		if loadErr != nil {
			return nil, fmt.Errorf("load CA %q for cert issuance: %w", c.CA, loadErr)
		}
		certCAs[c.CA] = loadedCA
	}

	ns, err := nonce.New(2*cfg.TokenWindow, cfg.NoncePath)
	if err != nil {
		return nil, fmt.Errorf("create nonce store: %w", err)
	}

	var ekValidator *attestpkg.EKValidator
	if cfg.EKCAPath != "" || cfg.EKHashPath != "" {
		ekValidator, err = attestpkg.NewEKValidator(cfg.EKCAPath, cfg.EKHashPath)
		if err != nil {
			return nil, fmt.Errorf("create EK validator: %w", err)
		}
	}

	return &Server{
		cfg:       cfg,
		secrets:   derivedSecrets,
		ca:        cas,
		hmacKey:   hmacKey,
		audit:     al,
		nonces:    ns,
		limiter:   newIPRateLimiter(rate.Every(12*time.Second), 5),
		scopes:    scopes,
		caScopes:  caScopes,
		certCAs:   certCAs,
		certSpecs: cfg.Certs,
		jwtKeys:   jwtKeys,
		jwtSpecs:  cfg.JWTs,
		logger:    logger,
		ek:        ekValidator,
	}, nil
}

// Claim implements the bidirectional streaming enrollment RPC.
// SPIRE AttestAgent pattern: stream IS the session.
func (s *Server) Claim(stream pb.EnrollmentService_ClaimServer) error {
	ip := peerIP(stream.Context())

	if !s.limiter.allow(ip) {
		s.logger.Warn("rate limited", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "rate limited"})
		return status.Error(codes.ResourceExhausted, "too many requests")
	}

	// Step 1: Receive initial params.
	msg, err := stream.Recv()
	if err != nil {
		return status.Error(codes.InvalidArgument, "expected initial params")
	}
	params := msg.GetParams()
	if params == nil {
		return status.Error(codes.InvalidArgument, "first message must be params")
	}

	// Step 2: Verify HMAC token.
	if !token.Verify(s.hmacKey, params.Token, time.Now(), s.cfg.TokenWindow, params.Scope) {
		s.logger.Warn("invalid token", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, Scope: params.Scope, OK: false, Error: "invalid token"})
		return status.Error(codes.PermissionDenied, "invalid or expired token")
	}

	var ekHash string

	// Step 3: TPM attestation or token-only.
	if params.Tpm != nil {
		var err error
		ekHash, err = s.attestTPM(stream, ip, params)
		if err != nil {
			return err // already a gRPC status error
		}
	} else if s.cfg.RequireTPM {
		s.logger.Warn("TPM required but token-only claim", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, Scope: params.Scope, OK: false, Error: "TPM attestation required"})
		return status.Error(codes.PermissionDenied, "TPM attestation required")
	}

	// Step 4: Consume one-time nonce.
	ok, err := s.nonces.Check(params.Token)
	if err != nil {
		s.logger.Error("nonce persistence failed", "ip", ip, "err", err)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "nonce storage error"})
		return status.Error(codes.Internal, "internal error")
	}
	if !ok {
		s.logger.Warn("replayed token", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "token already used"})
		return status.Error(codes.PermissionDenied, "token already used")
	}

	// Step 5: Build and send result.
	result, certNames, err := s.buildResult(params.Scope, params.Subject, params.CsrDer)
	if err != nil {
		s.logger.Error("build result failed", "ip", ip, "err", err)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, Scope: params.Scope, OK: false, Error: err.Error()})
		return status.Error(codes.Internal, "internal error")
	}

	s.logger.Info("claimed", "ip", ip, "scope", params.Scope, "subject", params.Subject, "ek", ekHash, "tpm", params.Tpm != nil)
	s.audit.Record(audit.Entry{
		Operation: "claim",
		IP:        ip,
		Scope:     params.Scope,
		Subject:   params.Subject,
		EKHash:    ekHash,
		Certs:     certNames,
		OK:        true,
	})

	return stream.Send(&pb.ClaimResponse{
		Step: &pb.ClaimResponse_Result{Result: result},
	})
}

// attestTPM performs inline TPM credential activation on the stream.
// Returns the EK hash (for audit) or a gRPC status error.
func (s *Server) attestTPM(stream pb.EnrollmentService_ClaimServer, ip string, params *pb.ClaimParams) (string, error) {
	tpm := params.Tpm

	// Parse EK public key.
	ekPub, err := x509.ParsePKIXPublicKey(tpm.EkPublic)
	if err != nil {
		return "", status.Error(codes.InvalidArgument, "invalid EK public key")
	}

	// Parse optional EK certificate.
	var ekCert *x509.Certificate
	if len(tpm.EkCert) > 0 {
		ekCert, err = x509.ParseCertificate(tpm.EkCert)
		if err != nil {
			return "", status.Error(codes.InvalidArgument, "invalid EK certificate")
		}
	}

	// Validate EK identity (SPIRE pattern).
	if s.ek != nil {
		if err := s.ek.Validate(ekPub, ekCert); err != nil {
			s.logger.Error("EK validation failed", "ip", ip, "err", err)
			s.audit.Record(audit.Entry{Operation: "claim", IP: ip, Scope: params.Scope, OK: false, Error: "EK: " + err.Error()})
			return "", status.Error(codes.PermissionDenied, "EK validation failed")
		}
	}

	// Build attestation parameters from proto.
	akParams := attest.AttestationParameters{
		Public:            tpm.AkPublic,
		CreateData:        tpm.AkCreateData,
		CreateAttestation: tpm.AkCreateAttestation,
		CreateSignature:   tpm.AkCreateSignature,
	}

	// Generate credential activation challenge.
	ap := attest.ActivationParameters{
		EK:   ekPub,
		AK:   akParams,
		Rand: rand.Reader,
	}
	if err := ap.CheckAKParameters(); err != nil {
		return "", status.Errorf(codes.InvalidArgument, "invalid AK parameters: %v", err)
	}
	secret, ec, err := ap.Generate()
	if err != nil {
		s.logger.Error("generate challenge failed", "ip", ip, "err", err)
		return "", status.Error(codes.Internal, "attestation challenge failed")
	}

	// Compute EK hash for audit.
	ekHash := attestpkg.EKHashFromKey(ekPub)

	// Send challenge to client.
	if err := stream.Send(&pb.ClaimResponse{
		Step: &pb.ClaimResponse_Challenge{
			Challenge: &pb.TPMChallenge{
				Credential: ec.Credential,
				Secret:     ec.Secret,
			},
		},
	}); err != nil {
		return "", err
	}

	// Receive challenge response.
	msg, err := stream.Recv()
	if err != nil {
		return "", status.Error(codes.InvalidArgument, "expected challenge response")
	}
	activated := msg.GetChallengeResponse()
	if activated == nil {
		return "", status.Error(codes.InvalidArgument, "expected challenge_response")
	}

	// Verify credential activation (constant-time).
	if subtle.ConstantTimeCompare(secret, activated) != 1 {
		s.logger.Warn("TPM attestation failed", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, Scope: params.Scope, EKHash: ekHash, OK: false, Error: "credential activation failed"})
		return "", status.Error(codes.PermissionDenied, "TPM attestation failed")
	}

	return ekHash, nil
}

// buildResult constructs the filtered claim result.
func (s *Server) buildResult(scope, subject string, csrDER []byte) (*pb.ClaimResult, string, error) {
	// Filter secrets by scope.
	filteredSecrets := make(map[string]string, len(s.secrets))
	for name, val := range s.secrets {
		sc := s.scopes[name]
		if sc == "" || sc == scope {
			filteredSecrets[name] = val
		}
	}

	// Vars are deployment-wide metadata (intentionally unscoped).
	filteredVars := make(map[string]string, len(s.cfg.Vars))
	for name, val := range s.cfg.Vars {
		filteredVars[name] = val
	}

	// Filter CAs by scope.
	filteredCAs := make(map[string]*pb.CACert, len(s.ca))
	for name, val := range s.ca {
		entry := &pb.CACert{CertPem: val.CertPEM}
		if sc := s.caScopes[name]; len(sc) > 0 && scopeMatch(sc, scope) {
			entry.PrivateKeyPem = val.PrivateKeyPEM
		}
		filteredCAs[name] = entry
	}

	// Parse optional CSR (for CSR-mode certs).
	var csr *x509.CertificateRequest
	if len(csrDER) > 0 {
		var err error
		csr, err = x509.ParseCertificateRequest(csrDER)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CSR: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, "", fmt.Errorf("CSR signature verification failed: %w", err)
		}
	}

	// Issue leaf certs for matching cert blocks.
	certs := make(map[string]*pb.CertBundle)
	var certNames []string
	for _, cs := range s.certSpecs {
		if !scopeMatch(cs.Scope, scope) {
			continue
		}

		cn := cs.CN
		if cn == "" {
			cn = subject
		}
		if cn == "" {
			return nil, "", fmt.Errorf("cert %q requires subject (no static cn)", cs.Name)
		}

		var ipSANs []net.IP
		for _, raw := range cs.IPSANs {
			ipSANs = append(ipSANs, net.ParseIP(raw))
		}

		serverAuth := cs.ServerAuth != nil && *cs.ServerAuth
		clientAuth := cs.ClientAuth == nil || *cs.ClientAuth

		if cs.Mode == "csr" {
			// CSR-mode: sign the worker's public key.
			if csr == nil {
				// No CSR provided — skip. Worker must include csr_der for CSR-mode certs.
				continue
			}
			ca := s.certCAs[cs.CA]
			certPEM, err := pki.SignCSR(ca, csr.PublicKey, cn, cs.DNSSANs, ipSANs, cs.TTL, serverAuth, clientAuth)
			if err != nil {
				return nil, "", fmt.Errorf("sign CSR for %q: %w", cs.Name, err)
			}
			certs[cs.Name] = &pb.CertBundle{CertPem: string(certPEM)}
		} else {
			// Push-mode: server generates keypair.
			ca := s.certCAs[cs.CA]
			certPEM, keyPEM, err := pki.IssueCert(ca, cn, cs.DNSSANs, ipSANs, cs.TTL, serverAuth, clientAuth)
			if err != nil {
				return nil, "", fmt.Errorf("issue cert %q: %w", cs.Name, err)
			}
			certs[cs.Name] = &pb.CertBundle{CertPem: string(certPEM), KeyPem: string(keyPEM)}
		}
		certNames = append(certNames, cs.Name)
	}

	// Sign JWTs for scope-matched specs; collect all public keys.
	var jwts map[string]string
	jwtKeys := make(map[string]string, len(s.jwtSpecs))
	for _, spec := range s.jwtSpecs {
		key, ok := s.jwtKeys[spec.Name]
		if !ok {
			continue
		}
		jwtKeys[spec.Name] = key.PublicKeyPEM
		if spec.Scope == scope {
			if subject == "" {
				return nil, "", fmt.Errorf("JWT %q requires subject", spec.Name)
			}
			signed, err := jwtpkg.Sign(key.PrivateKey, spec.Issuer, spec.Audience, subject, spec.TTL)
			if err != nil {
				return nil, "", fmt.Errorf("sign JWT %q: %w", spec.Name, err)
			}
			if jwts == nil {
				jwts = make(map[string]string)
			}
			jwts[spec.Name] = signed
		}
	}

	certNamesStr := ""
	if len(certNames) > 0 {
		certNamesStr = fmt.Sprintf("%v", certNames)
	}

	return &pb.ClaimResult{
		Secrets: filteredSecrets,
		Vars:    filteredVars,
		Ca:      filteredCAs,
		Certs:   certs,
		Jwts:    jwts,
		JwtKeys: jwtKeys,
	}, certNamesStr, nil
}

// peerIP extracts the client IP from gRPC peer info.
func peerIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return p.Addr.String()
	}
	return host
}

func scopeMatch(allowed []string, scope string) bool {
	for _, a := range allowed {
		if a == scope {
			return true
		}
	}
	return false
}

// ipRateLimiter tracks per-IP request rates.
type ipRateLimiter struct {
	mu        sync.Mutex
	limiters  map[string]*limiterEntry
	limit     rate.Limit
	burst     int
	lastPurge time.Time
}

type limiterEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(r rate.Limit, burst int) *ipRateLimiter {
	return &ipRateLimiter{
		limiters: make(map[string]*limiterEntry),
		limit:    r,
		burst:    burst,
	}
}

func (l *ipRateLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if time.Since(l.lastPurge) > 5*time.Minute {
		cutoff := time.Now().Add(-10 * time.Minute)
		for k, e := range l.limiters {
			if e.lastSeen.Before(cutoff) {
				delete(l.limiters, k)
			}
		}
		l.lastPurge = time.Now()
	}

	e, exists := l.limiters[ip]
	if !exists {
		e = &limiterEntry{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.limiters[ip] = e
	}
	e.lastSeen = time.Now()
	return e.limiter.Allow()
}
