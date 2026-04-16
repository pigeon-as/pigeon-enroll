// Package grpcserver implements the enrollment gRPC service.
// Follows the SPIRE AttestAgent bidirectional stream pattern:
// TPM attestation happens inline on the stream (no session store).
package grpcserver

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/google/go-attestation/attest"
	attestpkg "github.com/pigeon-as/pigeon-enroll/internal/attest"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	jwtpkg "github.com/pigeon-as/pigeon-enroll/internal/jwt"
	"github.com/pigeon-as/pigeon-enroll/internal/nonce"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/render"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	pb "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
	"github.com/zclconf/go-cty/cty"
	"golang.org/x/time/rate"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
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
	nonces    *nonce.Store
	limiter   *ipRateLimiter
	scopes    map[string]string
	caScopes  map[string][]string
	certCAs   map[string]*pki.CA
	certSpecs []config.CertSpec
	jwtKeys   map[string]secrets.JWTKeyEntry
	jwtSpecs  []config.JWTSpec
	templates map[string]config.TemplateSpec // keyed by name
	mtlsCA    *pki.CA                        // mTLS CA for generating ephemeral client certs
	clientTTL time.Duration                  // TTL for generated client certs
	vars      map[string]string              // config vars passed to template rendering
	logger    *slog.Logger
	ek        *attestpkg.EKValidator
}

// New creates a new enrollment gRPC server.
func New(logger *slog.Logger, cfg config.Config, hmacKey []byte, derivedSecrets map[string]string, cas map[string]secrets.CAEntry, jwtKeys map[string]secrets.JWTKeyEntry, mtlsCA *pki.CA) (*Server, error) {
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

	tplMap := make(map[string]config.TemplateSpec, len(cfg.Templates))
	for _, t := range cfg.Templates {
		tplMap[t.Name] = t
	}

	return &Server{
		cfg:       cfg,
		secrets:   derivedSecrets,
		ca:        cas,
		hmacKey:   hmacKey,
		nonces:    ns,
		limiter:   newIPRateLimiter(rate.Every(12*time.Second), 5),
		scopes:    scopes,
		caScopes:  caScopes,
		certCAs:   certCAs,
		certSpecs: cfg.Certs,
		jwtKeys:   jwtKeys,
		jwtSpecs:  cfg.JWTs,
		templates: tplMap,
		mtlsCA:    mtlsCA,
		clientTTL: cfg.ClientCertTTL,
		vars:      cfg.Vars,
		logger:    logger,
		ek:        ekValidator,
	}, nil
}

// Claim implements the bidirectional streaming enrollment RPC.
// SPIRE AttestAgent pattern: stream IS the session.
func (s *Server) Claim(stream pb.EnrollmentService_ClaimServer) error {
	ip := peerIP(stream.Context())

	if !s.limiter.allow(ip) {
		s.logger.Warn("claim denied", "ip", ip, "reason", "rate limited")
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
		s.logger.Warn("claim denied", "ip", ip, "scope", params.Scope, "reason", "invalid token")
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
		s.logger.Warn("claim denied", "ip", ip, "scope", params.Scope, "reason", "TPM attestation required")
		return status.Error(codes.PermissionDenied, "TPM attestation required")
	}

	// Step 4: Consume one-time nonce.
	ok, err := s.nonces.Check(params.Token)
	if err != nil {
		s.logger.Error("claim denied", "ip", ip, "reason", "nonce storage error", "err", err)
		return status.Error(codes.Internal, "internal error")
	}
	if !ok {
		s.logger.Warn("claim denied", "ip", ip, "reason", "token already used")
		return status.Error(codes.PermissionDenied, "token already used")
	}

	// Step 5: Build and send result.
	result, certNames, err := s.buildResult(params.Scope, params.Subject, params.CsrDer)
	if err != nil {
		s.logger.Error("claim denied", "ip", ip, "scope", params.Scope, "reason", err.Error())
		return status.Error(codes.InvalidArgument, "invalid claim request")
	}

	s.logger.Info("claim ok", "ip", ip, "scope", params.Scope, "subject", params.Subject, "ek", ekHash, "tpm", params.Tpm != nil, "certs", certNames)

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
			s.logger.Error("claim denied", "ip", ip, "scope", params.Scope, "reason", "EK validation failed", "err", err)
			code := codes.Internal
			if errors.Is(err, attestpkg.ErrEKNotTrusted) {
				code = codes.PermissionDenied
			}
			return "", status.Error(code, "EK validation failed")
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
		s.logger.Warn("claim denied", "ip", ip, "scope", params.Scope, "ek", ekHash, "reason", "credential activation failed")
		return "", status.Error(codes.PermissionDenied, "TPM attestation failed")
	}

	return ekHash, nil
}

// buildResult constructs the filtered claim result.
func (s *Server) buildResult(scope, subject string, csrDER []byte) (*pb.ClaimResult, []string, error) {
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
			return nil, nil, fmt.Errorf("invalid CSR: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, nil, fmt.Errorf("CSR signature verification failed: %w", err)
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
			return nil, nil, fmt.Errorf("cert %q requires subject (no static cn)", cs.Name)
		}

		dnsSANs, ipSANs, err := cs.ResolveSANs(subject)
		if err != nil {
			return nil, nil, fmt.Errorf("cert %q: %w", cs.Name, err)
		}

		serverAuth := cs.ServerAuth != nil && *cs.ServerAuth
		clientAuth := cs.ClientAuth == nil || *cs.ClientAuth

		if cs.Mode == "csr" {
			// CSR-mode: sign the worker's public key.
			if csr == nil {
				return nil, nil, fmt.Errorf("csr_der is required for CSR-mode cert %q", cs.Name)
			}
			ca := s.certCAs[cs.CA]
			certPEM, err := pki.SignCSR(ca, csr.PublicKey, cn, dnsSANs, ipSANs, cs.TTL, serverAuth, clientAuth)
			if err != nil {
				return nil, nil, fmt.Errorf("sign CSR for %q: %w", cs.Name, err)
			}
			certs[cs.Name] = &pb.CertBundle{CertPem: string(certPEM)}
		} else {
			// Push-mode: server generates keypair.
			ca := s.certCAs[cs.CA]
			certPEM, keyPEM, err := pki.IssueCert(ca, cn, dnsSANs, ipSANs, cs.TTL, serverAuth, clientAuth)
			if err != nil {
				return nil, nil, fmt.Errorf("issue cert %q: %w", cs.Name, err)
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
				return nil, nil, fmt.Errorf("JWT %q requires subject", spec.Name)
			}
			signed, err := jwtpkg.Sign(key.PrivateKey, spec.Issuer, spec.Audience, subject, spec.TTL)
			if err != nil {
				return nil, nil, fmt.Errorf("sign JWT %q: %w", spec.Name, err)
			}
			if jwts == nil {
				jwts = make(map[string]string)
			}
			jwts[spec.Name] = signed
		}
	}

	return &pb.ClaimResult{
		Secrets: filteredSecrets,
		Vars:    filteredVars,
		Ca:      filteredCAs,
		Certs:   certs,
		Jwts:    jwts,
		JwtKeys: jwtKeys,
	}, certNames, nil
}

// Render renders a server-side template with fresh credentials.
// The caller authenticates via mTLS (same CA as Claim). Authorization is
// enforced by checking the caller's cert OU against the template's scope
// (Vault cert auth pattern: allowed_organizational_units).
func (s *Server) Render(ctx context.Context, req *pb.RenderRequest) (*pb.RenderResponse, error) {
	ip := peerIP(ctx)

	if !s.limiter.allow(ip) {
		s.logger.Warn("render denied", "ip", ip, "reason", "rate limited")
		return nil, status.Error(codes.ResourceExhausted, "too many requests")
	}

	tpl, ok := s.templates[req.GetName()]
	if !ok {
		s.logger.Warn("render denied", "ip", ip, "name", req.GetName(), "reason", "unknown template")
		return nil, status.Error(codes.NotFound, "unknown template")
	}

	// Authorize: caller's cert OU must match template scope.
	peerScope, err := peerCertScope(ctx)
	if err != nil {
		s.logger.Warn("render denied", "ip", ip, "name", req.GetName(), "reason", "no peer cert")
		return nil, status.Error(codes.Unauthenticated, "client certificate required")
	}
	if peerScope != tpl.Scope {
		s.logger.Warn("render denied", "ip", ip, "name", req.GetName(),
			"reason", "scope mismatch", "peer_scope", peerScope, "template_scope", tpl.Scope)
		return nil, status.Error(codes.PermissionDenied, "scope mismatch")
	}

	// Generate fresh HMAC token scoped to the template's scope.
	tok := token.Generate(s.hmacKey, time.Now(), s.cfg.TokenWindow, tpl.Scope)

	// Generate ephemeral client cert bundle with template scope embedded as OU.
	certBundle, err := pki.GenerateClientCert(s.mtlsCA, tpl.Scope, s.clientTTL)
	if err != nil {
		s.logger.Error("render failed", "ip", ip, "name", tpl.Name, "reason", "generate cert", "err", err)
		return nil, status.Error(codes.Internal, "internal error")
	}

	// Build template variables: ${token}, ${cert}, ${vars.*}
	tplVars := map[string]cty.Value{
		"token": cty.StringVal(tok),
		"cert":  cty.StringVal(string(certBundle)),
	}
	if len(s.vars) > 0 {
		varMap := make(map[string]cty.Value, len(s.vars))
		for k, v := range s.vars {
			varMap[k] = cty.StringVal(v)
		}
		tplVars["vars"] = cty.ObjectVal(varMap)
	}

	rendered, err := render.File(tpl.Source, tplVars)
	if err != nil {
		s.logger.Error("render failed", "ip", ip, "name", tpl.Name, "reason", "render", "err", err)
		return nil, status.Error(codes.Internal, "template render failed")
	}

	s.logger.Info("render", "ip", ip, "name", tpl.Name, "scope", tpl.Scope)
	return &pb.RenderResponse{Content: string(rendered)}, nil
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

// peerCertScope extracts the scope (first OU) from the peer's TLS client
// certificate. Returns an error if no verified peer certificate is available.
// Follows the Vault cert auth pattern: allowed_organizational_units.
func peerCertScope(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no peer info")
	}
	ti, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(ti.State.VerifiedChains) == 0 || len(ti.State.VerifiedChains[0]) == 0 {
		return "", fmt.Errorf("no verified peer certificate")
	}
	leaf := ti.State.VerifiedChains[0][0]
	if len(leaf.Subject.OrganizationalUnit) == 0 {
		return "", fmt.Errorf("peer certificate has no OU")
	}
	return leaf.Subject.OrganizationalUnit[0], nil
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
