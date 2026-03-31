// Package api provides HTTP handlers for the enrollment server.
package api

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/google/go-attestation/attest"
	attestpkg "github.com/pigeon-as/pigeon-enroll/internal/attest"
	"github.com/pigeon-as/pigeon-enroll/internal/audit"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/nonce"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
)

// Server is the enrollment HTTP server.
type Server struct {
	cfg         config.Config
	secrets     map[string]string
	ca          map[string]secrets.CAEntry
	hmacKey     []byte
	audit       *audit.Log
	nonces      *nonce.Store
	limiter     *ipRateLimiter
	trustedNets []*net.IPNet
	scopes      map[string]string
	caScopes    map[string][]string
	certCAs     map[string]*pki.CA
	certSpecs   []config.CertSpec
	logger      *slog.Logger
	mux         *http.ServeMux
	verifier    *attestpkg.Verifier
}

// New creates a new enrollment API server.
func New(logger *slog.Logger, cfg config.Config, hmacKey []byte, derivedSecrets map[string]string, cas map[string]secrets.CAEntry, al *audit.Log) (*Server, error) {
	// Build scope map from secret specs.
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

	// Load CAs referenced by cert blocks for leaf issuance.
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
	var trustedNets []*net.IPNet
	for _, cidr := range cfg.TrustedProxies {
		_, n, _ := net.ParseCIDR(cidr)
		trustedNets = append(trustedNets, n)
	}
	nonces, err := nonce.New(2*cfg.TokenWindow, cfg.NoncePath)
	if err != nil {
		return nil, fmt.Errorf("create nonce store: %w", err)
	}

	// Create EK validator if configured (SPIRE pattern).
	var ekValidator *attestpkg.EKValidator
	if cfg.EKCAPath != "" || cfg.EKHashPath != "" {
		ekValidator, err = attestpkg.NewEKValidator(cfg.EKCAPath, cfg.EKHashPath)
		if err != nil {
			return nil, fmt.Errorf("create EK validator: %w", err)
		}
	}

	srv := &Server{
		cfg:         cfg,
		secrets:     derivedSecrets,
		ca:          cas,
		hmacKey:     hmacKey,
		audit:       al,
		nonces:      nonces,
		limiter:     newIPRateLimiter(rate.Every(12*time.Second), 5),
		trustedNets: trustedNets,
		scopes:      scopes,
		caScopes:    caScopes,
		certCAs:     certCAs,
		certSpecs:   cfg.Certs,
		logger:      logger,
		mux:         http.NewServeMux(),
		verifier:    attestpkg.NewVerifier(ekValidator),
	}
	srv.mux.HandleFunc("POST /attest", srv.handleAttest)
	srv.mux.HandleFunc("POST /claim", srv.handleClaim)
	srv.mux.HandleFunc("GET /health", srv.handleHealth)
	return srv, nil
}

// Close releases resources held by the server.
func (s *Server) Close() {
	if s.verifier != nil {
		s.verifier.Close()
	}
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	if len(s.trustedNets) == 0 {
		return s.mux
	}
	return s.withTrustedProxies(s.mux)
}

// withTrustedProxies rewrites RemoteAddr from X-Forwarded-For when the
// request originates from a trusted proxy. Follows the Vault pattern:
// flat structure, rightmost XFF entry (unspoofable), original port preserved.
func (s *Server) withTrustedProxies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		ip := net.ParseIP(host)
		if ip == nil {
			next.ServeHTTP(w, r)
			return
		}

		var trusted bool
		for _, n := range s.trustedNets {
			if n.Contains(ip) {
				trusted = true
				break
			}
		}
		if !trusted {
			next.ServeHTTP(w, r)
			return
		}

		// Collect all X-Forwarded-For values into a flat list.
		var addrs []string
		for _, header := range r.Header.Values("X-Forwarded-For") {
			for _, v := range strings.Split(header, ",") {
				if trimmed := strings.TrimSpace(v); trimmed != "" {
					addrs = append(addrs, trimmed)
				}
			}
		}

		if len(addrs) > 0 {
			// Take the rightmost entry: the one appended by the trusted proxy,
			// which cannot be spoofed by the client (Vault convention).
			clientAddr := addrs[len(addrs)-1]
			if net.ParseIP(clientAddr) != nil {
				r.RemoteAddr = net.JoinHostPort(clientAddr, port)
			}
		}

		next.ServeHTTP(w, r)
	})
}

type claimRequest struct {
	Token string `json:"token"`
	Scope string `json:"scope"`
}

// attestRequest is the input for POST /attest (TPM attestation round 1).
type attestRequest struct {
	Token    string                       `json:"token"`
	Scope    string                       `json:"scope"`
	EKPub    []byte                       `json:"ek_pub"`     // PKIX DER of EK public key
	EKCert   []byte                       `json:"ek_cert"`    // DER X.509 EK certificate (optional)
	AKParams attest.AttestationParameters `json:"ak_params"`
}

// attestResponse is returned by POST /attest.
type attestResponse struct {
	SessionID  string                    `json:"session_id"`
	Credential attest.EncryptedCredential `json:"credential"`
}

// claimRequestTPM is the TPM-attested claim (round 2).
type claimRequestTPM struct {
	SessionID       string `json:"session_id"`
	ActivatedSecret []byte `json:"activated_secret"`
}

type claimResponse struct {
	Secrets map[string]string            `json:"secrets"`
	Vars    map[string]string            `json:"vars"`
	CA      map[string]secrets.CAEntry   `json:"ca,omitempty"`
	Certs   map[string]secrets.CertEntry `json:"certs,omitempty"`
}

// handleAttest handles POST /attest — TPM attestation round 1.
// Validates the HMAC token (signature only, nonce not consumed yet),
// generates a credential activation challenge.
func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.allow(ip) {
		s.logger.Warn("rate limited", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "attest", IP: ip, OK: false, Error: "rate limited"})
		s.jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	var req attestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Validate HMAC token signature (nonce consumed in /claim on success).
	if !token.Verify(s.hmacKey, req.Token, time.Now(), s.cfg.TokenWindow, req.Scope) {
		s.logger.Warn("invalid token", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "attest", IP: ip, OK: false, Error: "invalid token"})
		s.jsonError(w, "invalid or expired token", http.StatusForbidden)
		return
	}

	// Parse EK public key.
	ekPub, err := x509.ParsePKIXPublicKey(req.EKPub)
	if err != nil {
		s.jsonError(w, "invalid EK public key", http.StatusBadRequest)
		return
	}

	// Parse optional EK certificate.
	var ekCert *x509.Certificate
	if len(req.EKCert) > 0 {
		ekCert, err = x509.ParseCertificate(req.EKCert)
		if err != nil {
			s.jsonError(w, "invalid EK certificate", http.StatusBadRequest)
			return
		}
	}

	// Start attestation session.
	resp, err := s.verifier.StartAttestation(attestpkg.StartRequest{
		Token:    req.Token,
		Scope:    req.Scope,
		EKPub:    ekPub,
		EKCert:   ekCert,
		AKParams: req.AKParams,
	})
	if err != nil {
		s.logger.Error("start attestation failed", "ip", ip, "err", err)
		s.audit.Record(audit.Entry{Operation: "attest", IP: ip, OK: false, Error: err.Error()})
		s.jsonError(w, "attestation challenge failed", http.StatusBadRequest)
		return
	}

	s.logger.Info("attestation started", "ip", ip, "session", resp.SessionID)
	s.audit.Record(audit.Entry{Operation: "attest", IP: ip, OK: true})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(attestResponse{
		SessionID:  resp.SessionID,
		Credential: *resp.EncryptedCredential,
	})
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.limiter.allow(ip) {
		s.logger.Warn("rate limited", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "rate limited"})
		s.jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 8192)

	// Peek at the body to determine claim mode (legacy vs TPM).
	var raw json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Try TPM claim first (has session_id field).
	var tpmReq claimRequestTPM
	if err := json.Unmarshal(raw, &tpmReq); err == nil && tpmReq.SessionID != "" {
		s.handleClaimTPM(w, r, ip, tpmReq)
		return
	}

	// Fall back to token-only claim (has token field).
	var tokenReq claimRequest
	if err := json.Unmarshal(raw, &tokenReq); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// When require_tpm is set, reject token-only claims.
	if s.cfg.RequireTPM {
		s.logger.Warn("TPM required but token-only claim received", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "TPM attestation required"})
		s.jsonError(w, "TPM attestation required", http.StatusForbidden)
		return
	}

	s.handleClaimTokenOnly(w, r, ip, tokenReq)
}

// handleClaimTokenOnly processes token-only claims (no TPM attestation).
// Used when require_tpm is false (dev/testing or migration).
func (s *Server) handleClaimTokenOnly(w http.ResponseWriter, r *http.Request, ip string, req claimRequest) {
	if !token.Verify(s.hmacKey, req.Token, time.Now(), s.cfg.TokenWindow, req.Scope) {
		s.logger.Warn("invalid token", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "invalid token"})
		s.jsonError(w, "invalid or expired token", http.StatusForbidden)
		return
	}

	ok, err := s.nonces.Check(req.Token)
	if err != nil {
		s.logger.Error("nonce persistence failed", "ip", ip, "err", err)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "nonce storage error"})
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.logger.Warn("replayed token", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "token already used"})
		s.jsonError(w, "token already used", http.StatusForbidden)
		return
	}

	s.logger.Info("claimed", "ip", ip, "scope", req.Scope)
	s.audit.Record(audit.Entry{Operation: "claim", IP: ip, Scope: req.Scope, OK: true})

	s.writeClaimResponse(w, req.Scope)
}

// handleClaimTPM processes TPM-attested claims (round 2 of attestation flow).
func (s *Server) handleClaimTPM(w http.ResponseWriter, r *http.Request, ip string, req claimRequestTPM) {
	result, err := s.verifier.CompleteAttestation(attestpkg.CompleteRequest{
		SessionID:       req.SessionID,
		ActivatedSecret: req.ActivatedSecret,
	})
	if err != nil {
		s.logger.Warn("TPM attestation failed", "ip", ip, "err", err)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "TPM: " + err.Error()})
		s.jsonError(w, "TPM attestation failed: "+err.Error(), http.StatusForbidden)
		return
	}

	// Consume the HMAC token nonce (crash-safe: only consumed on success).
	ok, err := s.nonces.Check(result.Token)
	if err != nil {
		s.logger.Error("nonce persistence failed", "ip", ip, "err", err)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "nonce storage error"})
		s.jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok {
		s.logger.Warn("replayed token", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "token already used"})
		s.jsonError(w, "token already used", http.StatusForbidden)
		return
	}

	s.logger.Info("claimed (TPM attested)", "ip", ip, "scope", result.Scope, "ek", result.EKHash)
	s.audit.Record(audit.Entry{Operation: "claim", IP: ip, Scope: result.Scope, OK: true})

	s.writeClaimResponse(w, result.Scope)
}

// writeClaimResponse builds and writes the filtered secrets response.
func (s *Server) writeClaimResponse(w http.ResponseWriter, scope string) {
	filteredSecrets := make(map[string]string, len(s.secrets))
	for name, val := range s.secrets {
		sc := s.scopes[name]
		if sc == "" || sc == scope {
			filteredSecrets[name] = val
		}
	}
	filteredVars := make(map[string]string, len(s.cfg.Vars))
	for name, val := range s.cfg.Vars {
		filteredVars[name] = val
	}

	filteredCAs := make(map[string]secrets.CAEntry, len(s.ca))
	for name, val := range s.ca {
		entry := secrets.CAEntry{CertPEM: val.CertPEM}
		if sc := s.caScopes[name]; len(sc) > 0 && scopeMatch(sc, scope) {
			entry.PrivateKeyPEM = val.PrivateKeyPEM
		}
		filteredCAs[name] = entry
	}

	// Issue leaf certs for matching cert blocks.
	var certs map[string]secrets.CertEntry
	for _, cs := range s.certSpecs {
		if !scopeMatch(cs.Scope, scope) {
			continue
		}
		ca := s.certCAs[cs.CA]
		serverAuth := cs.ServerAuth != nil && *cs.ServerAuth
		clientAuth := cs.ClientAuth == nil || *cs.ClientAuth // default true
		certPEM, keyPEM, err := pki.IssueCert(ca, cs.CN, cs.TTL, serverAuth, clientAuth)
		if err != nil {
			s.logger.Error("issue cert failed", "cert", cs.Name, "err", err)
			continue
		}
		if certs == nil {
			certs = make(map[string]secrets.CertEntry)
		}
		certs[cs.Name] = secrets.CertEntry{CertPEM: string(certPEM), KeyPEM: string(keyPEM)}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claimResponse{Secrets: filteredSecrets, Vars: filteredVars, CA: filteredCAs, Certs: certs})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

// scopeMatch reports whether scope is in the allowed list.
func scopeMatch(allowed []string, scope string) bool {
	for _, a := range allowed {
		if a == scope {
			return true
		}
	}
	return false
}

func (s *Server) jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// clientIP extracts the client IP from a request, stripping the port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
