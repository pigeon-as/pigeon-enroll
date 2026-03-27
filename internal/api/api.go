// Package api provides HTTP handlers for the enrollment server.
package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/pigeon-as/pigeon-enroll/internal/audit"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/nonce"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	"github.com/pigeon-as/pigeon-enroll/internal/verify"
)

// Server is the enrollment HTTP server.
type Server struct {
	cfg         config.Config
	secrets     map[string]string
	ca          map[string]secrets.CAEntry
	hmacKey     []byte
	verifier    verify.Verifier
	audit       *audit.Log
	nonces      *nonce.Store
	limiter     *ipRateLimiter
	trustedNets []*net.IPNet
	scopes      map[string]string
	logger      *slog.Logger
	mux         *http.ServeMux
}

// New creates a new enrollment API server.
func New(logger *slog.Logger, cfg config.Config, hmacKey []byte, derivedSecrets map[string]string, cas map[string]secrets.CAEntry, v verify.Verifier, al *audit.Log) (*Server, error) {
	// Build scope map from secret specs.
	scopes := make(map[string]string, len(cfg.Secrets))
	for _, s := range cfg.Secrets {
		if s.Scope != "" {
			scopes[s.Name] = s.Scope
		}
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
	srv := &Server{
		cfg:         cfg,
		secrets:     derivedSecrets,
		ca:          cas,
		hmacKey:     hmacKey,
		verifier:    v,
		audit:       al,
		nonces:      nonces,
		limiter:     newIPRateLimiter(rate.Every(12*time.Second), 5),
		trustedNets: trustedNets,
		scopes:      scopes,
		logger:      logger,
		mux:         http.NewServeMux(),
	}
	srv.mux.HandleFunc("POST /claim", srv.handleClaim)
	srv.mux.HandleFunc("GET /health", srv.handleHealth)
	return srv, nil
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

type claimResponse struct {
	Secrets map[string]string          `json:"secrets"`
	Vars    map[string]string          `json:"vars"`
	CA      map[string]secrets.CAEntry `json:"ca,omitempty"`
}

func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	ip := verify.ClientIP(r)
	if !s.limiter.allow(ip) {
		s.logger.Warn("rate limited", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "rate limited"})
		s.jsonError(w, "too many requests", http.StatusTooManyRequests)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var req claimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if !token.Verify(s.hmacKey, req.Token, time.Now(), s.cfg.TokenWindow, req.Scope) {
		s.logger.Warn("invalid token", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "invalid token"})
		s.jsonError(w, "invalid or expired token", http.StatusForbidden)
		return
	}

	if err := s.verifier.Verify(r.Context(), r); err != nil {
		s.logger.Warn("verification failed", "ip", ip, "err", err)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "verification failed"})
		s.jsonError(w, "verification failed", http.StatusForbidden)
		return
	}

	if !s.nonces.Check(req.Token) {
		s.logger.Warn("replayed token", "ip", ip)
		s.audit.Record(audit.Entry{Operation: "claim", IP: ip, OK: false, Error: "token already used"})
		s.jsonError(w, "token already used", http.StatusForbidden)
		return
	}

	s.logger.Info("claimed", "ip", ip, "scope", req.Scope)
	s.audit.Record(audit.Entry{Operation: "claim", IP: ip, Scope: req.Scope, OK: true})

	filteredSecrets := make(map[string]string, len(s.secrets))
	for name, val := range s.secrets {
		sc := s.scopes[name]
		if sc == "" || sc == req.Scope {
			filteredSecrets[name] = val
		}
	}
	filteredVars := make(map[string]string, len(s.cfg.Vars))
	for name, val := range s.cfg.Vars {
		filteredVars[name] = val
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claimResponse{Secrets: filteredSecrets, Vars: filteredVars, CA: s.ca})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
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
