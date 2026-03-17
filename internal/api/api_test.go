package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	"github.com/pigeon-as/pigeon-enroll/internal/verify"
)

func boolPtr(b bool) *bool { return &b }

var (
	testKey     = []byte("0123456789abcdef0123456789abcdef") // 32 bytes
	testHMACKey = mustDeriveHMACKey(testKey)
	testWindow  = 30 * time.Minute
)

func mustDeriveHMACKey(key []byte) []byte {
	k, err := secrets.DeriveHMACKey(key)
	if err != nil {
		panic(err)
	}
	return k
}

func testServer(t *testing.T) *Server {
	t.Helper()
	cfg := config.Config{
		TokenWindow: testWindow,
		Vars: map[string]string{
			"datacenter": "dc1",
		},
	}
	secrets := map[string]string{
		"secret_a": "dGVzdA==",
		"secret_b": "dGVzdA==",
		"secret_c": "dGVzdA==",
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	return New(logger, cfg, testHMACKey, secrets, verify.Noop{}, nil)
}

func validToken() string {
	return token.Generate(testHMACKey, time.Now(), testWindow, "")
}

func TestClaimSuccess(t *testing.T) {
	srv := testServer(t)

	body, _ := json.Marshal(claimRequest{
		Token: validToken(),
	})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp claimResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(resp.Secrets) != 3 {
		t.Errorf("expected 3 secrets, got %d", len(resp.Secrets))
	}
	if resp.Secrets["secret_a"] != "dGVzdA==" {
		t.Errorf("secret_a = %q", resp.Secrets["secret_a"])
	}
	if len(resp.Vars) != 1 {
		t.Errorf("expected 1 var, got %d", len(resp.Vars))
	}
	if resp.Vars["datacenter"] != "dc1" {
		t.Errorf("datacenter = %q", resp.Vars["datacenter"])
	}
}

func TestClaimInvalidToken(t *testing.T) {
	srv := testServer(t)

	body, _ := json.Marshal(claimRequest{
		Token: "deadbeef",
	})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestClaimExpiredToken(t *testing.T) {
	srv := testServer(t)

	// Token from 2 windows ago — outside current + previous check.
	expired := token.Generate(testHMACKey, time.Now().Add(-2*testWindow-time.Second), testWindow, "")
	body, _ := json.Marshal(claimRequest{
		Token: expired,
	})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestClaimOneTimeToken(t *testing.T) {
	srv := testServer(t)
	tok := validToken()

	// First use should succeed.
	body, _ := json.Marshal(claimRequest{Token: tok})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("first claim: status = %d, want 200", w.Code)
	}

	// Second use of same token should be rejected (nonce replay).
	body2, _ := json.Marshal(claimRequest{Token: tok})
	req2 := httptest.NewRequest("POST", "/claim", bytes.NewReader(body2))
	req2.RemoteAddr = "192.168.1.100:12345"
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Fatalf("replay claim: status = %d, want 403", w2.Code)
	}
}

func TestHealth(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestVerifierNonFatal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	v, err := verify.New(logger, []verify.Config{
		{Type: "cidr", Fatal: boolPtr(false), Config: json.RawMessage(`{"allow": ["10.0.0.0/8"]}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		TokenWindow: testWindow,
		Vars:        map[string]string{"k": "v"},
	}
	srv := New(logger, cfg, testHMACKey, nil, v, nil)

	body, _ := json.Marshal(claimRequest{
		Token: validToken(),
	})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345" // not in 10.0.0.0/8
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Non-fatal: claim should succeed despite verification failure.
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (non-fatal verifier)", w.Code)
	}
}

func TestVerifierFatal(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	v, err := verify.New(logger, []verify.Config{
		{Type: "cidr", Fatal: boolPtr(true), Config: json.RawMessage(`{"allow": ["10.0.0.0/8"]}`)},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		TokenWindow: testWindow,
		Vars:        map[string]string{"k": "v"},
	}
	srv := New(logger, cfg, testHMACKey, nil, v, nil)

	body, _ := json.Marshal(claimRequest{
		Token: validToken(),
	})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345" // not in 10.0.0.0/8
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Fatal: claim should be blocked.
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (fatal verifier)", w.Code)
	}
}

func TestCheckKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "enrollment-key")

	// Missing file should error.
	if err := CheckKeyFile(keyPath); err == nil {
		t.Fatal("expected error for missing key file")
	}

	// Create a key file — CheckKeyFile only verifies existence.
	os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0600)
	if err := CheckKeyFile(keyPath); err != nil {
		t.Fatalf("valid key: %v", err)
	}
}

func TestClaimScopeMismatch(t *testing.T) {
	srv := testServer(t)

	// Generate a worker-scoped token.
	workerTok := token.Generate(testHMACKey, time.Now(), testWindow, "worker")

	// Try to claim with server scope — should fail because HMAC won't match.
	body, _ := json.Marshal(claimRequest{Token: workerTok, Scope: "server"})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("scope mismatch: status = %d, want 403", w.Code)
	}
}

func TestClaimScopeMatch(t *testing.T) {
	srv := testServer(t)

	// Generate a worker-scoped token and claim with matching scope.
	workerTok := token.Generate(testHMACKey, time.Now(), testWindow, "worker")

	body, _ := json.Marshal(claimRequest{Token: workerTok, Scope: "worker"})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("scope match: status = %d, want 200, body = %s", w.Code, w.Body.String())
	}
}

func TestClaimRateLimited(t *testing.T) {
	srv := testServer(t)

	// Send burst+1 requests to trigger rate limiting.
	for i := 0; i < 6; i++ {
		body, _ := json.Marshal(claimRequest{Token: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"})
		req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
		req.RemoteAddr = "10.0.0.99:12345"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if i < 5 {
			// First 5 should not be rate limited (burst=5).
			if w.Code == http.StatusTooManyRequests {
				t.Fatalf("request %d should not be rate limited", i)
			}
		} else {
			if w.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d: status = %d, want 429", i, w.Code)
			}
		}
	}
}

func TestClaimLargeBody(t *testing.T) {
	srv := testServer(t)

	largeBody := strings.Repeat("x", 8192)
	req := httptest.NewRequest("POST", "/claim", strings.NewReader(largeBody))
	req.RemoteAddr = "192.168.1.200:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("large body: status = %d, want 400", w.Code)
	}
}
