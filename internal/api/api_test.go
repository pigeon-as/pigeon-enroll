package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	"github.com/shoenig/test/must"
)

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
	srv, err := New(logger, cfg, testHMACKey, secrets, nil, nil, nil)
	must.NoError(t, err)
	t.Cleanup(srv.Close)
	return srv
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

	must.EqOp(t, http.StatusOK, w.Code)

	var resp claimResponse
	must.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	must.MapLen(t, 3, resp.Secrets)
	must.EqOp(t, "dGVzdA==", resp.Secrets["secret_a"])
	must.MapLen(t, 1, resp.Vars)
	must.EqOp(t, "dc1", resp.Vars["datacenter"])
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

	must.EqOp(t, http.StatusForbidden, w.Code)
}

func TestClaimExpiredToken(t *testing.T) {
	srv := testServer(t)

	expired := token.Generate(testHMACKey, time.Now().Add(-2*testWindow-time.Second), testWindow, "")
	body, _ := json.Marshal(claimRequest{
		Token: expired,
	})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	must.EqOp(t, http.StatusForbidden, w.Code)
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
	must.EqOp(t, http.StatusOK, w.Code)

	// Second use of same token should be rejected (nonce replay).
	body2, _ := json.Marshal(claimRequest{Token: tok})
	req2 := httptest.NewRequest("POST", "/claim", bytes.NewReader(body2))
	req2.RemoteAddr = "192.168.1.100:12345"
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)
	must.EqOp(t, http.StatusForbidden, w2.Code)
}

func TestHealth(t *testing.T) {
	srv := testServer(t)

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	must.EqOp(t, http.StatusOK, w.Code)
}

func TestClaimScopeMismatch(t *testing.T) {
	srv := testServer(t)

	workerTok := token.Generate(testHMACKey, time.Now(), testWindow, "worker")

	body, _ := json.Marshal(claimRequest{Token: workerTok, Scope: "server"})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	must.EqOp(t, http.StatusForbidden, w.Code)
}

func TestClaimScopeMatch(t *testing.T) {
	srv := testServer(t)

	workerTok := token.Generate(testHMACKey, time.Now(), testWindow, "worker")

	body, _ := json.Marshal(claimRequest{Token: workerTok, Scope: "worker"})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	must.EqOp(t, http.StatusOK, w.Code)
}

func TestClaimRateLimited(t *testing.T) {
	srv := testServer(t)

	for i := 0; i < 6; i++ {
		body, _ := json.Marshal(claimRequest{Token: "deadbeefdeadbeefdeadbeefdeadbeef" + "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"})
		req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
		req.RemoteAddr = "10.0.0.99:12345"
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if i < 5 {
			must.NotEq(t, http.StatusTooManyRequests, w.Code, must.Sprintf("request %d should not be rate limited", i))
		} else {
			must.EqOp(t, http.StatusTooManyRequests, w.Code)
		}
	}
}

func TestClaimCAScopeFiltering(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.Config{
		TokenWindow: testWindow,
		Vars:        map[string]string{"k": "v"},
		CAs: []config.CASpec{
			{Name: "shared"},
			{Name: "server_ca", Scope: []string{"server"}},
			{Name: "both_ca", Scope: []string{"server", "worker"}},
		},
	}
	cas := map[string]secrets.CAEntry{
		"shared":    {CertPEM: "shared-cert", PrivateKeyPEM: "shared-key"},
		"server_ca": {CertPEM: "server-cert", PrivateKeyPEM: "server-key"},
		"both_ca":   {CertPEM: "both-cert", PrivateKeyPEM: "both-key"},
	}
	srv, err := New(logger, cfg, testHMACKey, nil, cas, nil, nil)
	must.NoError(t, err)
	t.Cleanup(srv.Close)

	// Worker scope: shared no key (empty scope), server_ca no key, both_ca has key.
	workerTok := token.Generate(testHMACKey, time.Now(), testWindow, "worker")
	body, _ := json.Marshal(claimRequest{Token: workerTok, Scope: "worker"})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	must.EqOp(t, http.StatusOK, w.Code)
	var resp claimResponse
	must.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	must.MapLen(t, 3, resp.CA)
	must.EqOp(t, "shared-cert", resp.CA["shared"].CertPEM)
	must.EqOp(t, "", resp.CA["shared"].PrivateKeyPEM)
	must.EqOp(t, "server-cert", resp.CA["server_ca"].CertPEM)
	must.EqOp(t, "", resp.CA["server_ca"].PrivateKeyPEM)
	must.EqOp(t, "both-cert", resp.CA["both_ca"].CertPEM)
	must.EqOp(t, "both-key", resp.CA["both_ca"].PrivateKeyPEM)

	// Server scope: shared still no key, server_ca has key, both_ca has key.
	serverTok := token.Generate(testHMACKey, time.Now(), testWindow, "server")
	body2, _ := json.Marshal(claimRequest{Token: serverTok, Scope: "server"})
	req2 := httptest.NewRequest("POST", "/claim", bytes.NewReader(body2))
	req2.RemoteAddr = "192.168.1.100:12345"
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	must.EqOp(t, http.StatusOK, w2.Code)
	var resp2 claimResponse
	must.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp2))
	must.MapLen(t, 3, resp2.CA)
	must.EqOp(t, "", resp2.CA["shared"].PrivateKeyPEM)
	must.EqOp(t, "server-key", resp2.CA["server_ca"].PrivateKeyPEM)
	must.EqOp(t, "both-key", resp2.CA["both_ca"].PrivateKeyPEM)
}

func TestClaimCertIssuance(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	namedCA, err := pki.DeriveNamedCA(testKey, "auth")
	must.NoError(t, err)

	cfg := config.Config{
		TokenWindow: testWindow,
		Vars:        map[string]string{"k": "v"},
		CAs: []config.CASpec{
			{Name: "auth", Scope: []string{"server"}},
		},
		Certs: []config.CertSpec{
			{
				Name:  "auth_worker",
				CA:    "auth",
				Scope: []string{"worker"},
				TTL:   720 * time.Hour,
				CN:    "worker",
			},
		},
	}
	cas := map[string]secrets.CAEntry{
		"auth": {CertPEM: string(namedCA.CertPEM), PrivateKeyPEM: string(namedCA.KeyPEM)},
	}
	srv, err := New(logger, cfg, testHMACKey, nil, cas, nil, nil)
	must.NoError(t, err)
	t.Cleanup(srv.Close)

	// Worker claim: cert issued, no CA private key.
	workerTok := token.Generate(testHMACKey, time.Now(), testWindow, "worker")
	body, _ := json.Marshal(claimRequest{Token: workerTok, Scope: "worker"})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	must.EqOp(t, http.StatusOK, w.Code)
	var resp claimResponse
	must.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	must.NotEq(t, "", resp.CA["auth"].CertPEM)
	must.EqOp(t, "", resp.CA["auth"].PrivateKeyPEM)

	must.MapLen(t, 1, resp.Certs)
	cert := resp.Certs["auth_worker"]
	must.NotEq(t, "", cert.CertPEM)
	must.NotEq(t, "", cert.KeyPEM)

	// Server claim: CA private key, no cert (scope mismatch).
	serverTok := token.Generate(testHMACKey, time.Now(), testWindow, "server")
	body2, _ := json.Marshal(claimRequest{Token: serverTok, Scope: "server"})
	req2 := httptest.NewRequest("POST", "/claim", bytes.NewReader(body2))
	req2.RemoteAddr = "192.168.1.100:12345"
	w2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w2, req2)

	must.EqOp(t, http.StatusOK, w2.Code)
	var resp2 claimResponse
	must.NoError(t, json.Unmarshal(w2.Body.Bytes(), &resp2))
	must.NotEq(t, "", resp2.CA["auth"].PrivateKeyPEM)
	must.MapLen(t, 0, resp2.Certs)
}

func TestClaimRequireTPM(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config.Config{
		TokenWindow: testWindow,
		RequireTPM:  true,
	}
	srv, err := New(logger, cfg, testHMACKey, nil, nil, nil, nil)
	must.NoError(t, err)
	t.Cleanup(srv.Close)

	tok := token.Generate(testHMACKey, time.Now(), testWindow, "")
	body, _ := json.Marshal(claimRequest{Token: tok})
	req := httptest.NewRequest("POST", "/claim", bytes.NewReader(body))
	req.RemoteAddr = "192.168.1.100:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	must.EqOp(t, http.StatusForbidden, w.Code)
	must.StrContains(t, w.Body.String(), "TPM attestation required")
}

func TestClaimLargeBody(t *testing.T) {
	srv := testServer(t)

	largeBody := strings.Repeat("x", 8192)
	req := httptest.NewRequest("POST", "/claim", strings.NewReader(largeBody))
	req.RemoteAddr = "192.168.1.200:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	must.EqOp(t, http.StatusBadRequest, w.Code)
}
