package action

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestVaultCertAuth_EnableAndCreateRole(t *testing.T) {
	var authEnabled atomic.Bool
	var roleCreated atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "mgmt-token" {
			t.Errorf("expected mgmt-token, got %q", r.Header.Get("X-Vault-Token"))
		}
		switch {
		case r.URL.Path == "/v1/sys/auth/cert" && r.Method == http.MethodPost:
			var body map[string]string
			json.NewDecoder(r.Body).Decode(&body)
			if body["type"] != "cert" {
				t.Errorf("expected type=cert, got %q", body["type"])
			}
			authEnabled.Store(true)
			w.WriteHeader(http.StatusNoContent)

		case r.URL.Path == "/v1/auth/cert/certs/node" && r.Method == http.MethodPost:
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			if body["certificate"] != "FAKE-CA-PEM" {
				t.Errorf("expected certificate=FAKE-CA-PEM, got %q", body["certificate"])
			}
			if body["token_ttl"] != "2h" {
				t.Errorf("expected token_ttl=2h, got %q", body["token_ttl"])
			}
			roleCreated.Store(true)
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	caFile := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(caFile, []byte("FAKE-CA-PEM"), 0600)

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":         srv.URL,
		"ca_cert_file": caFile,
		"token_secret": "vault_management_token",
		"role":         "node",
		"policies":     []string{"node-pki"},
		"token_ttl":    "2h",
	})

	a, err := newVaultCertAuth(jsonToBody(t, cfgJSON))
	if err != nil {
		t.Fatalf("newVaultCertAuth: %v", err)
	}

	secrets := map[string]string{"vault_management_token": "mgmt-token"}
	if err := a.Run(context.Background(), slog.Default(), secrets); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !authEnabled.Load() {
		t.Error("auth/cert was not enabled")
	}
	if !roleCreated.Load() {
		t.Error("cert role was not created")
	}
}

func TestVaultCertAuth_AlreadyEnabled(t *testing.T) {
	var roleCreated atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/auth/cert" && r.Method == http.MethodPost:
			// Simulate "path is already in use" error
			w.WriteHeader(http.StatusBadRequest)
			io.WriteString(w, `{"errors":["path is already in use at cert/"]}`)

		case r.URL.Path == "/v1/auth/cert/certs/node" && r.Method == http.MethodPost:
			roleCreated.Store(true)
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	caFile := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(caFile, []byte("FAKE-CA-PEM"), 0600)

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":         srv.URL,
		"ca_cert_file": caFile,
		"token_secret": "vault_management_token",
		"role":         "node",
		"policies":     []string{"node-pki"},
	})

	a, err := newVaultCertAuth(jsonToBody(t, cfgJSON))
	if err != nil {
		t.Fatalf("newVaultCertAuth: %v", err)
	}

	secrets := map[string]string{"vault_management_token": "mgmt-token"}
	if err := a.Run(context.Background(), slog.Default(), secrets); err != nil {
		t.Fatalf("expected success when auth/cert already enabled, got: %v", err)
	}

	if !roleCreated.Load() {
		t.Error("cert role should still be created/upserted")
	}
}

func TestVaultCertAuth_MissingSecret(t *testing.T) {
	caFile := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(caFile, []byte("FAKE-CA-PEM"), 0600)

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":         "http://127.0.0.1:8200",
		"ca_cert_file": caFile,
		"token_secret": "vault_management_token",
		"role":         "node",
		"policies":     []string{"node-pki"},
	})

	a, err := newVaultCertAuth(jsonToBody(t, cfgJSON))
	if err != nil {
		t.Fatalf("newVaultCertAuth: %v", err)
	}

	// Empty secrets map — token_secret not found.
	err = a.Run(context.Background(), slog.Default(), map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing secret")
	}
	if got := err.Error(); got != `vault-cert-auth: secret "vault_management_token" not found in derived secrets` {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVaultCertAuth_MissingCAFile(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":         "http://127.0.0.1:8200",
		"ca_cert_file": "/nonexistent/ca.crt",
		"token_secret": "vault_management_token",
		"role":         "node",
		"policies":     []string{"node-pki"},
	})

	a, err := newVaultCertAuth(jsonToBody(t, cfgJSON))
	if err != nil {
		t.Fatalf("newVaultCertAuth: %v", err)
	}

	secrets := map[string]string{"vault_management_token": "mgmt-token"}
	err = a.Run(context.Background(), slog.Default(), secrets)
	if err == nil {
		t.Fatal("expected error for missing CA file")
	}
	if got := err.Error(); !strings.Contains(got, "read CA cert") {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVaultCertAuth_VaultError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/auth/cert":
			// Non-"already in use" error
			w.WriteHeader(http.StatusForbidden)
			io.WriteString(w, `{"errors":["permission denied"]}`)
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	caFile := filepath.Join(t.TempDir(), "ca.crt")
	os.WriteFile(caFile, []byte("FAKE-CA-PEM"), 0600)

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":         srv.URL,
		"ca_cert_file": caFile,
		"token_secret": "vault_management_token",
		"role":         "node",
		"policies":     []string{"node-pki"},
	})

	a, err := newVaultCertAuth(jsonToBody(t, cfgJSON))
	if err != nil {
		t.Fatalf("newVaultCertAuth: %v", err)
	}

	secrets := map[string]string{"vault_management_token": "mgmt-token"}
	err = a.Run(context.Background(), slog.Default(), secrets)
	if err == nil {
		t.Fatal("expected error for permission denied")
	}
	if got := err.Error(); !strings.Contains(got, "enable auth/cert") {
		t.Errorf("unexpected error: %s", got)
	}
}

func TestVaultCertAuth_ConfigValidation(t *testing.T) {
	tests := []struct {
		name string
		cfg  map[string]interface{}
		want string
	}{
		{
			name: "missing ca_cert_file",
			cfg:  map[string]interface{}{"token_secret": "tok", "role": "r", "policies": []string{"p"}},
			want: "ca_cert_file",
		},
		{
			name: "missing token_secret",
			cfg:  map[string]interface{}{"ca_cert_file": "/ca.crt", "role": "r", "policies": []string{"p"}},
			want: "token_secret",
		},
		{
			name: "missing role",
			cfg:  map[string]interface{}{"ca_cert_file": "/ca.crt", "token_secret": "tok", "policies": []string{"p"}},
			want: "role",
		},
		{
			name: "missing policies",
			cfg:  map[string]interface{}{"ca_cert_file": "/ca.crt", "token_secret": "tok", "role": "r"},
			want: "policies",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfgJSON, _ := json.Marshal(tt.cfg)
			_, err := newVaultCertAuth(jsonToBody(t, cfgJSON))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q should contain %q", err.Error(), tt.want)
			}
		})
	}
}
