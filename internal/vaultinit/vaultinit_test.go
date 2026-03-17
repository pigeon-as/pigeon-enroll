package vaultinit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
)

func TestRun_AlreadyInitialized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/init" && r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]bool{"initialized": true})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	cfg := &config.VaultConfig{
		Addr:              srv.URL,
		RecoveryShares:    1,
		RecoveryThreshold: 1,
	}

	err := Run(context.Background(), slog.Default(), cfg, nil, filepath.Join(t.TempDir(), "init.json"))
	if err != nil {
		t.Fatalf("expected nil error for already-initialized Vault, got: %v", err)
	}
}

func TestRun_InitAndCreateToken(t *testing.T) {
	var tokenCreated atomic.Bool
	var rootRevoked atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]bool{"initialized": false})

		case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodPut:
			json.NewEncoder(w).Encode(initResponse{
				RootToken:    "s.root-token-123",
				RecoveryKeys: []string{"recovery-key-1"},
			})

		case r.URL.Path == "/v1/auth/token/create" && r.Method == http.MethodPost:
			if r.Header.Get("X-Vault-Token") != "s.root-token-123" {
				t.Error("expected root token in X-Vault-Token header")
			}
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			if body["id"] != "my-management-token" {
				t.Errorf("expected token id 'my-management-token', got %v", body["id"])
			}
			tokenCreated.Store(true)
			json.NewEncoder(w).Encode(map[string]interface{}{"auth": map[string]interface{}{"client_token": "my-management-token"}})

		case r.URL.Path == "/v1/auth/token/revoke-self" && r.Method == http.MethodPost:
			if r.Header.Get("X-Vault-Token") != "s.root-token-123" {
				t.Error("expected root token for revoke-self")
			}
			rootRevoked.Store(true)
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	outputPath := filepath.Join(t.TempDir(), "init.json")

	cfg := &config.VaultConfig{
		Addr:              srv.URL,
		SecretShares:      1,
		SecretThreshold:   1,
		RecoveryShares:    1,
		RecoveryThreshold: 1,
		Token: config.VaultTokenConfig{
			ID:         "vault_management_token",
			Policies:   []string{"root"},
			RevokeRoot: true,
		},
	}

	secrets := map[string]string{
		"vault_management_token": "my-management-token",
	}

	err := Run(context.Background(), slog.Default(), cfg, secrets, outputPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !tokenCreated.Load() {
		t.Error("management token was not created")
	}
	if !rootRevoked.Load() {
		t.Error("root token was not revoked")
	}

	// Verify init response was written.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var resp initResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if resp.RootToken != "" {
		t.Errorf("expected redacted root token (empty), got %q", resp.RootToken)
	}
}

func TestRun_InitWithoutToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]bool{"initialized": false})

		case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodPut:
			json.NewEncoder(w).Encode(initResponse{
				RootToken:    "s.root-token-abc",
				RecoveryKeys: []string{"key-1"},
			})

		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	outputPath := filepath.Join(t.TempDir(), "init.json")

	cfg := &config.VaultConfig{
		Addr:            srv.URL,
		SecretShares:    1,
		SecretThreshold: 1,
		// No Token.ID — skip management token creation.
	}

	err := Run(context.Background(), slog.Default(), cfg, nil, outputPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify output file exists with correct content.
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var resp initResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if resp.RootToken != "s.root-token-abc" {
		t.Errorf("expected root token 's.root-token-abc', got %q", resp.RootToken)
	}
}

func TestRun_MissingSecretForTokenID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodGet:
			json.NewEncoder(w).Encode(map[string]bool{"initialized": false})
		case r.URL.Path == "/v1/sys/init" && r.Method == http.MethodPut:
			json.NewEncoder(w).Encode(initResponse{
				RootToken:    "s.root",
				RecoveryKeys: []string{"key"},
			})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := &config.VaultConfig{
		Addr:            srv.URL,
		SecretShares:    1,
		SecretThreshold: 1,
		Token: config.VaultTokenConfig{
			ID: "nonexistent_secret",
		},
	}

	err := Run(context.Background(), slog.Default(), cfg, map[string]string{}, filepath.Join(t.TempDir(), "init.json"))
	if err == nil {
		t.Fatal("expected error for missing secret, got nil")
	}
}
