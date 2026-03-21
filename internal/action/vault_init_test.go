package action

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
)

func TestVaultInit_AlreadyInitialized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/init" && r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]bool{"initialized": true})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	cfgJSON, _ := json.Marshal(vaultInitConfig{
		Addr:              srv.URL,
		RecoveryShares:    1,
		RecoveryThreshold: 1,
		Output:            filepath.Join(t.TempDir(), "init.json"),
	})

	a, err := newVaultInit(cfgJSON)
	if err != nil {
		t.Fatalf("newVaultInit: %v", err)
	}

	if err := a.Run(context.Background(), slog.Default(), nil); err == nil {
		t.Fatal("expected error for already-initialized Vault, got nil")
	}
}

func TestVaultInit_InitAndCreateToken(t *testing.T) {
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

	cfgJSON, _ := json.Marshal(vaultInitConfig{
		Addr:              srv.URL,
		SecretShares:      1,
		SecretThreshold:   1,
		RecoveryShares:    1,
		RecoveryThreshold: 1,
		Output:            outputPath,
		Token: vaultTokenConfig{
			ID:         "vault_management_token",
			Policies:   []string{"root"},
			RevokeRoot: true,
		},
	})

	a, err := newVaultInit(cfgJSON)
	if err != nil {
		t.Fatalf("newVaultInit: %v", err)
	}

	secrets := map[string]string{
		"vault_management_token": "my-management-token",
	}

	if err := a.Run(context.Background(), slog.Default(), secrets); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !tokenCreated.Load() {
		t.Error("management token was not created")
	}
	if !rootRevoked.Load() {
		t.Error("root token was not revoked")
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	var resp initResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if resp.RootToken != "<revoked>" {
		t.Errorf("expected redacted root token '<revoked>', got %q", resp.RootToken)
	}
}

func TestVaultInit_InitWithoutToken(t *testing.T) {
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

	cfgJSON, _ := json.Marshal(vaultInitConfig{
		Addr:            srv.URL,
		SecretShares:    1,
		SecretThreshold: 1,
		Output:          outputPath,
	})

	a, err := newVaultInit(cfgJSON)
	if err != nil {
		t.Fatalf("newVaultInit: %v", err)
	}

	if err := a.Run(context.Background(), slog.Default(), nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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

func TestVaultInit_MissingSecretForTokenID(t *testing.T) {
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

	cfgJSON, _ := json.Marshal(vaultInitConfig{
		Addr:            srv.URL,
		SecretShares:    1,
		SecretThreshold: 1,
		Output:          filepath.Join(t.TempDir(), "init.json"),
		Token:           vaultTokenConfig{ID: "nonexistent_secret"},
	})

	a, err := newVaultInit(cfgJSON)
	if err != nil {
		t.Fatalf("newVaultInit: %v", err)
	}

	err = a.Run(context.Background(), slog.Default(), map[string]string{})
	if err == nil {
		t.Fatal("expected error for missing secret, got nil")
	}
}

func TestRun_UnknownActionType(t *testing.T) {
	cfgs := []Config{{Type: "nonexistent", Config: json.RawMessage(`{}`)}}
	err := Run(context.Background(), slog.Default(), cfgs, nil, "")
	if err == nil {
		t.Fatal("expected error for unknown action type")
	}
}

func TestRun_ActionNotFound(t *testing.T) {
	err := Run(context.Background(), slog.Default(), nil, nil, "vault-init")
	if err == nil {
		t.Fatal("expected error when action type not in config")
	}
}

func TestSecretNames_VaultInit(t *testing.T) {
	cfgJSON, _ := json.Marshal(vaultInitConfig{
		Token: vaultTokenConfig{ID: "my_token"},
	})

	a, err := New(Config{Type: "vault-init", Config: cfgJSON})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := a.SecretNames()
	if len(names) != 1 || names[0] != "my_token" {
		t.Errorf("SecretNames = %v, want [my_token]", names)
	}
}
