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

	"github.com/hashicorp/hcl/v2"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/shoenig/test/must"
)

func jsonToBody(t *testing.T, data []byte) hcl.Body {
	t.Helper()
	f, diags := hcljson.Parse(data, "test.json")
	if diags.HasErrors() {
		t.Fatalf("parse test body: %s", diags.Error())
	}
	return f.Body
}

func TestVaultInit_AlreadyInitialized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/init" && r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]bool{"initialized": true})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	outputPath := filepath.Join(t.TempDir(), "init.json")
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":               srv.URL,
		"recovery_shares":    1,
		"recovery_threshold": 1,
		"output":             outputPath,
	})

	a, err := newVaultInit(jsonToBody(t, cfgJSON))
	must.NoError(t, err)
	must.NoError(t, a.Run(context.Background(), slog.Default(), nil))
}

func TestVaultInit_AlreadyInitialized_SkipsMissingSecret(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sys/init" && r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]bool{"initialized": true})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":               srv.URL,
		"recovery_shares":    1,
		"recovery_threshold": 1,
		"output":             filepath.Join(t.TempDir(), "init.json"),
		"token": map[string]interface{}{
			"id":          "nonexistent_secret",
			"revoke_root": true,
		},
	})

	a, err := newVaultInit(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	// Should skip cleanly — tokenID resolution is deferred past the initialized check.
	must.NoError(t, a.Run(context.Background(), slog.Default(), map[string]string{}))
}

func TestVaultInit_RevokeRootWithoutManagementToken(t *testing.T) {
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

	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":             srv.URL,
		"secret_shares":    1,
		"secret_threshold": 1,
		"output":           filepath.Join(t.TempDir(), "init.json"),
		"token": map[string]interface{}{
			"id":          "missing_secret",
			"revoke_root": true,
		},
	})

	a, err := newVaultInit(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	err = a.Run(context.Background(), slog.Default(), map[string]string{})
	must.Error(t, err)
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
			must.EqOp(t, "s.root-token-123", r.Header.Get("X-Vault-Token"))
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			must.EqOp(t, "my-management-token", body["id"])
			tokenCreated.Store(true)
			json.NewEncoder(w).Encode(map[string]interface{}{"auth": map[string]interface{}{"client_token": "my-management-token"}})

		case r.URL.Path == "/v1/auth/token/revoke-self" && r.Method == http.MethodPost:
			must.EqOp(t, "s.root-token-123", r.Header.Get("X-Vault-Token"))
			rootRevoked.Store(true)
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	outputPath := filepath.Join(t.TempDir(), "init.json")
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":               srv.URL,
		"secret_shares":      1,
		"secret_threshold":   1,
		"recovery_shares":    1,
		"recovery_threshold": 1,
		"output":             outputPath,
		"token": map[string]interface{}{
			"id":          "vault_management_token",
			"policies":    []string{"root"},
			"revoke_root": true,
		},
	})

	a, err := newVaultInit(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	secrets := map[string]string{
		"vault_management_token": "my-management-token",
	}
	must.NoError(t, a.Run(context.Background(), slog.Default(), secrets))
	must.True(t, tokenCreated.Load())
	must.True(t, rootRevoked.Load())

	data, err := os.ReadFile(outputPath)
	must.NoError(t, err)
	var resp initResponse
	must.NoError(t, json.Unmarshal(data, &resp))
	must.EqOp(t, "<revoked>", resp.RootToken)
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
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":             srv.URL,
		"secret_shares":    1,
		"secret_threshold": 1,
		"output":           outputPath,
	})

	a, err := newVaultInit(jsonToBody(t, cfgJSON))
	must.NoError(t, err)
	must.NoError(t, a.Run(context.Background(), slog.Default(), nil))

	data, err := os.ReadFile(outputPath)
	must.NoError(t, err)
	var resp initResponse
	must.NoError(t, json.Unmarshal(data, &resp))
	must.EqOp(t, "s.root-token-abc", resp.RootToken)
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

	outputPath := filepath.Join(t.TempDir(), "init.json")
	cfgJSON, _ := json.Marshal(map[string]interface{}{
		"addr":             srv.URL,
		"secret_shares":    1,
		"secret_threshold": 1,
		"output":           outputPath,
		"token": map[string]interface{}{
			"id": "nonexistent_secret",
		},
	})

	a, err := newVaultInit(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	err = a.Run(context.Background(), slog.Default(), map[string]string{})
	must.Error(t, err)
}

func TestRun_UnknownActionType(t *testing.T) {
	cfgs := []Config{{Type: "nonexistent", Body: jsonToBody(t, []byte(`{}`))}}
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
	body := jsonToBody(t, []byte(`{"token": {"id": "my_token"}}`))
	a, err := New(Config{Type: "vault-init", Body: body})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	names := a.SecretNames()
	if len(names) != 1 || names[0] != "my_token" {
		t.Errorf("SecretNames = %v, want [my_token]", names)
	}
}
