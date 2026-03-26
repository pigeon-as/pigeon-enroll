package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/pigeon-as/pigeon-enroll/internal/action"
)

func testBody(t *testing.T, jsonStr string) hcl.Body {
	t.Helper()
	f, diags := hcljson.Parse([]byte(jsonStr), "test.json")
	if diags.HasErrors() {
		t.Fatalf("parse test body: %s", diags.Error())
	}
	return f.Body
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`vars = { k = "v" }`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Listen != ":8443" {
		t.Errorf("listen = %q, want :8443", cfg.Listen)
	}
	if cfg.KeyPath != "/etc/pigeon/enrollment-key" {
		t.Errorf("key_path = %q", cfg.KeyPath)
	}
	if cfg.TokenWindow != 30*time.Minute {
		t.Errorf("token_window = %v, want 30m", cfg.TokenWindow)
	}
	if cfg.ClientCertTTL != time.Hour {
		t.Errorf("client_cert_ttl = %v, want 1h", cfg.ClientCertTTL)
	}
	if cfg.ServerCertTTL != 720*time.Hour {
		t.Errorf("server_cert_ttl = %v, want 720h", cfg.ServerCertTTL)
	}
}

func TestLoadTokenWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
vars = { k = "v" }
token_window = "15m"
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.TokenWindow != 15*time.Minute {
		t.Errorf("token_window = %v, want 15m", cfg.TokenWindow)
	}
}

func TestLoadTokenWindowInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
vars = { k = "v" }
token_window = "bogus"
`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid token_window")
	}
}

func TestLoadTokenWindowTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
vars = { k = "v" }
token_window = "500ms"
`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for sub-second token_window")
	}
}

func TestLoadCertTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
vars = { k = "v" }
client_cert_ttl = "2h"
server_cert_ttl = "48h"
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.ClientCertTTL != 2*time.Hour {
		t.Errorf("client_cert_ttl = %v, want 2h", cfg.ClientCertTTL)
	}
	if cfg.ServerCertTTL != 48*time.Hour {
		t.Errorf("server_cert_ttl = %v, want 48h", cfg.ServerCertTTL)
	}
}

func TestLoadCertTTLInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")

	os.WriteFile(path, []byte(`
vars = { k = "v" }
client_cert_ttl = "bogus"
`), 0644)
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid client_cert_ttl")
	}

	os.WriteFile(path, []byte(`
vars = { k = "v" }
server_cert_ttl = "bogus"
`), 0644)
	if _, err := Load(path); err == nil {
		t.Error("expected error for invalid server_cert_ttl")
	}
}

func TestLoadCertTTLTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")

	os.WriteFile(path, []byte(`
vars = { k = "v" }
client_cert_ttl = "500ms"
`), 0644)
	if _, err := Load(path); err == nil {
		t.Error("expected error for sub-second client_cert_ttl")
	}

	os.WriteFile(path, []byte(`
vars = { k = "v" }
server_cert_ttl = "100ms"
`), 0644)
	if _, err := Load(path); err == nil {
		t.Error("expected error for sub-second server_cert_ttl")
	}
}

func TestValidateSecretsOrVars(t *testing.T) {
	// Neither vars nor secrets → error.
	err := validate(Config{TokenWindow: time.Minute, ClientCertTTL: time.Hour, ServerCertTTL: time.Hour})
	if err == nil {
		t.Error("expected error for empty vars and secrets")
	}
}

func TestValidateSecretSpec(t *testing.T) {
	tests := []struct {
		name string
		spec SecretSpec
		ok   bool
	}{
		{"valid base64", SecretSpec{Name: "k", Length: 32, Encoding: "base64"}, true},
		{"valid hex", SecretSpec{Name: "k", Length: 16, Encoding: "hex"}, true},
		{"missing name", SecretSpec{Length: 32, Encoding: "base64"}, false},
		{"zero length", SecretSpec{Name: "k", Length: 0, Encoding: "base64"}, false},
		{"bad encoding", SecretSpec{Name: "k", Length: 32, Encoding: "raw"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				TokenWindow:   time.Minute,
				ClientCertTTL: time.Hour,
				ServerCertTTL: time.Hour,
				Secrets:       []SecretSpec{tt.spec},
			}
			err := validate(cfg)
			if tt.ok && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tt.ok && err == nil {
				t.Error("expected validation error")
			}
		})
	}
}

func TestValidateDuplicateSecretName(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ClientCertTTL: time.Hour,
		ServerCertTTL: time.Hour,
		Secrets: []SecretSpec{
			{Name: "k", Length: 32, Encoding: "base64"},
			{Name: "k", Length: 16, Encoding: "hex"},
		},
	}
	if err := validate(cfg); err == nil {
		t.Error("expected error for duplicate secret name")
	}
}

func TestValidateNameConflict(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ClientCertTTL: time.Hour,
		ServerCertTTL: time.Hour,
		Secrets:       []SecretSpec{{Name: "k", Length: 32, Encoding: "base64"}},
		Vars:          map[string]string{"k": "v"},
	}
	if err := validate(cfg); err == nil {
		t.Error("expected error for name conflict")
	}
}

func TestValidateVaultTokenRefersToSecret(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ClientCertTTL: time.Hour,
		ServerCertTTL: time.Hour,
		Secrets:       []SecretSpec{{Name: "vault_token", Length: 32, Encoding: "hex"}},
		Actions:       []action.Config{{Type: "vault-init", Body: testBody(t, `{"token": {"id": "vault_token"}}`)}},
	}
	if err := validate(cfg); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateVaultTokenRefersToMissingSecret(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ClientCertTTL: time.Hour,
		ServerCertTTL: time.Hour,
		Secrets:       []SecretSpec{{Name: "other", Length: 32, Encoding: "hex"}},
		Actions:       []action.Config{{Type: "vault-init", Body: testBody(t, `{"token": {"id": "nonexistent"}}`)}},
	}
	if err := validate(cfg); err == nil {
		t.Error("expected error for vault.token.id referencing missing secret")
	}
}

func TestLoadActionConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
secret "mgmt" {
  length   = 32
  encoding = "hex"
}

action "vault-init" {
  token {
    id = "mgmt"
  }
}
`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Actions) != 1 {
		t.Fatalf("actions = %d, want 1", len(cfg.Actions))
	}
	if cfg.Actions[0].Type != "vault-init" {
		t.Errorf("action type = %q, want vault-init", cfg.Actions[0].Type)
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
