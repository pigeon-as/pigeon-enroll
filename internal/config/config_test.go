package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/action"
)

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"vars": {"k": "v"}}`), 0644)

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
}

func TestLoadTokenWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"vars": {"k": "v"}, "token_window": "15m"}`), 0644)

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
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"vars": {"k": "v"}, "token_window": "bogus"}`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for invalid token_window")
	}
}

func TestLoadTokenWindowTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{"vars": {"k": "v"}, "token_window": "500ms"}`), 0644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for sub-second token_window")
	}
}

func TestValidateSecretsOrVars(t *testing.T) {
	// Neither vars nor secrets → error.
	err := validate(Config{TokenWindow: time.Minute})
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
				TokenWindow: time.Minute,
				Secrets:     []SecretSpec{tt.spec},
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
		TokenWindow: time.Minute,
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
		TokenWindow: time.Minute,
		Secrets:     []SecretSpec{{Name: "k", Length: 32, Encoding: "base64"}},
		Vars:        map[string]string{"k": "v"},
	}
	if err := validate(cfg); err == nil {
		t.Error("expected error for name conflict")
	}
}

func TestValidateVaultTokenRefersToSecret(t *testing.T) {
	vaultCfg, _ := json.Marshal(map[string]interface{}{
		"token": map[string]interface{}{"id": "vault_token"},
	})
	cfg := Config{
		TokenWindow: time.Minute,
		Secrets:     []SecretSpec{{Name: "vault_token", Length: 32, Encoding: "hex"}},
		Actions:     []action.Config{{Type: "vault-init", Config: vaultCfg}},
	}
	if err := validate(cfg); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateVaultTokenRefersToMissingSecret(t *testing.T) {
	vaultCfg, _ := json.Marshal(map[string]interface{}{
		"token": map[string]interface{}{"id": "nonexistent"},
	})
	cfg := Config{
		TokenWindow: time.Minute,
		Secrets:     []SecretSpec{{Name: "other", Length: 32, Encoding: "hex"}},
		Actions:     []action.Config{{Type: "vault-init", Config: vaultCfg}},
	}
	if err := validate(cfg); err == nil {
		t.Error("expected error for vault.token.id referencing missing secret")
	}
}

func TestLoadVaultDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	os.WriteFile(path, []byte(`{
		"secrets": [{"name": "mgmt", "length": 32, "encoding": "hex"}],
		"actions": [{"type": "vault-init", "config": {"token": {"id": "mgmt"}}}]
	}`), 0644)

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
