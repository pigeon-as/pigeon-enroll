package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	cfg := Config{
		TokenWindow: time.Minute,
		Secrets:     []SecretSpec{{Name: "vault_token", Length: 32, Encoding: "hex"}},
		Vault: &VaultConfig{
			Token: VaultTokenConfig{ID: "vault_token"},
		},
	}
	if err := validate(cfg); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestValidateVaultTokenRefersToMissingSecret(t *testing.T) {
	cfg := Config{
		TokenWindow: time.Minute,
		Secrets:     []SecretSpec{{Name: "other", Length: 32, Encoding: "hex"}},
		Vault: &VaultConfig{
			Token: VaultTokenConfig{ID: "nonexistent"},
		},
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
		"vault": {"token": {"id": "mgmt"}}
	}`), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Vault.Addr != "https://127.0.0.1:8200" {
		t.Errorf("vault.addr = %q, want https://127.0.0.1:8200", cfg.Vault.Addr)
	}
	if cfg.Vault.SecretShares != 1 {
		t.Errorf("vault.secret_shares = %d, want 1", cfg.Vault.SecretShares)
	}
	if cfg.Vault.SecretThreshold != 1 {
		t.Errorf("vault.secret_threshold = %d, want 1", cfg.Vault.SecretThreshold)
	}
	if len(cfg.Vault.Token.Policies) != 1 || cfg.Vault.Token.Policies[0] != "root" {
		t.Errorf("vault.token.policies = %v, want [root]", cfg.Vault.Token.Policies)
	}
}
