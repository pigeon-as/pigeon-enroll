// Package config loads and validates the pigeon-enroll JSON configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/verify"
)

// SecretSpec describes a secret to derive from the enrollment key via HKDF.
type SecretSpec struct {
	Name     string `json:"name"`
	Length   int    `json:"length"`
	Encoding string `json:"encoding"` // "base64" or "hex"
	Scope    string `json:"scope"`    // optional: only returned to claims matching this scope
}

// VaultTokenConfig holds the management token configuration.
type VaultTokenConfig struct {
	// ID references a secret name from the secrets array. The derived secret
	// value becomes the custom token ID passed to vault token create.
	ID string `json:"id"`
	// Policies to attach to the management token (default: ["root"]).
	Policies []string `json:"policies"`
	// RevokeRoot revokes the initial root token after the management token is created.
	RevokeRoot bool `json:"revoke_root"`
}

// VaultConfig holds vault initialization settings.
// Supports both Shamir and auto-unseal modes:
//   - Shamir: set secret_shares + secret_threshold (default 1/1)
//   - Auto-unseal: also set recovery_shares + recovery_threshold
type VaultConfig struct {
	Addr              string           `json:"addr"`
	TLSSkipVerify     bool             `json:"tls_skip_verify"`
	SecretShares      int              `json:"secret_shares"`
	SecretThreshold   int              `json:"secret_threshold"`
	RecoveryShares    int              `json:"recovery_shares"`
	RecoveryThreshold int              `json:"recovery_threshold"`
	Token             VaultTokenConfig `json:"token"`
}

// Config holds the pigeon-enroll configuration.
type Config struct {
	Listen         string            `json:"listen"`
	KeyPath        string            `json:"key_path"`
	TLSCert        string            `json:"tls_cert"`
	TLSKey         string            `json:"tls_key"`
	TokenWindow    time.Duration     `json:"-"`
	TokenWindowRaw string            `json:"token_window"`
	AuditPath      string            `json:"audit_path"`
	Verifiers      []verify.Config   `json:"verifiers"`
	Vars           map[string]string `json:"vars"`
	Secrets        []SecretSpec      `json:"secrets"`
	SecretsPath    string            `json:"secrets_path"`
	TrustedProxies []string          `json:"trusted_proxies"`
	Vault          *VaultConfig      `json:"vault"`
}

// Load reads a JSON config file and returns a validated Config with defaults applied.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = "/etc/pigeon/enrollment-key"
	}
	if cfg.TokenWindowRaw == "" {
		cfg.TokenWindow = 30 * time.Minute
	} else {
		d, err := time.ParseDuration(cfg.TokenWindowRaw)
		if err != nil {
			return Config{}, fmt.Errorf("parse token_window: %w", err)
		}
		cfg.TokenWindow = d
	}

	// Apply vault defaults.
	if cfg.Vault != nil {
		if cfg.Vault.Addr == "" {
			cfg.Vault.Addr = "https://127.0.0.1:8200"
		}
		if cfg.Vault.SecretShares == 0 {
			cfg.Vault.SecretShares = 1
		}
		if cfg.Vault.SecretThreshold == 0 {
			cfg.Vault.SecretThreshold = 1
		}
		// RecoveryShares/RecoveryThreshold: 0 means Shamir-only (no auto-unseal).
		if len(cfg.Vault.Token.Policies) == 0 {
			cfg.Vault.Token.Policies = []string{"root"}
		}
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validate(cfg Config) error {
	if cfg.TokenWindow < time.Second {
		return fmt.Errorf("token_window must be at least 1s")
	}
	if len(cfg.Vars) == 0 && len(cfg.Secrets) == 0 {
		return fmt.Errorf("vars or secrets must not be empty")
	}
	seen := make(map[string]bool, len(cfg.Secrets)+len(cfg.Vars))
	for _, s := range cfg.Secrets {
		if s.Name == "" {
			return fmt.Errorf("secrets: name is required")
		}
		if s.Length <= 0 {
			return fmt.Errorf("secret %q: length must be positive", s.Name)
		}
		if s.Encoding != "base64" && s.Encoding != "hex" {
			return fmt.Errorf("secret %q: encoding must be \"base64\" or \"hex\"", s.Name)
		}
		if seen[s.Name] {
			return fmt.Errorf("secret %q: duplicate name", s.Name)
		}
		seen[s.Name] = true
	}
	for k := range cfg.Vars {
		if seen[k] {
			return fmt.Errorf("var %q conflicts with a secret entry", k)
		}
	}

	for _, cidr := range cfg.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("trusted_proxies: invalid CIDR %q: %w", cidr, err)
		}
	}

	if cfg.Vault != nil && cfg.Vault.Token.ID != "" {
		if !seen[cfg.Vault.Token.ID] {
			return fmt.Errorf("vault.token.id %q does not reference a known secret", cfg.Vault.Token.ID)
		}
	}

	return nil
}
