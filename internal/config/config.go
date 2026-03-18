// Package config loads and validates the pigeon-enroll JSON configuration.
package config

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/action"
	"github.com/pigeon-as/pigeon-enroll/internal/verify"
)

// SecretSpec describes a secret to derive from the enrollment key via HKDF.
type SecretSpec struct {
	Name     string `json:"name"`
	Length   int    `json:"length"`
	Encoding string `json:"encoding"` // "base64" or "hex"
	Scope    string `json:"scope"`    // optional: only returned to claims matching this scope
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
	Actions        []action.Config   `json:"actions"`
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

	// Validate action configs: no duplicate types, reference known secrets.
	actionTypes := make(map[string]bool, len(cfg.Actions))
	for i, acfg := range cfg.Actions {
		if acfg.Type == "" {
			return fmt.Errorf("actions[%d]: type is required", i)
		}
		if actionTypes[acfg.Type] {
			return fmt.Errorf("duplicate action type %q", acfg.Type)
		}
		actionTypes[acfg.Type] = true

		a, err := action.New(acfg)
		if err != nil {
			return fmt.Errorf("action %q: %w", acfg.Type, err)
		}
		for _, name := range a.SecretNames() {
			if !seen[name] {
				return fmt.Errorf("action %q references secret %q which is not defined", acfg.Type, name)
			}
		}
	}

	return nil
}

// CheckKeyFile verifies the enrollment key file exists.
func CheckKeyFile(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("enrollment key not found at %s: %w (must be provisioned by Terraform)", path, err)
		}
		return fmt.Errorf("cannot access enrollment key at %s: %w", path, err)
	}
	return nil
}
