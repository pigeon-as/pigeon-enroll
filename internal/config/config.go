// Package config loads and validates the pigeon-enroll HCL configuration.
package config

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/pigeon-as/pigeon-enroll/internal/action"
	"github.com/pigeon-as/pigeon-enroll/internal/verify"
)

// SecretSpec describes a secret to derive from the enrollment key via HKDF.
type SecretSpec struct {
	Name     string `hcl:"name,label"`
	Length   int    `hcl:"length"`
	Encoding string `hcl:"encoding"` // "base64" or "hex"
	Scope    string `hcl:"scope,optional"`
}

// CASpec describes a CA certificate to derive from the enrollment key via HKDF.
type CASpec struct {
	Name string `hcl:"name,label"`
}

// Config holds the pigeon-enroll configuration.
type Config struct {
	Listen           string `hcl:"listen,optional"`
	KeyPath          string `hcl:"key_path,optional"`
	NoncePath        string `hcl:"nonce_path,optional"`
	TokenWindow      time.Duration
	TokenWindowRaw   string `hcl:"token_window,optional"`
	ClientCertTTL    time.Duration
	ClientCertTTLRaw string `hcl:"client_cert_ttl,optional"`
	ServerCertTTL    time.Duration
	ServerCertTTLRaw string            `hcl:"server_cert_ttl,optional"`
	AuditPath        string            `hcl:"audit_path,optional"`
	Verifiers        []verify.Config   `hcl:"verifier,block"`
	Vars             map[string]string `hcl:"vars,optional"`
	Secrets          []SecretSpec      `hcl:"secret,block"`
	CAs              []CASpec          `hcl:"ca,block"`
	SecretsPath      string            `hcl:"secrets_path,optional"`
	TrustedProxies   []string          `hcl:"trusted_proxies,optional"`
	Actions          []action.Config   `hcl:"action,block"`
}

// Load reads an HCL config file and returns a validated Config with defaults applied.
func Load(path string) (Config, error) {
	var cfg Config
	if err := hclsimple.DecodeFile(path, nil, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Listen == "" {
		cfg.Listen = ":8443"
	}
	if cfg.KeyPath == "" {
		cfg.KeyPath = "/etc/pigeon/enrollment-key"
	}
	if cfg.NoncePath == "" {
		cfg.NoncePath = "/var/lib/pigeon-enroll/nonces"
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
	if cfg.ClientCertTTLRaw == "" {
		cfg.ClientCertTTL = 1 * time.Hour
	} else {
		d, err := time.ParseDuration(cfg.ClientCertTTLRaw)
		if err != nil {
			return Config{}, fmt.Errorf("parse client_cert_ttl: %w", err)
		}
		cfg.ClientCertTTL = d
	}
	if cfg.ServerCertTTLRaw == "" {
		cfg.ServerCertTTL = 30 * 24 * time.Hour
	} else {
		d, err := time.ParseDuration(cfg.ServerCertTTLRaw)
		if err != nil {
			return Config{}, fmt.Errorf("parse server_cert_ttl: %w", err)
		}
		cfg.ServerCertTTL = d
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
	if cfg.ClientCertTTL < time.Second {
		return fmt.Errorf("client_cert_ttl must be at least 1s")
	}
	if cfg.ServerCertTTL < time.Second {
		return fmt.Errorf("server_cert_ttl must be at least 1s")
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

	caNames := make(map[string]bool, len(cfg.CAs))
	for _, ca := range cfg.CAs {
		if ca.Name == "" {
			return fmt.Errorf("ca: name is required")
		}
		if caNames[ca.Name] {
			return fmt.Errorf("ca %q: duplicate name", ca.Name)
		}
		caNames[ca.Name] = true
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

// CheckKeyFile verifies the enrollment key file exists and has safe permissions.
func CheckKeyFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("enrollment key not found at %s: %w (must be provisioned by Terraform)", path, err)
		}
		return fmt.Errorf("cannot access enrollment key at %s: %w", path, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("enrollment key file %s has loose permissions %04o — must be 0600", path, info.Mode().Perm())
	}
	return nil
}
