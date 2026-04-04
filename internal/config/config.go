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
	Name  string   `hcl:"name,label"`
	Scope []string `hcl:"scope,optional"`
}

// CertSpec describes a leaf certificate to auto-issue during claim.
// Follows the Vault PKI role pattern: issuance policy separate from CA.
// When CN is empty, the claim subject (node identity) is used as the cert CN.
type CertSpec struct {
	Name       string   `hcl:"name,label"`
	CA         string   `hcl:"ca"`                   // must reference a ca block name
	Scope      []string `hcl:"scope"`                 // who gets this cert auto-issued
	TTLRaw     string   `hcl:"ttl"`                   // e.g. "720h"
	TTL        time.Duration
	ClientAuth *bool    `hcl:"client_auth,optional"`  // default true
	ServerAuth *bool    `hcl:"server_auth,optional"`  // default false
	CN         string   `hcl:"cn,optional"`           // static common name (if empty, claim subject is used)
	DNSSANs    []string `hcl:"dns_sans,optional"`     // DNS subject alternative names
}

// JWTSpec describes a JWT to sign and include in the claim response.
// Key pair is derived from the enrollment key via HKDF (same pattern as CAs).
type JWTSpec struct {
	Name     string `hcl:"name,label"`
	Issuer   string `hcl:"issuer"`
	Audience string `hcl:"audience"`
	TTLRaw   string `hcl:"ttl"`
	TTL      time.Duration
	Scope    string `hcl:"scope"` // who gets the signed JWT (e.g. "worker")
}

// Config holds the pigeon-enroll configuration.
type Config struct {
	Listen           string `hcl:"listen,optional"`
	KeyPath          string `hcl:"key_path,optional"`
	NoncePath        string `hcl:"nonce_path,optional"`
	TokenWindow      time.Duration
	TokenWindowRaw   string `hcl:"token_window,optional"`
	ServerCertTTL    time.Duration
	ServerCertTTLRaw string            `hcl:"server_cert_ttl,optional"`
	AuditPath        string            `hcl:"audit_path,optional"`
	Vars             map[string]string `hcl:"vars,optional"`
	Secrets          []SecretSpec      `hcl:"secret,block"`
	CAs              []CASpec          `hcl:"ca,block"`
	Certs            []CertSpec        `hcl:"cert,block"`
	JWTs             []JWTSpec         `hcl:"jwt,block"`
	SecretsPath      string            `hcl:"secrets_path,optional"`
	TrustedProxies   []string          `hcl:"trusted_proxies,optional"`
	Actions          []action.Config   `hcl:"action,block"`
	RequireTPM       bool   `hcl:"require_tpm,optional"`
	EKCAPath         string `hcl:"ek_ca_path,optional"`
	EKHashPath       string `hcl:"ek_hash_path,optional"`
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
	d, err := parseDuration(cfg.TokenWindowRaw, 30*time.Minute)
	if err != nil {
		return Config{}, fmt.Errorf("parse token_window: %w", err)
	}
	cfg.TokenWindow = d

	d, err = parseDuration(cfg.ServerCertTTLRaw, 30*24*time.Hour)
	if err != nil {
		return Config{}, fmt.Errorf("parse server_cert_ttl: %w", err)
	}
	cfg.ServerCertTTL = d

	for i, c := range cfg.Certs {
		if c.TTLRaw == "" {
			return Config{}, fmt.Errorf("cert %q: ttl is required", c.Name)
		}
		d, err := time.ParseDuration(c.TTLRaw)
		if err != nil {
			return Config{}, fmt.Errorf("cert %q: parse ttl: %w", c.Name, err)
		}
		cfg.Certs[i].TTL = d
	}

	for i, j := range cfg.JWTs {
		if j.TTLRaw == "" {
			return Config{}, fmt.Errorf("jwt %q: ttl is required", j.Name)
		}
		d, err := time.ParseDuration(j.TTLRaw)
		if err != nil {
			return Config{}, fmt.Errorf("jwt %q: parse ttl: %w", j.Name, err)
		}
		cfg.JWTs[i].TTL = d
	}

	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// parseDuration parses a Go duration string, returning defaultVal if raw is empty.
func parseDuration(raw string, defaultVal time.Duration) (time.Duration, error) {
	if raw == "" {
		return defaultVal, nil
	}
	return time.ParseDuration(raw)
}

func validate(cfg Config) error {
	if cfg.TokenWindow < time.Second {
		return fmt.Errorf("token_window must be at least 1s")
	}
	if cfg.ServerCertTTL < time.Second {
		return fmt.Errorf("server_cert_ttl must be at least 1s")
	}
	if len(cfg.Vars) == 0 && len(cfg.Secrets) == 0 && len(cfg.CAs) == 0 && len(cfg.JWTs) == 0 && len(cfg.Certs) == 0 {
		return fmt.Errorf("config must define at least one of: vars, secret, ca, cert, or jwt")
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
		for _, s := range ca.Scope {
			if s == "" {
				return fmt.Errorf("ca %q: scope entries must not be empty strings", ca.Name)
			}
		}
		caNames[ca.Name] = true
	}

	certNames := make(map[string]bool, len(cfg.Certs))
	for _, c := range cfg.Certs {
		if c.Name == "" {
			return fmt.Errorf("cert: name is required")
		}
		if certNames[c.Name] {
			return fmt.Errorf("cert %q: duplicate name", c.Name)
		}
		if caNames[c.Name] {
			return fmt.Errorf("cert %q: name conflicts with a ca block", c.Name)
		}
		certNames[c.Name] = true
		if !caNames[c.CA] {
			return fmt.Errorf("cert %q: ca %q is not defined", c.Name, c.CA)
		}
		if len(c.Scope) == 0 {
			return fmt.Errorf("cert %q: scope must not be empty", c.Name)
		}
		for _, s := range c.Scope {
			if s == "" {
				return fmt.Errorf("cert %q: scope entries must not be empty strings", c.Name)
			}
		}
		for _, d := range c.DNSSANs {
			if d == "" {
				return fmt.Errorf("cert %q: dns_sans entries must not be empty strings", c.Name)
			}
		}
		if c.TTL < time.Minute {
			return fmt.Errorf("cert %q: ttl must be at least 1m", c.Name)
		}
		serverAuth := c.ServerAuth != nil && *c.ServerAuth
		clientAuth := c.ClientAuth == nil || *c.ClientAuth
		if !serverAuth && !clientAuth {
			return fmt.Errorf("cert %q: at least one of client_auth or server_auth must be true", c.Name)
		}
	}

	jwtNames := make(map[string]bool, len(cfg.JWTs))
	for _, j := range cfg.JWTs {
		if j.Name == "" {
			return fmt.Errorf("jwt: name is required")
		}
		if jwtNames[j.Name] {
			return fmt.Errorf("jwt %q: duplicate name", j.Name)
		}
		jwtNames[j.Name] = true
		if j.Issuer == "" {
			return fmt.Errorf("jwt %q: issuer is required", j.Name)
		}
		if j.Audience == "" {
			return fmt.Errorf("jwt %q: audience is required", j.Name)
		}
		if j.TTL < time.Minute {
			return fmt.Errorf("jwt %q: ttl must be at least 1m", j.Name)
		}
		if j.Scope == "" {
			return fmt.Errorf("jwt %q: scope is required", j.Name)
		}
	}

	for _, cidr := range cfg.TrustedProxies {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return fmt.Errorf("trusted_proxies: invalid CIDR %q: %w", cidr, err)
		}
	}

	// Validate EK identity config (SPIRE pattern: at least one required when TPM is required).
	if cfg.RequireTPM && cfg.EKCAPath == "" && cfg.EKHashPath == "" {
		return fmt.Errorf("require_tpm is set but neither ek_ca_path nor ek_hash_path is configured")
	}
	if cfg.EKCAPath != "" {
		info, err := os.Stat(cfg.EKCAPath)
		if err != nil {
			return fmt.Errorf("ek_ca_path: %w", err)
		}
		if !info.IsDir() {
			return fmt.Errorf("ek_ca_path must be a directory")
		}
	}
	if cfg.EKHashPath != "" {
		info, err := os.Stat(cfg.EKHashPath)
		if err != nil {
			return fmt.Errorf("ek_hash_path: %w", err)
		}
		if info.IsDir() {
			return fmt.Errorf("ek_hash_path must be a regular file")
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
