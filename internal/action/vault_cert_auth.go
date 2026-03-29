package action

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
)

// vaultCertAuthConfig configures the Vault cert auth method.
// This action reads the enrollment CA public cert from disk and configures
// Vault's auth/cert method with a role that trusts it.
type vaultCertAuthConfig struct {
	Addr          string   `hcl:"addr,optional"`
	TLSSkipVerify bool     `hcl:"tls_skip_verify,optional"`
	CACertFile    string   `hcl:"ca_cert_file"`
	TokenSecret   string   `hcl:"token_secret"`
	Role          string   `hcl:"role"`
	Policies      []string `hcl:"policies"`
	TokenTTL      string   `hcl:"token_ttl,optional"`
}

type vaultCertAuth struct {
	cfg vaultCertAuthConfig
}

func (v *vaultCertAuth) SecretNames() []string {
	if v.cfg.TokenSecret != "" {
		return []string{v.cfg.TokenSecret}
	}
	return nil
}

func newVaultCertAuth(body hcl.Body) (*vaultCertAuth, error) {
	var cfg vaultCertAuthConfig
	if body != nil {
		if diags := gohcl.DecodeBody(body, nil, &cfg); diags.HasErrors() {
			return nil, fmt.Errorf("parse vault-cert-auth config: %s", diags.Error())
		}
	}
	if cfg.Addr == "" {
		cfg.Addr = "https://127.0.0.1:8200"
	}
	if cfg.CACertFile == "" {
		return nil, fmt.Errorf("vault-cert-auth: ca_cert_file is required")
	}
	if cfg.TokenSecret == "" {
		return nil, fmt.Errorf("vault-cert-auth: token_secret is required")
	}
	if cfg.Role == "" {
		return nil, fmt.Errorf("vault-cert-auth: role is required")
	}
	if len(cfg.Policies) == 0 {
		return nil, fmt.Errorf("vault-cert-auth: policies is required")
	}
	if cfg.TokenTTL == "" {
		cfg.TokenTTL = "1h"
	}
	return &vaultCertAuth{cfg: cfg}, nil
}

func (v *vaultCertAuth) Run(ctx context.Context, logger *slog.Logger, secrets map[string]string) error {
	token, ok := secrets[v.cfg.TokenSecret]
	if !ok {
		return fmt.Errorf("vault-cert-auth: secret %q not found in derived secrets", v.cfg.TokenSecret)
	}

	caCertPEM, err := os.ReadFile(v.cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("vault-cert-auth: read CA cert: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	if v.cfg.TLSSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	// Enable auth/cert (idempotent: ignore "already in use").
	if err := vaultPost(ctx, client, v.cfg.Addr+"/v1/sys/auth/cert", token, map[string]string{
		"type": "cert",
	}); err != nil && !isAlreadyEnabled(err) {
		return fmt.Errorf("vault-cert-auth: enable auth/cert: %w", err)
	}

	// Create role.
	role := map[string]interface{}{
		"certificate":    string(caCertPEM),
		"token_policies": v.cfg.Policies,
		"token_ttl":      v.cfg.TokenTTL,
	}
	if err := vaultPost(ctx, client, v.cfg.Addr+"/v1/auth/cert/certs/"+v.cfg.Role, token, role); err != nil {
		return fmt.Errorf("vault-cert-auth: create role %q: %w", v.cfg.Role, err)
	}

	logger.Info("cert auth configured", "role", v.cfg.Role, "policies", v.cfg.Policies)
	return nil
}

// isAlreadyEnabled checks if a Vault error indicates the auth method is already
// mounted (e.g. "path is already in use at cert/").
func isAlreadyEnabled(err error) bool {
	return err != nil && strings.Contains(err.Error(), "path is already in use")
}

// vaultPost sends a POST request with JSON body and the given Vault token.
func vaultPost(ctx context.Context, client *http.Client, url, token string, payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", req.Method, req.URL.String(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Vault returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}
