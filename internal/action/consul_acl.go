package action

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
)

// consulACLConfig holds consul-acl action configuration.
type consulACLConfig struct {
	// Addr is the Consul HTTP API address (default: "https://127.0.0.1:8501").
	Addr string `hcl:"addr,optional"`
	// CACert is the path to the CA certificate for Consul TLS verification.
	CACert string `hcl:"ca_cert,optional"`
	// TLSSkipVerify disables TLS certificate verification.
	TLSSkipVerify bool `hcl:"tls_skip_verify,optional"`
	// ManagementToken references a secret name whose value is the Consul management token.
	ManagementToken string `hcl:"management_token"`
	// AgentToken references a secret name whose value becomes the agent token SecretID.
	AgentToken string `hcl:"agent_token"`
	// AgentTokenDescription is the description for the agent token in Consul.
	AgentTokenDescription string `hcl:"agent_token_description,optional"`
}

type consulACL struct {
	cfg consulACLConfig
}

func newConsulACL(body hcl.Body) (*consulACL, error) {
	var cfg consulACLConfig
	if body != nil {
		if diags := gohcl.DecodeBody(body, nil, &cfg); diags.HasErrors() {
			return nil, fmt.Errorf("parse consul-acl config: %s", diags.Error())
		}
	}
	if cfg.Addr == "" {
		cfg.Addr = "https://127.0.0.1:8501"
	}
	if cfg.ManagementToken == "" {
		return nil, fmt.Errorf("consul-acl: management_token is required")
	}
	if cfg.AgentToken == "" {
		return nil, fmt.Errorf("consul-acl: agent_token is required")
	}
	if cfg.AgentTokenDescription == "" {
		cfg.AgentTokenDescription = "Nomad agent token (HKDF-derived)"
	}
	return &consulACL{cfg: cfg}, nil
}

func (c *consulACL) SecretNames() []string {
	return []string{c.cfg.ManagementToken, c.cfg.AgentToken}
}

func (c *consulACL) Run(ctx context.Context, logger *slog.Logger, secrets map[string]string) error {
	mgmtToken, ok := secrets[c.cfg.ManagementToken]
	if !ok {
		return fmt.Errorf("consul-acl: management_token %q not found in derived secrets", c.cfg.ManagementToken)
	}
	agentTokenID, ok := secrets[c.cfg.AgentToken]
	if !ok {
		return fmt.Errorf("consul-acl: agent_token %q not found in derived secrets", c.cfg.AgentToken)
	}

	client, err := c.httpClient()
	if err != nil {
		return err
	}

	// Check if the token already exists by reading it.
	exists, err := c.tokenExists(ctx, client, mgmtToken, agentTokenID)
	if err != nil {
		return err
	}
	if exists {
		logger.Info("consul agent token already exists, skipping")
		return nil
	}

	// Create the policy.
	policyID, err := c.ensurePolicy(ctx, logger, client, mgmtToken)
	if err != nil {
		return err
	}

	// Create the token with the HKDF-derived SecretID.
	if err := c.createToken(ctx, client, mgmtToken, agentTokenID, policyID); err != nil {
		return err
	}
	logger.Info("consul agent token registered")
	return nil
}

func (c *consulACL) httpClient() (*http.Client, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	if c.cfg.CACert != "" {
		caCert, err := os.ReadFile(c.cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("read ca_cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("ca_cert: no valid certificates found")
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.RootCAs = pool
		client.Transport = transport
	} else if c.cfg.TLSSkipVerify {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{}
		}
		transport.TLSClientConfig.InsecureSkipVerify = true
		client.Transport = transport
	}
	return client, nil
}

// tokenExists checks if a token with the given SecretID already exists.
func (c *consulACL) tokenExists(ctx context.Context, client *http.Client, mgmtToken, secretID string) (bool, error) {
	// Consul API: read own token via X-Consul-Token header with the agent token itself.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Addr+"/v1/acl/token/self", nil)
	if err != nil {
		return false, fmt.Errorf("create token self request: %w", err)
	}
	req.Header.Set("X-Consul-Token", secretID)

	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("check token: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusForbidden:
		// Token doesn't exist — 403 means the token is not valid.
		return false, nil
	default:
		return false, fmt.Errorf("check token: unexpected status %d", resp.StatusCode)
	}
}

// ensurePolicy creates the nomad-agent policy if it doesn't exist.
func (c *consulACL) ensurePolicy(ctx context.Context, logger *slog.Logger, client *http.Client, mgmtToken string) (string, error) {
	const policyName = "nomad-agent"

	// Check if policy already exists.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.Addr+"/v1/acl/policy/name/"+policyName, nil)
	if err != nil {
		return "", fmt.Errorf("create policy read request: %w", err)
	}
	req.Header.Set("X-Consul-Token", mgmtToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("read policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var existing struct {
			ID string `json:"ID"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&existing); err != nil {
			return "", fmt.Errorf("decode policy response: %w", err)
		}
		logger.Info("consul nomad-agent policy already exists", "id", existing.ID)
		return existing.ID, nil
	}
	io.Copy(io.Discard, resp.Body)

	// Create the policy.
	// Nomad clients need: agent read, node write, service write (for deregistration).
	// Ref: https://developer.hashicorp.com/nomad/docs/integrations/consul/acl#nomad-agents
	policy := map[string]string{
		"Name":        policyName,
		"Description": "Nomad agent token policy (node/service write, agent read)",
		"Rules": `agent_prefix "" { policy = "read" }
node_prefix "" { policy = "write" }
service_prefix "" { policy = "write" }`,
	}
	body, err := json.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("marshal policy: %w", err)
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodPut, c.cfg.Addr+"/v1/acl/policy", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create policy request: %w", err)
	}
	req.Header.Set("X-Consul-Token", mgmtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err = client.Do(req)
	if err != nil {
		return "", fmt.Errorf("create policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create policy: status %d: %s", resp.StatusCode, respBody)
	}

	var created struct {
		ID string `json:"ID"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		return "", fmt.Errorf("decode policy response: %w", err)
	}
	logger.Info("consul nomad-agent policy created", "id", created.ID)
	return created.ID, nil
}

// createToken creates a Consul ACL token with the HKDF-derived SecretID.
func (c *consulACL) createToken(ctx context.Context, client *http.Client, mgmtToken, secretID, policyID string) error {
	token := map[string]any{
		"SecretID":    secretID,
		"Description": c.cfg.AgentTokenDescription,
		"Policies":    []map[string]string{{"ID": policyID}},
		"Local":       false,
	}
	body, err := json.Marshal(token)
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.cfg.Addr+"/v1/acl/token", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("X-Consul-Token", mgmtToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("create token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create token: status %d: %s", resp.StatusCode, respBody)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}
