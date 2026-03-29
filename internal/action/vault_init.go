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
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
)

// vaultInitConfig holds vault-init action configuration.
type vaultInitConfig struct {
	Addr              string             `hcl:"addr,optional"`
	TLSSkipVerify     bool               `hcl:"tls_skip_verify,optional"`
	SecretShares      int                `hcl:"secret_shares,optional"`
	SecretThreshold   int                `hcl:"secret_threshold,optional"`
	RecoveryShares    int                `hcl:"recovery_shares,optional"`
	RecoveryThreshold int                `hcl:"recovery_threshold,optional"`
	Output            string             `hcl:"output,optional"`
	Token             []vaultTokenConfig `hcl:"token,block"`
}

// vaultTokenConfig holds the management token configuration.
type vaultTokenConfig struct {
	// ID references a secret name. The derived secret value becomes the
	// custom token ID passed to vault token create.
	ID string `hcl:"id"`
	// Policies to attach to the management token.
	Policies []string `hcl:"policies,optional"`
	// RevokeRoot revokes the initial root token after the management token is created.
	RevokeRoot bool `hcl:"revoke_root,optional"`
}

type vaultInit struct {
	cfg vaultInitConfig
}

func (v *vaultInit) SecretNames() []string {
	if len(v.cfg.Token) > 0 && v.cfg.Token[0].ID != "" {
		return []string{v.cfg.Token[0].ID}
	}
	return nil
}

func newVaultInit(body hcl.Body) (*vaultInit, error) {
	var cfg vaultInitConfig
	if body != nil {
		if diags := gohcl.DecodeBody(body, nil, &cfg); diags.HasErrors() {
			return nil, fmt.Errorf("parse vault-init config: %s", diags.Error())
		}
	}
	// Defaults.
	if cfg.Addr == "" {
		cfg.Addr = "https://127.0.0.1:8200"
	}
	if cfg.SecretShares == 0 {
		cfg.SecretShares = 1
	}
	if cfg.SecretThreshold == 0 {
		cfg.SecretThreshold = 1
	}
	if cfg.Output == "" {
		cfg.Output = "/encrypted/vault/init.json"
	}
	if len(cfg.Token) > 1 {
		return nil, fmt.Errorf("vault-init: at most one token block allowed, got %d", len(cfg.Token))
	}
	if len(cfg.Token) > 0 && len(cfg.Token[0].Policies) == 0 && cfg.Token[0].ID != "" {
		cfg.Token[0].Policies = []string{"root"}
	}
	return &vaultInit{cfg: cfg}, nil
}

// initResponse is the JSON returned by PUT /v1/sys/init.
type initResponse struct {
	RootToken          string   `json:"root_token"`
	Keys               []string `json:"keys,omitempty"`
	KeysBase64         []string `json:"keys_base64,omitempty"`
	RecoveryKeys       []string `json:"recovery_keys,omitempty"`
	RecoveryKeysBase64 []string `json:"recovery_keys_base64,omitempty"`
}

func (v *vaultInit) Run(ctx context.Context, logger *slog.Logger, secrets map[string]string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	if v.cfg.TLSSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	initURL := v.cfg.Addr + "/v1/sys/init"

	logger.Info("waiting for Vault", "addr", v.cfg.Addr)
	initialized, err := pollUntilReachable(ctx, logger, client, initURL)
	if err != nil {
		return err
	}

	if initialized {
		logger.Info("Vault already initialized, skipping", "addr", v.cfg.Addr)
		return nil
	}

	// Resolve management token ID after confirming Vault needs initialization.
	var tokenID string
	if len(v.cfg.Token) > 0 && v.cfg.Token[0].ID != "" {
		var ok bool
		tokenID, ok = secrets[v.cfg.Token[0].ID]
		if !ok {
			return fmt.Errorf("vault-init: token.id %q not found in derived secrets", v.cfg.Token[0].ID)
		}
	}

	logger.Info("initializing Vault")
	initResp, err := initVault(ctx, client, initURL, &v.cfg)
	if err != nil {
		return err
	}

	rootToken := initResp.RootToken

	var managementTokenCreated bool
	if len(v.cfg.Token) > 0 && v.cfg.Token[0].ID != "" {
		if err := createManagementToken(ctx, client, v.cfg.Addr, rootToken, tokenID, v.cfg.Token[0].Policies); err != nil {
			return err
		}
		logger.Info("management token created", "policies", v.cfg.Token[0].Policies)
		managementTokenCreated = true
	}

	if len(v.cfg.Token) > 0 && v.cfg.Token[0].RevokeRoot {
		if !managementTokenCreated {
			return fmt.Errorf("vault-init: revoke_root requires a management token (set token.id)")
		}
		if err := revokeToken(ctx, client, v.cfg.Addr, rootToken); err != nil {
			return err
		}
		logger.Info("root token revoked")
		initResp.RootToken = "<revoked>"
	}

	respJSON, err := json.MarshalIndent(initResp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal init response: %w", err)
	}
	if err := atomicfile.Write(v.cfg.Output, respJSON, 0600); err != nil {
		return fmt.Errorf("write %s: %w", v.cfg.Output, err)
	}
	logger.Info("Vault initialized", "output", v.cfg.Output)

	return nil
}

func initVault(ctx context.Context, client *http.Client, initURL string, cfg *vaultInitConfig) (*initResponse, error) {
	initReq := map[string]int{
		"secret_shares":    cfg.SecretShares,
		"secret_threshold": cfg.SecretThreshold,
	}
	if cfg.RecoveryShares > 0 {
		initReq["recovery_shares"] = cfg.RecoveryShares
		initReq["recovery_threshold"] = cfg.RecoveryThreshold
	}
	body, err := json.Marshal(initReq)
	if err != nil {
		return nil, fmt.Errorf("marshal init request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, initURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create init request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("PUT /v1/sys/init: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read init response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("init returned %d: %s", resp.StatusCode, respBody)
	}

	var initResp initResponse
	if err := json.Unmarshal(respBody, &initResp); err != nil {
		return nil, fmt.Errorf("decode init response: %w", err)
	}
	if initResp.RootToken == "" {
		return nil, fmt.Errorf("init response missing root_token")
	}

	return &initResp, nil
}

// createManagementToken creates a token with a known ID using the root token.
func createManagementToken(ctx context.Context, client *http.Client, vaultAddr, rootToken, tokenID string, policies []string) error {
	payload := map[string]interface{}{
		"id":           tokenID,
		"policies":     policies,
		"no_parent":    true,
		"display_name": "pigeon-management",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal token create request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, vaultAddr+"/v1/auth/token/create", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Vault-Token", rootToken)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /v1/auth/token/create: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token create returned %d: %s", resp.StatusCode, respBody)
	}

	return nil
}

// revokeToken revokes the given token using POST /v1/auth/token/revoke-self.
func revokeToken(ctx context.Context, client *http.Client, vaultAddr, token string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, vaultAddr+"/v1/auth/token/revoke-self", nil)
	if err != nil {
		return fmt.Errorf("create revoke request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /v1/auth/token/revoke-self: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke-self returned %d: %s", resp.StatusCode, respBody)
	}

	return nil
}

// initStatus is the JSON returned by GET /v1/sys/init.
type initStatus struct {
	Initialized bool `json:"initialized"`
}

// pollUntilReachable retries GET /v1/sys/init with backoff until Vault responds.
func pollUntilReachable(ctx context.Context, logger *slog.Logger, client *http.Client, url string) (bool, error) {
	backoff := time.Second
	const maxBackoff = 30 * time.Second

	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return false, fmt.Errorf("create request: %w", err)
		}

		resp, err := client.Do(req)
		if err == nil {
			var status initStatus
			decodeErr := json.NewDecoder(resp.Body).Decode(&status)
			resp.Body.Close()
			if decodeErr == nil {
				return status.Initialized, nil
			}
		} else {
			logger.Debug("Vault not ready, retrying", "backoff", backoff, "err", err)
		}

		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(backoff):
		}

		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}
