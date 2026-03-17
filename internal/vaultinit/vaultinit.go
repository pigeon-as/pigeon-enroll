// Package vaultinit handles one-time Vault initialization.
package vaultinit

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
	"path/filepath"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
)

// initResponse is the JSON returned by PUT /v1/sys/init.
type initResponse struct {
	RootToken          string   `json:"root_token"`
	Keys               []string `json:"keys,omitempty"`
	KeysBase64         []string `json:"keys_base64,omitempty"`
	RecoveryKeys       []string `json:"recovery_keys,omitempty"`
	RecoveryKeysBase64 []string `json:"recovery_keys_base64,omitempty"`
}

// Run initializes Vault, creates a management token, and optionally
// revokes the root token. Idempotent — skips if already initialized.
func Run(ctx context.Context, logger *slog.Logger, cfg *config.VaultConfig, secrets map[string]string, outputPath string) error {
	client := &http.Client{Timeout: 10 * time.Second}
	if cfg.TLSSkipVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	initURL := cfg.Addr + "/v1/sys/init"

	logger.Info("waiting for Vault", "addr", cfg.Addr)
	initialized, err := pollUntilReachable(ctx, logger, client, initURL)
	if err != nil {
		return err
	}

	if initialized {
		logger.Info("Vault already initialized, nothing to do")
		return nil
	}

	logger.Info("initializing Vault")
	initResp, err := initVault(ctx, client, initURL, cfg)
	if err != nil {
		return err
	}

	// Keep root token in memory only; redact before writing to disk
	// when it will be revoked, so it never touches the filesystem.
	rootToken := initResp.RootToken
	if cfg.Token.ID != "" && cfg.Token.RevokeRoot {
		initResp.RootToken = "<revoked>"
	}

	respJSON, err := json.MarshalIndent(initResp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal init response: %w", err)
	}
	if err := writeAtomic(outputPath, respJSON, 0600); err != nil {
		return fmt.Errorf("write %s: %w", outputPath, err)
	}
	logger.Info("Vault initialized", "output", outputPath)

	if cfg.Token.ID != "" {
		tokenID, ok := secrets[cfg.Token.ID]
		if !ok {
			return fmt.Errorf("vault.token.id %q not found in derived secrets", cfg.Token.ID)
		}

		if err := createManagementToken(ctx, client, cfg.Addr, rootToken, tokenID, cfg.Token.Policies); err != nil {
			return err
		}
		logger.Info("management token created", "policies", cfg.Token.Policies)

		if cfg.Token.RevokeRoot {
			if err := revokeToken(ctx, client, cfg.Addr, rootToken); err != nil {
				return err
			}
			logger.Info("root token revoked")
		}
	}

	return nil
}

func initVault(ctx context.Context, client *http.Client, initURL string, cfg *config.VaultConfig) (*initResponse, error) {
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
// Uses POST /v1/auth/token/create with the id field.
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
		}

		logger.Debug("Vault not ready, retrying", "backoff", backoff, "err", err)

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

func writeAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vault-init-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
