// Package action provides pluggable post-claim lifecycle actions.
package action

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Action performs a lifecycle operation using derived secrets.
type Action interface {
	Run(ctx context.Context, logger *slog.Logger, secrets map[string]string) error
}

// Config holds action configuration from the enrollment config file.
type Config struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

// New creates an Action from config.
func New(cfg Config) (Action, error) {
	switch cfg.Type {
	case "vault-init":
		return newVaultInit(cfg.Config)
	default:
		return nil, fmt.Errorf("unknown action type: %q", cfg.Type)
	}
}

// Run finds the action matching the given type and runs it.
// If actionType is empty, all actions are run in config order.
func Run(ctx context.Context, logger *slog.Logger, cfgs []Config, secrets map[string]string, actionType string) error {
	if actionType == "" {
		for _, cfg := range cfgs {
			if err := runOne(ctx, logger, cfg, secrets); err != nil {
				return err
			}
		}
		return nil
	}

	for _, cfg := range cfgs {
		if cfg.Type == actionType {
			return runOne(ctx, logger, cfg, secrets)
		}
	}
	return fmt.Errorf("action %q not found in config", actionType)
}

func runOne(ctx context.Context, logger *slog.Logger, cfg Config, secrets map[string]string) error {
	a, err := New(cfg)
	if err != nil {
		return fmt.Errorf("action %q: %w", cfg.Type, err)
	}
	logger.Info("running action", "type", cfg.Type)
	if err := a.Run(ctx, logger, secrets); err != nil {
		return fmt.Errorf("action %q: %w", cfg.Type, err)
	}
	return nil
}

// SecretNames returns the set of secret names referenced by action configs.
// Used by config validation to check that referenced secrets exist.
func SecretNames(cfgs []Config) (map[string]bool, error) {
	names := make(map[string]bool)
	for _, cfg := range cfgs {
		switch cfg.Type {
		case "vault-init":
			var vc vaultInitConfig
			if err := json.Unmarshal(cfg.Config, &vc); err != nil {
				return nil, fmt.Errorf("parse vault-init config: %w", err)
			}
			if vc.Token.ID != "" {
				names[vc.Token.ID] = true
			}
		}
	}
	return names, nil
}
