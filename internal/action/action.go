// Package action provides pluggable post-claim lifecycle actions.
// vault-init follows the Vault /sys/init + /auth/token/create-orphan API pattern.
// luks-recovery follows the cryptsetup luksAddKey + dmsetup table --showkeys pattern.
package action

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/hashicorp/hcl/v2"
)

// Action performs a lifecycle operation using derived secrets.
type Action interface {
	Run(ctx context.Context, logger *slog.Logger, secrets map[string]string) error
	SecretNames() []string
}

// Config holds action configuration from the enrollment config file.
type Config struct {
	Type string   `hcl:"type,label"`
	Body hcl.Body `hcl:",remain"`
}

// New creates an Action from config.
func New(cfg Config) (Action, error) {
	switch cfg.Type {
	case "vault-init":
		return newVaultInit(cfg.Body)
	case "luks-recovery":
		return newLuksRecovery(cfg.Body)
	case "consul-acl":
		return newConsulACL(cfg.Body)
	default:
		return nil, fmt.Errorf("unknown action type")
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
