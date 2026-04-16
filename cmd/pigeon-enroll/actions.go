package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/pigeon-as/pigeon-enroll/internal/action"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
)

func cmdRunActions(args []string) int {
	flags := newFlagSet("run-actions")
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	keyPathFlag := flags.String("key-path", "", "Override enrollment key path from config")
	varsPath := flags.String("vars", "", "Path to pre-derived secrets file (enroll.json); skips enrollment key")
	logLevel := flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	actionType := flags.String("type", "", "Run a specific action type (default: all)")
	flags.Parse(args)

	if *varsPath != "" {
		return runActionsFromSecrets(*configPath, *varsPath, *logLevel, *actionType)
	}

	logger, cfg, ikm, _, err := loadConfig(*configPath, *logLevel, *keyPathFlag)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}

	if len(cfg.Actions) == 0 {
		logger.Error("no actions configured")
		return 1
	}

	// Empty scope — run-actions only needs derived secrets, not certs.
	derived, _, _, _, err := secrets.Resolve(cfg.Secrets, cfg.CAs, cfg.Certs, cfg.JWTs, cfg.Vars, cfg.PersistPath, ikm, "", "")
	if err != nil {
		logger.Error("resolve secrets", "err", err)
		return 1
	}
	if derived == nil {
		derived = make(map[string]string)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := action.Run(ctx, logger, cfg.Actions, derived, *actionType); err != nil {
		logger.Error("action failed", "err", err)
		return 1
	}

	return 0
}

// runActionsFromSecrets loads pre-derived secrets from a JSON file and runs
// actions without requiring the enrollment key. Used on nodes that received
// secrets via claim (e.g. control-plane servers).
func runActionsFromSecrets(configPath, secretsPath, logLevel, actionType string) int {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		logger.Error(fmt.Sprintf("invalid log-level %q: %s", logLevel, err))
		return 1
	}
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Error("load config", "err", err)
		return 1
	}

	if len(cfg.Actions) == 0 {
		logger.Error("no actions configured")
		return 1
	}

	derived, err := secrets.LoadSecretsFile(secretsPath)
	if err != nil {
		logger.Error("load secrets", "err", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := action.Run(ctx, logger, cfg.Actions, derived, actionType); err != nil {
		logger.Error("action failed", "err", err)
		return 1
	}

	return 0
}
