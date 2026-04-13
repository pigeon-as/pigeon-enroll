package main

import (
	"context"
	"os"
	"os/signal"

	"github.com/pigeon-as/pigeon-enroll/internal/action"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
)

func cmdRunActions(args []string) int {
	flags := newFlagSet("run-actions")
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	keyPathFlag := flags.String("key-path", "", "Override enrollment key path from config")
	logLevel := flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	actionType := flags.String("type", "", "Run a specific action type (default: all)")
	flags.Parse(args)

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
