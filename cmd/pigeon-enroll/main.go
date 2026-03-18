// pigeon-enroll is a secret enrollment server and claim client for pigeon infrastructure.
//
// Server mode (control-plane):
//
//	pigeon-enroll --config=<path> [--log-level=info]
//
// Generate HMAC token (for autoscaler):
//
//	pigeon-enroll --generate-token --config=<path> [--scope=worker]
//
// Claim mode (worker):
//
//	pigeon-enroll --claim --url=<url> --token=<hmac> --output=<path> [--scope=worker] [--insecure]
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/action"
	"github.com/pigeon-as/pigeon-enroll/internal/api"
	"github.com/pigeon-as/pigeon-enroll/internal/audit"
	"github.com/pigeon-as/pigeon-enroll/internal/claim"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	"github.com/pigeon-as/pigeon-enroll/internal/verify"
)

var (
	// Shared flags.
	configPath = flag.String("config", "", "Path to JSON config file (required for server and generate-token)")
	logLevel   = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	showVer    = flag.Bool("version", false, "Print version and exit")

	// Mode flags (mutually exclusive).
	generateToken = flag.Bool("generate-token", false, "Generate an HMAC token and print to stdout")
	doClaim       = flag.Bool("claim", false, "Claim secrets from an enrollment server")
	runActions    = flag.String("run-actions", "", "Run actions from config (all if empty, or specify type)")
	runActionsSet bool

	// Shared optional flag.
	scope = flag.String("scope", "", "Scope for token generation (--generate-token) or secret filtering (--claim)")

	// Claim flags.
	claimURL      = flag.String("url", "", "Enrollment server URL (--claim)")
	claimToken    = flag.String("token", "", "HMAC claim token (--claim)")
	claimOutput   = flag.String("output", "", "Path to write secrets JSON (--claim)")
	claimInsecure = flag.Bool("insecure", false, "Skip TLS certificate verification (--claim)")
)

func main() {
	flag.Parse()
	// Detect whether --run-actions was explicitly set (distinguishes
	// "--run-actions" (all) from not provided at all).
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "run-actions" {
			runActionsSet = true
		}
	})
	os.Exit(run())
}

func run() int {
	switch {
	case *showVer:
		fmt.Println("pigeon-enroll v0.1.0")
		return 0
	case *doClaim:
		return runClaim()
	case *generateToken:
		return runGenerateToken()
	case runActionsSet:
		return doRunActions()
	default:
		return runServer()
	}
}

// loadConfig loads the JSON config, reads the enrollment key, and derives
// the HMAC signing key. Shared by --generate-token, server, and vault-init modes.
func loadConfig() (*slog.Logger, config.Config, []byte, []byte, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(*logLevel),
	}))

	if *configPath == "" {
		return logger, config.Config{}, nil, nil, fmt.Errorf("--config is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return logger, config.Config{}, nil, nil, fmt.Errorf("load config: %w", err)
	}

	if err := config.CheckKeyFile(cfg.KeyPath); err != nil {
		return logger, config.Config{}, nil, nil, err
	}

	if runtime.GOOS != "windows" {
		if info, err := os.Stat(cfg.KeyPath); err == nil && info.Mode().Perm()&0077 != 0 {
			logger.Warn("enrollment key file has loose permissions — should be 0600",
				"path", cfg.KeyPath,
				"mode", fmt.Sprintf("%04o", info.Mode().Perm()))
		}
	}

	enrollmentKeyHex, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return logger, config.Config{}, nil, nil, fmt.Errorf("read enrollment key: %w", err)
	}
	ikm, err := hex.DecodeString(strings.TrimSpace(string(enrollmentKeyHex)))
	if err != nil {
		return logger, config.Config{}, nil, nil, fmt.Errorf("decode enrollment key: %w", err)
	}

	if err := secrets.ValidateIKM(ikm); err != nil {
		return logger, config.Config{}, nil, nil, err
	}

	hmacKey, err := secrets.DeriveHMACKey(ikm)
	if err != nil {
		return logger, config.Config{}, nil, nil, err
	}

	return logger, cfg, ikm, hmacKey, nil
}

func runGenerateToken() int {
	_, cfg, _, hmacKey, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Print(token.Generate(hmacKey, time.Now(), cfg.TokenWindow, *scope))
	return 0
}

func runServer() int {
	logger, cfg, ikm, hmacKey, err := loadConfig()
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	logger.Info("enrollment key", "path", cfg.KeyPath)

	derived, err := secrets.Resolve(cfg.Secrets, cfg.Vars, cfg.SecretsPath, ikm)
	if err != nil {
		logger.Error("resolve secrets", "err", err)
		return 1
	}
	if derived != nil {
		logger.Info("secrets resolved", "count", len(derived), "path", cfg.SecretsPath)
	}

	v, err := verify.New(logger, cfg.Verifiers)
	if err != nil {
		logger.Error("create verifier", "err", err)
		return 1
	}

	al, err := audit.Open(cfg.AuditPath)
	if err != nil {
		logger.Error("open audit log", "err", err)
		return 1
	}
	defer al.Close()
	if cfg.AuditPath != "" {
		logger.Info("audit log", "path", cfg.AuditPath)
	}

	srv := api.New(logger, cfg, hmacKey, derived, v, al)

	httpServer := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutCtx)
	}()

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		httpServer.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		logger.Info("listening (TLS)", "addr", cfg.Listen)
		if err := httpServer.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey); err != http.ErrServerClosed {
			logger.Error("listen", "err", err)
			return 1
		}
	} else {
		logger.Info("listening (plain HTTP)", "addr", cfg.Listen)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("listen", "err", err)
			return 1
		}
	}

	return 0
}

func doRunActions() int {
	logger, cfg, ikm, _, err := loadConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	if len(cfg.Actions) == 0 {
		logger.Error("no actions configured")
		return 1
	}

	derived, err := secrets.Resolve(cfg.Secrets, cfg.Vars, cfg.SecretsPath, ikm)
	if err != nil {
		logger.Error("resolve secrets", "err", err)
		return 1
	}
	if derived == nil {
		derived = make(map[string]string)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := action.Run(ctx, logger, cfg.Actions, derived, *runActions); err != nil {
		logger.Error("action failed", "err", err)
		return 1
	}

	return 0
}

func runClaim() int {
	if *claimURL == "" || *claimToken == "" || *claimOutput == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll --claim --url=<url> --token=<hmac> --output=<path>")
		return 1
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if *claimInsecure {
		fmt.Fprintln(os.Stderr, "WARNING: TLS verification disabled — do not use in production")
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := claim.Run(client, *claimURL, *claimToken, *scope, *claimOutput)
	if err != nil {
		fmt.Fprintf(os.Stderr, "claim failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "claimed %d secrets → %s\n", len(resp.Secrets), *claimOutput)
	return 0
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
