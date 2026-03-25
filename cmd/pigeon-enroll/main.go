// pigeon-enroll is a secret enrollment server and claim client for pigeon infrastructure.
//
// Usage:
//
//	pigeon-enroll <command> [options]
//
// Commands:
//
//	server          Run the enrollment server
//	generate-token  Generate an HMAC claim token
//	claim           Claim secrets from an enrollment server
//	run-actions     Run post-claim lifecycle actions
//	version         Print version
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

const (
	version           = "0.1.0"
	defaultConfigPath = "/etc/pigeon/enroll.json"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "help", "-h", "--help":
		printUsage()
	case "server":
		os.Exit(cmdServer(args))
	case "generate-token":
		os.Exit(cmdGenerateToken(args))
	case "claim":
		os.Exit(cmdClaim(args))
	case "run-actions":
		os.Exit(cmdRunActions(args))
	case "version":
		fmt.Printf("pigeon-enroll v%s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: pigeon-enroll <command> [options]

Commands:
  server          Run the enrollment server
  generate-token  Generate an HMAC claim token
  claim           Claim secrets from an enrollment server
  run-actions     Run post-claim lifecycle actions
  version         Print version`)
}

// loadConfig loads the JSON config, reads the enrollment key, and derives
// the HMAC signing key.
func loadConfig(configPath, logLevel string) (*slog.Logger, config.Config, []byte, []byte, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: parseLevel(logLevel),
	}))

	cfg, err := config.Load(configPath)
	if err != nil {
		return logger, config.Config{}, nil, nil, fmt.Errorf("load config: %w", err)
	}

	if err := config.CheckKeyFile(cfg.KeyPath); err != nil {
		return logger, config.Config{}, nil, nil, err
	}

	if runtime.GOOS != "windows" {
		if info, err := os.Stat(cfg.KeyPath); err == nil && info.Mode().Perm()&0077 != 0 {
			return logger, config.Config{}, nil, nil, fmt.Errorf(
				"enrollment key file %s has loose permissions %04o — must be 0600",
				cfg.KeyPath, info.Mode().Perm())
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

func cmdServer(args []string) int {
	flags := flag.NewFlagSet("server", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "Path to JSON config file")
	logLevel := flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	insecure := flags.Bool("insecure", false, "Allow plain HTTP (no TLS)")
	flags.Parse(args)

	logger, cfg, ikm, hmacKey, err := loadConfig(*configPath, *logLevel)
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
	} else if cfg.TLSCert != "" || cfg.TLSKey != "" {
		logger.Error("both tls_cert and tls_key must be set (only one provided)")
		return 1
	} else {
		if !*insecure {
			logger.Error("TLS not configured — use -insecure to allow plain HTTP")
			return 1
		}
		logger.Warn("listening without TLS (-insecure)", "addr", cfg.Listen)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("listen", "err", err)
			return 1
		}
	}

	return 0
}

func cmdGenerateToken(args []string) int {
	flags := flag.NewFlagSet("generate-token", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "Path to JSON config file")
	scope := flags.String("scope", "", "Scope for token generation")
	flags.Parse(args)

	_, cfg, _, hmacKey, err := loadConfig(*configPath, "info")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Print(token.Generate(hmacKey, time.Now(), cfg.TokenWindow, *scope))
	return 0
}

func cmdClaim(args []string) int {
	flags := flag.NewFlagSet("claim", flag.ExitOnError)
	url := flags.String("url", "", "Enrollment server URL")
	tok := flags.String("token", "", "HMAC claim token")
	output := flags.String("output", "", "Path to write secrets JSON")
	scope := flags.String("scope", "", "Scope for secret filtering")
	insecure := flags.Bool("insecure", false, "Skip TLS certificate verification")
	flags.Parse(args)

	if *url == "" || *tok == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll claim -url=<url> -token=<hmac> -output=<path>")
		return 1
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if *insecure {
		fmt.Fprintln(os.Stderr, "WARNING: TLS verification disabled — do not use in production")
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}

	resp, err := claim.Run(client, *url, *tok, *scope, *output)
	if err != nil {
		fmt.Fprintf(os.Stderr, "claim failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "claimed %d secrets → %s\n", len(resp.Secrets), *output)
	return 0
}

func cmdRunActions(args []string) int {
	flags := flag.NewFlagSet("run-actions", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "Path to JSON config file")
	logLevel := flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	actionType := flags.String("type", "", "Run a specific action type (default: all)")
	flags.Parse(args)

	logger, cfg, ikm, _, err := loadConfig(*configPath, *logLevel)
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

	if err := action.Run(ctx, logger, cfg.Actions, derived, *actionType); err != nil {
		logger.Error("action failed", "err", err)
		return 1
	}

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
