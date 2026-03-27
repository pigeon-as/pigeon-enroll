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
//	generate-cert   Generate a client TLS certificate bundle
//	claim           Claim secrets from an enrollment server
//	render          Render HCL templates with variables
//	run-actions     Run post-claim lifecycle actions
//	version         Print version
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/action"
	"github.com/pigeon-as/pigeon-enroll/internal/api"
	"github.com/pigeon-as/pigeon-enroll/internal/audit"
	"github.com/pigeon-as/pigeon-enroll/internal/claim"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/render"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	"github.com/pigeon-as/pigeon-enroll/internal/verify"
)

const (
	version           = "0.1.0"
	defaultConfigPath = "/etc/pigeon/enroll.hcl"
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
	case "generate-cert":
		os.Exit(cmdGenerateCert(args))
	case "claim":
		os.Exit(cmdClaim(args))
	case "render":
		os.Exit(cmdRender(args))
	case "run-actions":
		os.Exit(cmdRunActions(args))
	case "derive":
		os.Exit(cmdDerive(args))
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
  generate-cert   Generate a client TLS certificate bundle (PEM)
  claim           Claim secrets from an enrollment server
  render          Render HCL templates with variables
  run-actions     Run post-claim lifecycle actions
  derive          Derive a named secret from the enrollment key
  version         Print version`)
}

// loadConfig loads the HCL config, reads the enrollment key, and derives
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
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	logLevel := flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	skipTLS := flags.Bool("skip-tls", false, "Allow plain HTTP (no TLS)")
	flags.Parse(args)

	logger, cfg, ikm, hmacKey, err := loadConfig(*configPath, *logLevel)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	logger.Info("enrollment key", "path", cfg.KeyPath)

	derived, cas, err := secrets.Resolve(cfg.Secrets, cfg.CAs, cfg.Vars, cfg.SecretsPath, ikm)
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

	srv, err := api.New(logger, cfg, hmacKey, derived, cas, v, al)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}

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

	if !*skipTLS {
		// Auto-TLS with mTLS: derive CA, rotate server cert automatically.
		ca, err := pki.DeriveCA(ikm)
		if err != nil {
			logger.Error("derive CA", "err", err)
			return 1
		}
		caPool := x509.NewCertPool()
		caPool.AddCert(ca.Cert)
		rotator := pki.NewCertRotator(ca, []string{"pigeon-enroll"}, cfg.ServerCertTTL)
		httpServer.TLSConfig = &tls.Config{
			MinVersion:     tls.VersionTLS12,
			GetCertificate: rotator.GetCertificate,
			ClientAuth:     tls.RequireAndVerifyClientCert,
			ClientCAs:      caPool,
		}
		logger.Info("listening (mTLS)", "addr", cfg.Listen, "server_cert_ttl", cfg.ServerCertTTL)
		if err := httpServer.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			logger.Error("listen", "err", err)
			return 1
		}
	} else {
		logger.Warn("listening without TLS (-skip-tls)", "addr", cfg.Listen)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			logger.Error("listen", "err", err)
			return 1
		}
	}

	return 0
}

func cmdGenerateToken(args []string) int {
	flags := flag.NewFlagSet("generate-token", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
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

func cmdGenerateCert(args []string) int {
	flags := flag.NewFlagSet("generate-cert", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	output := flags.String("output", "", "Write PEM bundle to file (0600) instead of stdout")
	encodeBase64 := flags.Bool("base64", false, "Base64-encode the output (for embedding in env vars)")
	flags.Parse(args)

	_, cfg, ikm, _, err := loadConfig(*configPath, "error")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	ca, err := pki.DeriveCA(ikm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive CA: %v\n", err)
		return 1
	}

	bundle, err := pki.GenerateClientCert(ca, cfg.ClientCertTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate client cert: %v\n", err)
		return 1
	}

	var data []byte
	if *encodeBase64 {
		data = []byte(base64.StdEncoding.EncodeToString(bundle))
	} else {
		data = bundle
	}

	if *output != "" {
		if err := os.WriteFile(*output, data, 0600); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			return 1
		}
		return 0
	}

	os.Stdout.Write(data)
	return 0
}

func cmdClaim(args []string) int {
	flags := flag.NewFlagSet("claim", flag.ExitOnError)
	url := flags.String("url", "", "Enrollment server URL")
	tok := flags.String("token", "", "HMAC claim token")
	output := flags.String("output", "", "Path to write secrets JSON")
	scope := flags.String("scope", "", "Scope for secret filtering")
	tlsBundle := flags.String("tls", "", "Path to client TLS certificate bundle (PEM)")
	insecure := flags.Bool("insecure", false, "Skip TLS certificate verification")
	flags.Parse(args)

	if *url == "" || *tok == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll claim -url=<url> -token=<hmac> -output=<path> [-tls=<bundle>] [-scope=<scope>] [-insecure]")
		return 1
	}

	client := &http.Client{Timeout: 30 * time.Second}
	if *tlsBundle != "" {
		bundlePEM, err := os.ReadFile(*tlsBundle)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read TLS bundle: %v\n", err)
			return 1
		}
		key, cert, caPool, err := pki.LoadClientBundle(bundlePEM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load TLS bundle: %v\n", err)
			return 1
		}
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				Certificates: []tls.Certificate{{
					Certificate: [][]byte{cert.Raw},
					PrivateKey:  key,
				}},
				RootCAs:    caPool,
				ServerName: "pigeon-enroll",
			},
		}
	} else if *insecure {
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

func cmdRender(args []string) int {
	flags := flag.NewFlagSet("render", flag.ExitOnError)
	configPath := flags.String("config", "", "Path to render HCL config")
	varsPath := flags.String("vars", "/encrypted/pigeon/secrets.json", "Path to template variables JSON")
	flags.Parse(args)

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll render -config=<path> [-vars=<path>]")
		return 1
	}

	cfg, err := render.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load render config: %v\n", err)
		return 1
	}

	vars, err := render.ParseVarsFile(*varsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse vars: %v\n", err)
		return 1
	}

	for _, tpl := range cfg.Templates {
		perms := tpl.Perms
		if perms == "" {
			perms = "0640"
		}
		perm, err := parsePerms(perms)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid perms for %s: %v\n", tpl.Source, err)
			return 1
		}

		rendered, err := render.File(tpl.Source, vars)
		if err != nil {
			fmt.Fprintf(os.Stderr, "render %s: %v\n", tpl.Source, err)
			return 1
		}

		uid, err := render.LookupUser(tpl.User)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", tpl.Destination, err)
			return 1
		}
		gid, err := render.LookupGroup(tpl.Group)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", tpl.Destination, err)
			return 1
		}

		if err := render.WriteAtomic(tpl.Destination, rendered, perm, uid, gid); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", tpl.Destination, err)
			return 1
		}

		fmt.Fprintf(os.Stderr, "rendered %s → %s\n", tpl.Source, tpl.Destination)
	}

	return 0
}

func parsePerms(s string) (os.FileMode, error) {
	p, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parse perms %q: %w", s, err)
	}
	if p > 0o777 {
		return 0, fmt.Errorf("invalid perms %q: must be between 0000 and 0777", s)
	}
	return os.FileMode(p), nil
}

func cmdRunActions(args []string) int {
	flags := flag.NewFlagSet("run-actions", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
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

	derived, _, err := secrets.Resolve(cfg.Secrets, cfg.CAs, cfg.Vars, cfg.SecretsPath, ikm)
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

func cmdDerive(args []string) int {
	flags := flag.NewFlagSet("derive", flag.ExitOnError)
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	name := flags.String("name", "", "Name of the secret to derive")
	flags.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll derive -name=<secret> [-config=<path>]")
		return 1
	}

	_, cfg, ikm, _, err := loadConfig(*configPath, "error")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	for _, s := range cfg.Secrets {
		if s.Name == *name {
			derived, _, derr := secrets.Resolve([]config.SecretSpec{s}, nil, nil, "", ikm)
			if derr != nil {
				fmt.Fprintf(os.Stderr, "derive: %v\n", derr)
				return 1
			}
			fmt.Print(derived[s.Name])
			return 0
		}
	}

	fmt.Fprintf(os.Stderr, "secret %q not found in config\n", *name)
	return 1
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
