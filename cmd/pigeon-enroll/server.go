package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/attestor"
	"github.com/pigeon-as/pigeon-enroll/internal/bindings"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/grpcserver"
	"github.com/pigeon-as/pigeon-enroll/internal/identity"
	"github.com/pigeon-as/pigeon-enroll/internal/nonce"
	"github.com/pigeon-as/pigeon-enroll/internal/policy"
	"github.com/pigeon-as/pigeon-enroll/internal/resource"
)

func cmdServer(args []string) int {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/pigeon/enroll-server.hcl", "path to HCL config")
	keyPath := fs.String("key-path", "/etc/pigeon/enrollment-key", "path to 32-byte enrollment key (HKDF IKM)")
	noncePath := fs.String("nonce-store", "/var/lib/pigeon/enroll-nonces", "path to nonce store file")
	bindingsPath := fs.String("bindings-store", "/var/lib/pigeon/enroll-bindings", "path to EK→identity binding store")
	bootstrapCAPath := fs.String("bootstrap-ca", "", "optional PEM bundle of CAs for bootstrap_cert attestor")
	logLevel := fs.String("log-level", "info", "log level: debug, info, warn, error")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	log := newLogger(*logLevel)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}

	ikm, err := readEnrollmentKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key: %v\n", err)
		return 1
	}

	engine, err := policy.New(cfg.Policies)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy: %v\n", err)
		return 1
	}

	// Nonces must outlive any token that could still be accepted. The hmac
	// attestor accepts the current and previous window (so 2x window), and
	// we keep nonces for at least that long — otherwise a purged nonce
	// could be replayed against a still-valid token.
	nonceMax := 2 * time.Hour
	if a, ok := cfg.Attestors["hmac"]; ok && a.Window > 0 {
		nonceMax = 2 * a.Window
	}
	nonces, err := nonce.New(nonceMax, *noncePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nonce store: %v\n", err)
		return 1
	}

	binds, err := bindings.New(*bindingsPath, ikm, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bindings store: %v\n", err)
		return 1
	}

	var bootstrapPool *x509.CertPool
	if *bootstrapCAPath != "" {
		pool, err := loadCAPool(*bootstrapCAPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bootstrap CA: %v\n", err)
			return 1
		}
		bootstrapPool = pool
	}

	attestors, err := attestor.Build(cfg, nonces, bootstrapPool, ikm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "attestors: %v\n", err)
		return 1
	}

	registry, err := identity.New(cfg, engine, attestors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identity registry: %v\n", err)
		return 1
	}

	resolver, err := resource.New(cfg, engine, ikm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resource resolver: %v\n", err)
		return 1
	}

	srv, err := grpcserver.New(cfg, engine, registry, resolver, binds, ikm, grpcserver.Options{
		Logger: log,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		return 1
	}

	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen %s: %v\n", cfg.Listen, err)
		return 1
	}

	gs := srv.GRPCServer()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		log.Info("pigeon-enroll server listening", "addr", cfg.Listen, "trust_domain", cfg.TrustDomain)
		errCh <- gs.Serve(lis)
	}()

	select {
	case <-ctx.Done():
		log.Info("shutdown requested")
		gs.GracefulStop()
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "serve: %v\n", err)
			return 1
		}
	}
	return 0
}

func loadCAPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no PEM certs found")
	}
	return pool, nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
