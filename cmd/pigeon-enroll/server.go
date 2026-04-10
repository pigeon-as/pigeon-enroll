package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/api"
	"github.com/pigeon-as/pigeon-enroll/internal/audit"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
)

func cmdServer(args []string) int {
	flags := newFlagSet("server")
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	logLevel := flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	skipTLS := flags.Bool("skip-tls", false, "Allow plain HTTP (no TLS)")
	flags.Parse(args)

	logger, cfg, ikm, hmacKey, err := loadConfig(*configPath, *logLevel)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	logger.Info("enrollment key", "source", cfg.KeySource, "path", cfg.KeyPath)

	hostname, err := os.Hostname()
	if err != nil {
		logger.Error("get hostname", "err", err)
		return 1
	}

	derived, cas, _, jwtKeys, err := secrets.Resolve(cfg.Secrets, cfg.CAs, cfg.Certs, cfg.JWTs, cfg.Vars, cfg.SecretsPath, ikm, "server", hostname)
	if err != nil {
		logger.Error("resolve secrets", "err", err)
		return 1
	}
	if derived != nil {
		logger.Info("secrets resolved", "count", len(derived), "path", cfg.SecretsPath)
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

	srv, err := api.New(logger, cfg, hmacKey, derived, cas, jwtKeys, al)
	if err != nil {
		logger.Error("create api server", "err", err)
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
		srv.Close()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpServer.Shutdown(shutCtx)
	}()

	if !*skipTLS {
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
