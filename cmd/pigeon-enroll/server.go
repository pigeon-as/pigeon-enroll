package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/pigeon-as/pigeon-enroll/internal/grpcserver"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	pb "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func cmdServer(args []string) int {
	flags := newFlagSet("server")
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	keyPathFlag := flags.String("key-path", "", "Override enrollment key path from config")
	logLevel := flags.String("log-level", "info", "Log level (debug, info, warn, error)")
	flags.Parse(args)

	logger, cfg, ikm, hmacKey, err := loadConfig(*configPath, *logLevel, *keyPathFlag)
	if err != nil {
		logger.Error(err.Error())
		return 1
	}
	logger.Info("enrollment key loaded", "path", cfg.KeyPath)

	hostname, err := os.Hostname()
	if err != nil {
		logger.Error("get hostname", "err", err)
		return 1
	}

	derived, cas, _, jwtKeys, err := secrets.Resolve(cfg.Secrets, cfg.CAs, cfg.Certs, cfg.JWTs, cfg.Vars, cfg.PersistPath, ikm, "server", hostname)
	if err != nil {
		logger.Error("resolve secrets", "err", err)
		return 1
	}
	if derived != nil {
		logger.Info("secrets resolved", "count", len(derived), "path", cfg.PersistPath)
	}

	srv, err := grpcserver.New(logger, cfg, hmacKey, derived, cas, jwtKeys)
	if err != nil {
		logger.Error("create grpc server", "err", err)
		return 1
	}

	// Derive mTLS credentials from enrollment key.
	ca, err := pki.DeriveCA(ikm)
	if err != nil {
		logger.Error("derive CA", "err", err)
		return 1
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)
	rotator := pki.NewCertRotator(ca, []string{"pigeon-enroll"}, cfg.ServerCertTTL)

	tlsCfg := &tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: rotator.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
	}

	grpcSrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	pb.RegisterEnrollmentServiceServer(grpcSrv, srv)

	lis, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		logger.Error("listen", "err", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		logger.Info("shutting down")
		grpcSrv.GracefulStop()
	}()

	logger.Info("listening (gRPC mTLS)", "addr", cfg.Listen, "server_cert_ttl", cfg.ServerCertTTL)
	if err := grpcSrv.Serve(lis); err != nil {
		logger.Error("serve", "err", err)
		return 1
	}

	return 0
}
