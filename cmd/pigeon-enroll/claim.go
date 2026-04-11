package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/pigeon-as/pigeon-enroll/internal/claimgrpc"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func cmdClaim(args []string) int {
	flags := newFlagSet("claim")
	addr := flags.String("addr", "", "Enrollment server address (host:port)")
	tok := flags.String("token", "", "HMAC claim token")
	output := flags.String("output", "", "Path to write secrets JSON")
	scope := flags.String("scope", "", "Scope for secret filtering")
	subject := flags.String("subject", "", "Subject identity for JWT sub claim (e.g. hostname)")
	tlsBundle := flags.String("tls", "", "Path to client TLS certificate bundle (PEM)")
	insecureFlag := flags.Bool("insecure", false, "Skip TLS certificate verification")
	skipTPM := flags.Bool("skip-tpm", false, "Skip TPM attestation (dev/testing only)")
	flags.Parse(args)

	if *addr == "" || *tok == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll claim -addr=<host:port> -token=<hmac> -output=<path> [-tls=<bundle>] [-scope=<scope>] [-subject=<identity>] [-insecure] [-skip-tpm]")
		return 1
	}

	var dialOpts []grpc.DialOption

	switch {
	case *tlsBundle != "":
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
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{{
				Certificate: [][]byte{cert.Raw},
				PrivateKey:  key,
			}},
			RootCAs:    caPool,
			ServerName: "pigeon-enroll",
		}
		if *insecureFlag {
			fmt.Fprintln(os.Stderr, "WARNING: TLS verification disabled — do not use in production")
			tlsCfg.InsecureSkipVerify = true
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))

	case *insecureFlag:
		fmt.Fprintln(os.Stderr, "WARNING: TLS verification disabled, no client cert — do not use in production")
		tlsCfg := &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))

	default:
		// No bundle, not insecure — use system CA pool.
		pool, err := x509.SystemCertPool()
		if err != nil {
			fmt.Fprintf(os.Stderr, "load system CA pool: %v\n", err)
			return 1
		}
		tlsCfg := &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    pool,
			ServerName: "pigeon-enroll",
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	}

	conn, err := grpc.NewClient(*addr, dialOpts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gRPC connect: %v\n", err)
		return 1
	}
	defer conn.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	resp, err := claimgrpc.Run(ctx, conn, *tok, *scope, *subject, *output, *skipTPM, slog.Default())
	if err != nil {
		fmt.Fprintf(os.Stderr, "claim failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "claimed %d secrets → %s\n", len(resp.Secrets), *output)
	return 0
}
