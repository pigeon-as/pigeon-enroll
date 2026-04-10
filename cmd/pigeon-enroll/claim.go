package main

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/claim"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
)

func cmdClaim(args []string) int {
	flags := newFlagSet("claim")
	url := flags.String("url", "", "Enrollment server URL")
	tok := flags.String("token", "", "HMAC claim token")
	output := flags.String("output", "", "Path to write secrets JSON")
	scope := flags.String("scope", "", "Scope for secret filtering")
	subject := flags.String("subject", "", "Subject identity for JWT sub claim (e.g. hostname)")
	tlsBundle := flags.String("tls", "", "Path to client TLS certificate bundle (PEM)")
	insecure := flags.Bool("insecure", false, "Skip TLS certificate verification")
	skipTPM := flags.Bool("skip-tpm", false, "Skip TPM attestation (dev/testing only)")
	flags.Parse(args)

	if *url == "" || *tok == "" || *output == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll claim -url=<url> -token=<hmac> -output=<path> [-tls=<bundle>] [-scope=<scope>] [-subject=<identity>] [-insecure] [-skip-tpm]")
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

	resp, err := claim.Run(client, *url, *tok, *scope, *subject, *output, *skipTPM, slog.Default())
	if err != nil {
		fmt.Fprintf(os.Stderr, "claim failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "claimed %d secrets → %s\n", len(resp.Secrets), *output)
	return 0
}
