package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	enrollv1 "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
)

func cmdRenew(args []string) int {
	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	cf := registerClientFlags(fs)
	timeout := fs.Duration("timeout", 30*time.Second, "renew timeout")
	rotateKey := fs.Bool("rotate-key", true, "generate a new keypair (recommended)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	conn, err := dialServer(cf.addr, cf.ca, identityBundlePath(cf.identityDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		return 1
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	client := enrollv1.NewEnrollClient(conn)

	req := &enrollv1.RenewRequest{}
	var newKeyPEM []byte
	if *rotateKey {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintf(os.Stderr, "generate keypair: %v\n", err)
			return 1
		}
		// Subject is server-controlled; CSR CN is informational only.
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "renew"},
		}, priv)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create csr: %v\n", err)
			return 1
		}
		req.CsrDer = csrDER
		newKeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(priv)})
	}

	resp, err := client.Renew(ctx, req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "renew: %v\n", err)
		return 1
	}

	keyPEM := newKeyPEM
	if keyPEM == nil {
		// Reuse existing key.
		existing, err := os.ReadFile(identityKeyPath(cf.identityDir))
		if err != nil {
			fmt.Fprintf(os.Stderr, "read existing key: %v\n", err)
			return 1
		}
		keyPEM = existing
	}

	if err := writeIdentityBundle(cf.identityDir, resp.CertPem, keyPEM, resp.CaBundlePem); err != nil {
		fmt.Fprintf(os.Stderr, "write identity: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "renewed (renew in %ds, expires in %ds)\n",
		resp.RenewAfterSeconds, resp.ExpiresInSeconds)
	return 0
}
