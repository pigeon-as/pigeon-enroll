package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	enrollv1 "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
)

// cmdIssue implements `pigeon-enroll issue pki/<role>`.
//
// Convenience wrapper over `write pki/<role>`. Generates an Ed25519
// keypair locally, builds a CSR, calls Write, and writes the cert and
// key to disk. The private key never leaves the host.
func cmdIssue(args []string) int {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: pigeon-enroll issue [flags] <pki/role>

Generate a keypair locally, build a CSR, and write pki/<role>.

Flags:`)
		fs.PrintDefaults()
	}
	cf := registerClientFlags(fs)
	certPath := fs.String("out-cert", "", "certificate output file (required)")
	keyPath := fs.String("out-key", "", "private key output file (required)")
	cn := fs.String("cn", "", "CSR CommonName (default: empty, server selects from spec)")
	timeout := fs.Duration("timeout", 30*time.Second, "issue timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 || *certPath == "" || *keyPath == "" {
		fs.Usage()
		return 2
	}
	path := rest[0]

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		return 1
	}
	tmpl := &x509.CertificateRequest{}
	if *cn != "" {
		tmpl.Subject.CommonName = *cn
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "build csr: %v\n", err)
		return 1
	}

	conn, err := dialServer(cf.addr, cf.ca, identityBundlePath(cf.identityDir))
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		return 1
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	resp, err := enrollv1.NewEnrollClient(conn).Write(ctx, &enrollv1.Request{
		Path: path,
		Data: map[string][]byte{"csr": csrDER},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 1
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal key: %v\n", err)
		return 1
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := atomicfile.Write(*certPath, resp.Content, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *certPath, err)
		return 1
	}
	if err := atomicfile.Write(*keyPath, keyPEM, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *keyPath, err)
		return 1
	}
	return 0
}
