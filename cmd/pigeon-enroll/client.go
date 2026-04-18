// Client-side gRPC helpers shared by register/renew/fetch/sign.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// clientFlags holds the server-dial flags common to all subcommands. Values
// are overridable via env vars (Vault convention):
//
//	ENROLL_ADDR
//	ENROLL_CACERT
//	ENROLL_IDENTITY_DIR
type clientFlags struct {
	addr        string
	ca          string
	identityDir string
}

// registerClientFlags attaches the shared flags to fs with env-var defaults.
func registerClientFlags(fs *flag.FlagSet) *clientFlags {
	c := &clientFlags{}
	fs.StringVar(&c.addr, "addr", envDefault("ENROLL_ADDR", ""),
		"server address host:port (env: ENROLL_ADDR)")
	fs.StringVar(&c.ca, "ca", envDefault("ENROLL_CACERT", ""),
		"path to server CA PEM bundle (env: ENROLL_CACERT)")
	fs.StringVar(&c.identityDir, "identity-dir",
		envDefault("ENROLL_IDENTITY_DIR", "/etc/pigeon/identity"),
		"directory holding identity cert.pem / key.pem / ca.pem (env: ENROLL_IDENTITY_DIR)")
	return c
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// readValueOrFile resolves a CLI value. If the value starts with "@" the
// rest is treated as a path and its contents are returned (Vault
// convention). An empty value returns nil, nil.
func readValueOrFile(v string) ([]byte, error) {
	if v == "" {
		return nil, nil
	}
	if strings.HasPrefix(v, "@") {
		return os.ReadFile(v[1:])
	}
	return []byte(v), nil
}

// dialServer opens a gRPC connection to addr.
//
//   - caPath is the PEM bundle containing the server's CA (always required).
//     The CA's SPIFFE URI SAN (`spiffe://<trust_domain>`) drives server
//     verification — the expected leaf SPIFFE ID is derived from it, so the
//     caller never needs to know hostnames or IPs.
//   - bundlePath, if non-empty, is a combined cert+key PEM file for the
//     client. Used on Register (bootstrap cert) and Renew/Fetch/Sign
//     (identity cert).
//
// Server verification follows the SPIRE pattern: custom VerifyPeerCertificate
// builds the chain against the trust bundle and checks the leaf's
// `spiffe://<trust_domain>/pigeon-enroll/server` URI SAN. Hostname/IP
// matching is skipped — server addressing can change without touching certs.
func dialServer(addr, caPath, bundlePath string) (*grpc.ClientConn, error) {
	if addr == "" {
		return nil, errors.New("-addr is required (or set ENROLL_ADDR)")
	}
	if caPath == "" {
		return nil, errors.New("-ca is required (or set ENROLL_CACERT)")
	}

	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("no PEM certs found in %s", caPath)
	}
	trustDomain, err := trustDomainFromCAPEM(caPEM)
	if err != nil {
		return nil, fmt.Errorf("ca trust domain: %w", err)
	}
	expectedID := "spiffe://" + trustDomain + "/pigeon-enroll/server"

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		// SPIFFE verification pattern (canonical in go-spiffe / SPIRE /
		// Istio): InsecureSkipVerify disables Go's default hostname match,
		// and VerifyPeerCertificate below re-implements trust — it builds
		// the chain against the caller's CA pool, enforces NotBefore /
		// NotAfter / ExtKeyUsage via leaf.Verify, and requires the leaf
		// carry the expected SPIFFE ID as a URI SAN. This is strictly
		// stronger than default verification, not weaker: CodeQL's
		// `go/disabled-certificate-check` fires on the field name alone
		// without reasoning about the custom hook.
		InsecureSkipVerify: true, //nolint:gosec // SPIFFE, see VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			return verifySPIFFEServer(rawCerts, pool, expectedID)
		},
	}

	if bundlePath != "" {
		bundle, err := os.ReadFile(bundlePath)
		if err != nil {
			return nil, fmt.Errorf("read tls bundle: %w", err)
		}
		cert, err := tls.X509KeyPair(bundle, bundle)
		if err != nil {
			return nil, fmt.Errorf("parse tls bundle: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
}

// trustDomainFromCAPEM extracts the SPIFFE trust domain from the first CA
// cert in a PEM bundle. Matches the SPIFFE convention that CA certs carry
// `spiffe://<trust_domain>` as URI SAN.
func trustDomainFromCAPEM(caPEM []byte) (string, error) {
	for rest := caPEM; len(rest) > 0; {
		block, r := pem.Decode(rest)
		if block == nil {
			break
		}
		rest = r
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		if td, err := pki.TrustDomainFromCA(cert); err == nil {
			return td, nil
		}
	}
	return "", errors.New("no CA cert with spiffe:// URI SAN")
}

// verifySPIFFEServer is the tls.Config.VerifyPeerCertificate hook used by
// dialServer. It parses the presented chain, verifies it against `pool`
// (server-auth EKU required), and then checks the leaf carries exactly the
// expected SPIFFE ID as a URI SAN. No hostname / IP matching.
func verifySPIFFEServer(rawCerts [][]byte, pool *x509.CertPool, expectedID string) error {
	if len(rawCerts) == 0 {
		return errors.New("no server certificate presented")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, raw := range rawCerts[1:] {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return fmt.Errorf("parse chain: %w", err)
		}
		intermediates.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("verify server chain: %w", err)
	}
	for _, u := range leaf.URIs {
		if u.String() == expectedID {
			return nil
		}
	}
	return fmt.Errorf("server cert missing SPIFFE ID %q", expectedID)
}

// identityBundlePath returns the combined cert+key PEM file under dir.
func identityBundlePath(dir string) string { return dir + "/bundle.pem" }

func identityCertPath(dir string) string { return dir + "/cert.pem" }
func identityKeyPath(dir string) string  { return dir + "/key.pem" }
func identityCAPath(dir string) string   { return dir + "/ca.pem" }
