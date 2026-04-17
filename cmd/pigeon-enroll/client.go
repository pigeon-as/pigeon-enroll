// Client-side gRPC helpers shared by register/renew/fetch/sign.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

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
//   - bundlePath, if non-empty, is a combined cert+key PEM file for the
//     client. Used on Register (bootstrap cert) and Renew/Fetch/Sign
//     (identity cert).
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

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		RootCAs:    pool,
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

// identityBundlePath returns the combined cert+key PEM file under dir.
func identityBundlePath(dir string) string { return dir + "/bundle.pem" }

func identityCertPath(dir string) string { return dir + "/cert.pem" }
func identityKeyPath(dir string) string  { return dir + "/key.pem" }
func identityCAPath(dir string) string   { return dir + "/ca.pem" }
