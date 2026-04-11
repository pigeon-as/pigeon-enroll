package main

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/pki"
)

func cmdGenerateCert(args []string) int {
	flags := newFlagSet("generate-cert")
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	fromCA := flags.String("from-ca", "", "PEM file with CA cert+key (alternative to -config)")
	cn := flags.String("cn", "", "Certificate CommonName (default: pigeon-enroll)")
	ttl := flags.String("ttl", "24h", "Certificate validity duration")
	bundlePath := flags.String("bundle", "", "Write PEM bundle (cert+key+ca) to file, or - for stdout")
	certPath := flags.String("cert", "", "Write certificate PEM to file")
	keyPath := flags.String("key", "", "Write private key PEM to file")
	caPath := flags.String("ca", "", "Write CA certificate PEM to file")
	encodeBase64 := flags.Bool("base64", false, "Base64-encode bundle output (requires -bundle)")
	var dnsNames, ipAddrs stringSlice
	flags.Var(&dnsNames, "dns", "DNS SAN (repeatable)")
	flags.Var(&ipAddrs, "ip", "IP SAN (repeatable)")
	flags.Parse(args)

	// Validate: at least one output flag required.
	if *bundlePath == "" && *certPath == "" && *keyPath == "" && *caPath == "" {
		fmt.Fprintln(os.Stderr, "error: at least one output flag required (-bundle, -cert, -key, -ca)")
		return 1
	}

	// Validate: -base64 only with -bundle.
	if *encodeBase64 && *bundlePath == "" {
		fmt.Fprintln(os.Stderr, "error: -base64 requires -bundle")
		return 1
	}

	// Validate: -ip values must be valid IPs.
	for _, ip := range ipAddrs {
		if net.ParseIP(ip) == nil {
			fmt.Fprintf(os.Stderr, "invalid IP address: %s\n", ip)
			return 1
		}
	}

	// Parse TTL.
	certTTL, err := time.ParseDuration(*ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid -ttl: %v\n", err)
		return 1
	}
	if certTTL < time.Second {
		fmt.Fprintln(os.Stderr, "error: -ttl must be at least 1s")
		return 1
	}

	// Load CA: either from explicit PEM file (-from-ca) or derived from enrollment key (-config).
	var ca *pki.CA
	if *fromCA != "" {
		caPEM, err := os.ReadFile(*fromCA)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read CA file: %v\n", err)
			return 1
		}
		ca, err = pki.LoadCA(caPEM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load CA: %v\n", err)
			return 1
		}
	} else {
		ikm, err := loadIKM(*configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			return 1
		}
		ca, err = pki.DeriveCA(ikm)
		if err != nil {
			fmt.Fprintf(os.Stderr, "derive CA: %v\n", err)
			return 1
		}
	}

	certCN := *cn
	if certCN == "" {
		certCN = "pigeon-enroll"
	}

	var hosts []string
	hosts = append(hosts, dnsNames...)
	hosts = append(hosts, ipAddrs...)

	certPEM, keyPEM, err := pki.GenerateCert(ca, certCN, hosts, certTTL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate cert: %v\n", err)
		return 1
	}

	// Write bundle.
	if *bundlePath != "" {
		var bundle []byte
		bundle = append(bundle, certPEM...)
		bundle = append(bundle, keyPEM...)
		bundle = append(bundle, ca.CertPEM...)

		if *encodeBase64 {
			bundle = []byte(base64.StdEncoding.EncodeToString(bundle))
		}

		if *bundlePath == "-" {
			if _, err := os.Stdout.Write(bundle); err != nil {
				fmt.Fprintf(os.Stderr, "write bundle: %v\n", err)
				return 1
			}
		} else {
			if err := writeSecureFile(*bundlePath, bundle); err != nil {
				fmt.Fprintf(os.Stderr, "write bundle: %v\n", err)
				return 1
			}
		}
	}

	// Write individual files.
	for _, f := range []struct {
		path string
		data []byte
	}{
		{*certPath, certPEM},
		{*keyPath, keyPEM},
		{*caPath, ca.CertPEM},
	} {
		if f.path == "" {
			continue
		}
		if err := writeSecureFile(f.path, f.data); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", f.path, err)
			return 1
		}
	}

	return 0
}
