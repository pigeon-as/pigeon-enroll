package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
)

// cmdGenerateToken mints an HMAC bootstrap token for the given identity.
//
// Modelled on SPIRE's `spire-server token generate -spiffeID <id>`: the
// command runs on a host that holds the signing material, emits a
// short-lived bearer, and expects it to be shipped out-of-band (ConfigDrive
// for a new worker, SSH heredoc pipe for the control-plane's own bootstrap).
//
// No gRPC round-trip — same HKDF + HMAC derivation the running server would
// use to verify the token, computed locally.
func cmdGenerateToken(args []string) int {
	fs := flag.NewFlagSet("generate-token", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: pigeon-enroll generate-token [flags]

Mint an HMAC bootstrap token for the given identity, using the local
enrollment key. Prints the token to stdout.

Flags:`)
		fs.PrintDefaults()
	}
	configPath := fs.String("config", "/etc/pigeon/enroll-server.hcl", "path to HCL config")
	keyPath := fs.String("key-path", "", "enrollment key file, or - for stdin (required)")
	identityName := fs.String("identity", "", "identity name to scope the token to (required)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *keyPath == "" || *identityName == "" {
		fs.Usage()
		return 2
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}

	id, ok := cfg.Identities[*identityName]
	if !ok {
		fmt.Fprintf(os.Stderr, "identity %q not found in %s\n", *identityName, *configPath)
		return 1
	}
	hmacAt, ok := cfg.Attestors["hmac"]
	if !ok {
		fmt.Fprintln(os.Stderr, "hmac attestor not configured")
		return 1
	}
	accepted := false
	for _, k := range id.Attestors {
		if k == "hmac" {
			accepted = true
			break
		}
	}
	if !accepted {
		fmt.Fprintf(os.Stderr, "identity %q does not accept the hmac attestor\n", *identityName)
		return 1
	}

	ikm, err := readEnrollmentKey(*keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key: %v\n", err)
		return 1
	}

	fmt.Println(token.Generate(ikm, time.Now(), hmacAt.Window, *identityName))
	return 0
}

// readEnrollmentKey reads 32 raw bytes from path. "-" means stdin.
func readEnrollmentKey(path string) ([]byte, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	// Match server.go: trim trailing newlines (systemd-creds decrypt can add one).
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
		data = data[:len(data)-1]
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("expected 32 raw bytes, got %d", len(data))
	}
	return data, nil
}
