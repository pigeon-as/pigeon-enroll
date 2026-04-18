package main

import (
	"flag"
	"fmt"
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
	hmacKey, err := token.DeriveHMACKey(ikm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "derive hmac key: %v\n", err)
		return 1
	}

	fmt.Println(token.Generate(hmacKey, time.Now(), hmacAt.Window, *identityName))
	return 0
}
