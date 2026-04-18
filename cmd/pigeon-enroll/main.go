// pigeon-enroll - SPIFFE/Vault-shaped identity and resource service.
package main

import (
	"fmt"
	"os"
)

const version = "0.0.1-beta.1"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "help", "-h", "--help":
		printUsage()
	case "version":
		fmt.Printf("pigeon-enroll v%s\n", version)
	case "ek-hash":
		os.Exit(cmdEKHash(os.Args[2:]))
	case "server":
		os.Exit(cmdServer(os.Args[2:]))
	case "register":
		os.Exit(cmdRegister(os.Args[2:]))
	case "renew":
		os.Exit(cmdRenew(os.Args[2:]))
	case "read":
		os.Exit(cmdRead(os.Args[2:]))
	case "write":
		os.Exit(cmdWrite(os.Args[2:]))
	case "issue":
		os.Exit(cmdIssue(os.Args[2:]))
	case "generate-token":
		os.Exit(cmdGenerateToken(os.Args[2:]))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: pigeon-enroll <command> [options]

Commands:
  server     Run the enrollment server
  register   Attest and receive an identity cert (bootstrap credentials)
  renew      Rotate the identity cert (mTLS with existing identity cert)
  read       Read a scalar resource (var, secret, ca, jwt_key, template)
  write      Write against a mutating path (pki, jwt)
  issue      Generate a keypair, CSR, and write pki/<role> in one step
  generate-token  Mint an HMAC bootstrap token locally from the enrollment key
  ek-hash    Print local TPM EK public key hash
  version    Print version`)
}
