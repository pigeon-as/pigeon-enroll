// pigeon-enroll is a secret enrollment server and claim client for pigeon infrastructure.
//
// Usage:
//
//	pigeon-enroll <command> [options]
//
// Commands:
//
//	server          Run the enrollment server
//	generate-token  Generate an HMAC claim token
//	generate-cert   Generate a TLS certificate
//	claim           Claim secrets from an enrollment server
//	render          Render HCL templates with variables
//	run-actions     Run post-claim lifecycle actions
//	version         Print version
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
)

const (
	version           = "0.1.0"
	defaultConfigPath = "/etc/pigeon/enroll-server.hcl"
)

// stringSlice implements flag.Value for repeatable string flags.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "help", "-h", "--help":
		printUsage()
	case "server":
		os.Exit(cmdServer(args))
	case "generate-token":
		os.Exit(cmdGenerateToken(args))
	case "generate-cert":
		os.Exit(cmdGenerateCert(args))
	case "claim":
		os.Exit(cmdClaim(args))
	case "ek-hash":
		os.Exit(cmdEKHash(args))
	case "render":
		os.Exit(cmdRender(args))
	case "run-actions":
		os.Exit(cmdRunActions(args))
	case "version":
		fmt.Printf("pigeon-enroll v%s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: pigeon-enroll <command> [options]

Commands:
  server          Run the enrollment server
  generate-token  Generate an HMAC claim token
  generate-cert   Generate a TLS certificate
  claim           Claim secrets from an enrollment server
  ek-hash         Print EK public key hash (for ek_hash_path allowlist)
  render          Render HCL templates with variables
  run-actions     Run post-claim lifecycle actions
  version         Print version`)
}

// newFlagSet creates a flag.FlagSet with ExitOnError for a subcommand.
func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ExitOnError)
}

// loadConfig loads the HCL config, reads the enrollment key, and derives the
// HMAC signing key. If keyPath is non-empty, it overrides cfg.KeyPath.
func loadConfig(configPath, logLevel, keyPath string) (*slog.Logger, config.Config, []byte, []byte, error) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	var level slog.Level
	if err := level.UnmarshalText([]byte(logLevel)); err != nil {
		return logger, config.Config{}, nil, nil, fmt.Errorf("invalid log-level %q: %w", logLevel, err)
	}
	logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	}))

	cfg, err := config.Load(configPath)
	if err != nil {
		return logger, config.Config{}, nil, nil, fmt.Errorf("load config: %w", err)
	}
	if keyPath != "" {
		cfg.KeyPath = keyPath
	}

	ikm, err := readIKM(cfg)
	if err != nil {
		return logger, config.Config{}, nil, nil, err
	}

	hmacKey, err := secrets.DeriveHMACKey(ikm)
	if err != nil {
		return logger, config.Config{}, nil, nil, err
	}

	return logger, cfg, ikm, hmacKey, nil
}

// loadIKM loads the HCL config and reads the enrollment key without deriving HMAC.
// If keyPath is non-empty, it overrides cfg.KeyPath.
func loadIKM(configPath, keyPath string) ([]byte, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if keyPath != "" {
		cfg.KeyPath = keyPath
	}
	return readIKM(cfg)
}

// readIKM reads the enrollment key from the key_path config file.
func readIKM(cfg config.Config) ([]byte, error) {
	if err := config.CheckKeyFile(cfg.KeyPath); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read enrollment key: %w", err)
	}

	ikm, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, fmt.Errorf("decode enrollment key: %w", err)
	}

	if err := secrets.ValidateIKM(ikm); err != nil {
		return nil, err
	}
	return ikm, nil
}

// writeSecureFile writes data atomically with mode 0600.
func writeSecureFile(path string, data []byte) error {
	return atomicfile.Write(path, data, 0600)
}
