package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/secrets"
	"github.com/pigeon-as/pigeon-enroll/internal/tpm"
	"github.com/pigeon-as/pigeon-enroll/internal/tpmseal"
)

func cmdEKHash(args []string) int {
	newFlagSet("ek-hash").Parse(args)

	if !tpm.Available() {
		fmt.Fprintln(os.Stderr, "error: no TPM available on this host")
		return 1
	}

	sess, err := tpm.Open()
	if err != nil {
		fmt.Fprintf(os.Stderr, "open TPM: %v\n", err)
		return 1
	}
	defer sess.Close()

	ekHash, err := sess.EKHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "compute EK hash: %v\n", err)
		return 1
	}

	// Print hash to stdout for use in ek_hash_path file.
	fmt.Println(ekHash)
	return 0
}

func cmdSealKey(args []string) int {
	flags := newFlagSet("seal-key")
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	pcrList := flags.String("pcrs", "7,11,14", "Comma-separated PCR indices to seal to")
	output := flags.String("output", "", "Path to write sealed blob (default: key_path + \".sealed\")")
	deletePlaintext := flags.Bool("delete-plaintext", false, "Delete the plaintext key file after sealing")
	flags.Parse(args)

	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		return 1
	}

	pcrs, err := parsePCRList(*pcrList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid PCR list: %v\n", err)
		return 1
	}

	outPath := *output
	if outPath == "" {
		outPath = cfg.KeyPath + ".sealed"
	}

	// Read the plaintext enrollment key.
	if err := config.CheckKeyFile(cfg.KeyPath); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	enrollmentKeyHex, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read enrollment key: %v\n", err)
		return 1
	}
	ikm, err := hex.DecodeString(strings.TrimSpace(string(enrollmentKeyHex)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode enrollment key: %v\n", err)
		return 1
	}
	if err := secrets.ValidateIKM(ikm); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	// Seal to TPM.
	if err := tpmseal.Seal(ikm, pcrs, outPath); err != nil {
		fmt.Fprintf(os.Stderr, "seal: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "sealed enrollment key to TPM (PCRs %s) → %s\n", *pcrList, outPath)

	if *deletePlaintext {
		if err := os.Remove(cfg.KeyPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: sealed successfully but failed to delete plaintext: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "deleted plaintext key %s\n", cfg.KeyPath)
	}

	return 0
}

func parsePCRList(s string) ([]uint, error) {
	parts := strings.Split(s, ",")
	pcrs := make([]uint, 0, len(parts))
	seen := make(map[uint]bool)
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid PCR index %q: %w", p, err)
		}
		if n > 23 {
			return nil, fmt.Errorf("PCR index %d out of range (0-23)", n)
		}
		if seen[uint(n)] {
			return nil, fmt.Errorf("duplicate PCR index %d", n)
		}
		seen[uint(n)] = true
		pcrs = append(pcrs, uint(n))
	}
	if len(pcrs) == 0 {
		return nil, fmt.Errorf("at least one PCR required")
	}
	return pcrs, nil
}
