package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/pigeon-as/pigeon-enroll/internal/tpm"
)

func cmdEKHash(args []string) int {
	flag.NewFlagSet("ek-hash", flag.ExitOnError).Parse(args)

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
