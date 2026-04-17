package main

import (
	"flag"
	"fmt"
	"os"
	"time"
)

// cmdRead implements `pigeon-enroll read <path>`.
//
// Every supported path returns exactly one scalar. Output is written raw
// to stdout (or -o <file>).
func cmdRead(args []string) int {
	fs := flag.NewFlagSet("read", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: pigeon-enroll read [flags] <path>

Read a scalar resource. Paths:
  var/<name>        literal string
  secret/<name>     HKDF-derived secret (encoded per config)
  ca/<name>         CA certificate (PEM)
  jwt_key/<name>    JWT signing public key (PEM)

Flags:`)
		fs.PrintDefaults()
	}
	cf := registerClientFlags(fs)
	outPath := fs.String("o", "", "output file (default stdout)")
	timeout := fs.Duration("timeout", 30*time.Second, "read timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fs.Usage()
		return 2
	}
	return dispatchScalar(cf, *outPath, *timeout, rest[0], nil /*write=*/, false)
}
