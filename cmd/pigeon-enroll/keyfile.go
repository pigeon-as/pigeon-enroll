package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

// readEnrollmentKey reads the 32-byte enrollment key from a file, or from
// stdin if path is "-".
//
// On-disk format is 64 hex characters (RFC 4648 lowercase, `openssl rand
// -hex 32`) with optional leading UTF-8 BOM and trailing whitespace.
//
// For file (not stdin) sources a permission check rejects IKM files that are
// readable by group or other (perm & 0o077 != 0). Restores a pre-rewrite
// invariant — world-readable root secrets must not open silently.
func readEnrollmentKey(path string) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		if err := checkKeyFilePerm(path); err != nil {
			return nil, err
		}
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	// Strip a leading UTF-8 BOM (Windows editors add one by default) before
	// trimming ASCII whitespace — TrimSpace recognises U+00A0 but not U+FEFF.
	s := strings.TrimPrefix(string(data), "\uFEFF")
	s = strings.TrimSpace(s)
	ikm, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("enrollment key must be 64 hex chars: %w", err)
	}
	if len(ikm) != 32 {
		return nil, fmt.Errorf("enrollment key must decode to 32 bytes, got %d", len(ikm))
	}
	return ikm, nil
}
