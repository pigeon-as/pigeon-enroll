//go:build unix

package main

import (
	"fmt"
	"os"
)

// checkKeyFilePerm rejects IKM files that are readable by group or other.
// Mirrors the pre-rewrite contract: "0600 or narrower." The check is a
// fail-fast guard against common operator mistakes (umask 022 copy,
// accidental `chmod +r`).
func checkKeyFilePerm(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("enrollment key %s has loose permissions %04o — must be 0600 or narrower",
			path, info.Mode().Perm())
	}
	return nil
}
