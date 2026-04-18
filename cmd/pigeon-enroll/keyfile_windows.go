//go:build windows

package main

// checkKeyFilePerm is a no-op on Windows — POSIX-style mode bits don't
// reflect ACL-based access and there is no portable cross-check here.
// Operators running on Windows are expected to use credstore equivalents.
func checkKeyFilePerm(path string) error {
	_ = path
	return nil
}
