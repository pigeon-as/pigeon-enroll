package main

import (
	"fmt"
	"io"
	"os"
)

// readEnrollmentKey reads the 32-byte enrollment key from a file, or from
// stdin if path is "-". Trailing newlines are trimmed so callers can pipe
// from `systemd-creds decrypt` or similar producers.
func readEnrollmentKey(path string) ([]byte, error) {
	var (
		data []byte
		err  error
	)
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
		data = data[:len(data)-1]
	}
	if len(data) != 32 {
		return nil, fmt.Errorf("expected 32 raw bytes, got %d", len(data))
	}
	return data, nil
}
