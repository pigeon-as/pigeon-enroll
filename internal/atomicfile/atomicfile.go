// Package atomicfile provides atomic file writes via temp file + rename.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write writes data to path atomically. It creates a temp file in the same
// directory, writes, sets permissions, and renames in one shot. The parent
// directory is created if it doesn't exist.
func Write(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".atomic-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
