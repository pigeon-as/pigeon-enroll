// Package atomicfile provides atomic file writes via temp file + rename.
package atomicfile

import (
	"fmt"
	"os"
	"path/filepath"
)

// Write writes data to path atomically. It creates a temp file in the same
// directory, writes, sets permissions, and renames in one shot. The parent
// directory is created if it doesn't exist.
func Write(path string, data []byte, perm os.FileMode) error {
	return WriteOwned(path, data, perm, -1, -1)
}

// WriteOwned writes data to path atomically with ownership. It chowns the
// temp file before renaming, so the destination appears with correct ownership
// atomically. uid/gid of -1 means "don't change".
func WriteOwned(path string, data []byte, perm os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	f, err := os.CreateTemp(dir, ".atomic-*")
	if err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if uid != -1 || gid != -1 {
		if err := os.Chown(f.Name(), uid, gid); err != nil {
			return fmt.Errorf("atomic write %s: %w", path, err)
		}
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	return nil
}
