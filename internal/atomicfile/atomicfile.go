// Package atomicfile provides atomic file writes via temp file + rename.
// Follows the Calico CNI install / Flannel WriteSubnetFile pattern: create
// temp file in same directory, chmod + chown on the open fd (race-free),
// fsync, rename, then fsync the parent dir so the rename is durable across
// crash.
//
// References:
//   - Calico CNI install: https://github.com/projectcalico/calico/blob/master/cni-plugin/pkg/install/install.go
//   - Flannel subnet file: https://github.com/flannel-io/flannel/blob/master/pkg/subnet/subnet.go
//   - SPIRE diskutil:      https://github.com/spiffe/spire/blob/main/pkg/common/diskutil/file_posix.go
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

// WriteOwned writes data to path atomically with ownership. Chmod and Chown
// are issued on the open file descriptor (fchmod/fchown semantics) before
// rename, so the destination appears with correct perms+owner atomically
// and no path-based TOCTOU window exists between close and chown.
// uid/gid of -1 means "don't change".
func WriteOwned(path string, data []byte, perm os.FileMode, uid, gid int) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	f, err := os.CreateTemp(dir, ".atomic-*")
	if err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	tmpName := f.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	// Chown on the open fd (fchown) instead of by path — a symlink-swap race
	// between close and chown cannot redirect the ownership change.
	if uid != -1 || gid != -1 {
		if err := f.Chown(uid, gid); err != nil {
			f.Close()
			return fmt.Errorf("atomic write %s: %w", path, err)
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("atomic write %s: %w", path, err)
	}
	committed = true
	// fsync the parent directory so the rename is durable across crash
	// (SPIRE diskutil pattern). Best-effort on platforms where opening a
	// directory isn't supported.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
