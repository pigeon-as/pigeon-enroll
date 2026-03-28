package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.txt")

	if err := Write(path, []byte("hello"), 0600); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello" {
		t.Fatalf("got %q, want %q", data, "hello")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if info.Mode().Perm() != 0600 {
			t.Fatalf("got perm %o, want 0600", info.Mode().Perm())
		}
	}
}

func TestWriteOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if err := Write(path, []byte("first"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("second"), 0600); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Fatalf("got %q, want %q", data, "second")
	}
}

func TestWriteNoTempLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	if err := Write(path, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected 1 file, got %d: %v", len(entries), names)
	}
}

func TestWriteOwned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "owned.txt")

	uid := os.Getuid()
	gid := os.Getgid()

	if err := WriteOwned(path, []byte("owned"), 0640, uid, gid); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	assertOwnership(t, info, uid, gid)
	if info.Mode().Perm() != 0640 {
		t.Fatalf("got perm %o, want 0640", info.Mode().Perm())
	}
}

func assertOwnership(t *testing.T, info os.FileInfo, uid, gid int) {
	t.Helper()
	stat := info.Sys().(*syscall.Stat_t)
	if int(stat.Uid) != uid {
		t.Fatalf("got uid %d, want %d", stat.Uid, uid)
	}
	if int(stat.Gid) != gid {
		t.Fatalf("got gid %d, want %d", stat.Gid, gid)
	}
}
