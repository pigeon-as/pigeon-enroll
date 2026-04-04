package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/shoenig/test/must"
)

func TestWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "test.txt")

	must.NoError(t, Write(path, []byte("hello"), 0600))

	data, err := os.ReadFile(path)
	must.NoError(t, err)
	must.EqOp(t, "hello", string(data))

	info, err := os.Stat(path)
	must.NoError(t, err)
	if runtime.GOOS != "windows" {
		must.EqOp(t, os.FileMode(0600), info.Mode().Perm())
	}
}

func TestWriteOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	must.NoError(t, Write(path, []byte("first"), 0644))
	must.NoError(t, Write(path, []byte("second"), 0600))

	data, err := os.ReadFile(path)
	must.NoError(t, err)
	must.EqOp(t, "second", string(data))
}

func TestWriteNoTempLeftOnSuccess(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")

	must.NoError(t, Write(path, []byte("ok"), 0600))

	entries, err := os.ReadDir(dir)
	must.NoError(t, err)
	must.SliceLen(t, 1, entries)
}

func TestWriteOwned(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chown not supported on windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "owned.txt")

	uid := os.Getuid()
	gid := os.Getgid()

	must.NoError(t, WriteOwned(path, []byte("owned"), 0640, uid, gid))

	info, err := os.Stat(path)
	must.NoError(t, err)
	assertOwnership(t, info, uid, gid)
	must.EqOp(t, os.FileMode(0640), info.Mode().Perm())
}

func assertOwnership(t *testing.T, info os.FileInfo, uid, gid int) {
	t.Helper()
	stat := info.Sys().(*syscall.Stat_t)
	must.EqOp(t, uid, int(stat.Uid))
	must.EqOp(t, gid, int(stat.Gid))
}
