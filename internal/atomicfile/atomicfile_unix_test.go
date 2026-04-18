//go:build unix

package atomicfile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/shoenig/test/must"
)

func TestWriteOwned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "owned.txt")

	uid := os.Getuid()
	gid := os.Getgid()

	must.NoError(t, WriteOwned(path, []byte("owned"), 0o640, uid, gid))

	info, err := os.Stat(path)
	must.NoError(t, err)
	stat := info.Sys().(*syscall.Stat_t)
	must.EqOp(t, uid, int(stat.Uid))
	must.EqOp(t, gid, int(stat.Gid))
	must.EqOp(t, os.FileMode(0o640), info.Mode().Perm())
}
