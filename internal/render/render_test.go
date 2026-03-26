package render

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestFileSimple(t *testing.T) {
	tpl := writeTempFile(t, "simple.tpl", `hello ${name}`)
	got, err := File(tpl, map[string]string{"name": "world"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
}

func TestFileMultipleVars(t *testing.T) {
	tpl := writeTempFile(t, "multi.tpl", `dc=${datacenter} key=${gossip_key}`)
	got, err := File(tpl, map[string]string{
		"datacenter": "eu-west-gra",
		"gossip_key": "abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `dc=eu-west-gra key=abc123`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFileGoTemplatePassthrough(t *testing.T) {
	// {{ }} must pass through as literal text — HCL template engine ignores them.
	tpl := writeTempFile(t, "passthrough.tpl", `bind_addr = "{{ GetInterfaceIP \"wg0\" }}"`)
	got, err := File(tpl, map[string]string{})
	if err != nil {
		t.Fatal(err)
	}
	want := `bind_addr = "{{ GetInterfaceIP \"wg0\" }}"`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFileMixedSyntax(t *testing.T) {
	// Real-world pattern: HCL ${} interpolation alongside Go {{ }} passthrough.
	tpl := writeTempFile(t, "mixed.tpl", `encrypt = "${consul_encrypt}"
bind_addr = "{{ GetInterfaceIP \"wg0\" }}"`)
	got, err := File(tpl, map[string]string{"consul_encrypt": "secret123"})
	if err != nil {
		t.Fatal(err)
	}
	want := `encrypt = "secret123"
bind_addr = "{{ GetInterfaceIP \"wg0\" }}"`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestFileUndefinedVar(t *testing.T) {
	tpl := writeTempFile(t, "undef.tpl", `hello ${missing}`)
	_, err := File(tpl, map[string]string{})
	if err == nil {
		t.Fatal("expected error for undefined variable")
	}
}

func TestFileInvalidSyntax(t *testing.T) {
	tpl := writeTempFile(t, "invalid.tpl", `hello ${`)
	_, err := File(tpl, map[string]string{})
	if err == nil {
		t.Fatal("expected error for invalid template syntax")
	}
}

func TestFileMultiline(t *testing.T) {
	tpl := writeTempFile(t, "multiline.tpl", `{
  "seeds": ${mesh_seeds},
  "gossip_key": "${gossip_key}",
  "wg_psk": "${wg_psk}"
}`)
	got, err := File(tpl, map[string]string{
		"mesh_seeds": `["10.0.0.1", "10.0.0.2"]`,
		"gossip_key": "gk-base64",
		"wg_psk":     "psk-base64",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "seeds": ["10.0.0.1", "10.0.0.2"],
  "gossip_key": "gk-base64",
  "wg_psk": "psk-base64"
}`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "output.txt")
	if err := WriteAtomic(path, []byte("content"), 0640); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "content" {
		t.Fatalf("got %q, want %q", got, "content")
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0640 {
			t.Fatalf("got perms %04o, want 0640", info.Mode().Perm())
		}
	}
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
