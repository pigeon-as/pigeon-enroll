package render

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/zclconf/go-cty/cty"
)

func TestFileSimple(t *testing.T) {
	tpl := writeTempFile(t, "simple.tpl", `hello ${name}`)
	got, err := File(tpl, map[string]cty.Value{"name": cty.StringVal("world")})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
}

func TestFileMultipleVars(t *testing.T) {
	tpl := writeTempFile(t, "multi.tpl", `dc=${datacenter} key=${gossip_key}`)
	got, err := File(tpl, map[string]cty.Value{
		"datacenter": cty.StringVal("eu-west-gra"),
		"gossip_key": cty.StringVal("abc123"),
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
	got, err := File(tpl, map[string]cty.Value{})
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
	got, err := File(tpl, map[string]cty.Value{"consul_encrypt": cty.StringVal("secret123")})
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
	_, err := File(tpl, map[string]cty.Value{})
	if err == nil {
		t.Fatal("expected error for undefined variable")
	}
}

func TestFileInvalidSyntax(t *testing.T) {
	tpl := writeTempFile(t, "invalid.tpl", `hello ${`)
	_, err := File(tpl, map[string]cty.Value{})
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
	got, err := File(tpl, map[string]cty.Value{
		"mesh_seeds": cty.StringVal(`["10.0.0.1", "10.0.0.2"]`),
		"gossip_key": cty.StringVal("gk-base64"),
		"wg_psk":     cty.StringVal("psk-base64"),
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
	if err := WriteAtomic(path, []byte("content"), 0640, -1, -1); err != nil {
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

func TestFileNestedObject(t *testing.T) {
	tpl := writeTempFile(t, "nested.tpl", `key=${secrets.gossip_key} dc=${vars.datacenter}`)
	got, err := File(tpl, map[string]cty.Value{
		"secrets": cty.ObjectVal(map[string]cty.Value{
			"gossip_key": cty.StringVal("abc123"),
		}),
		"vars": cty.ObjectVal(map[string]cty.Value{
			"datacenter": cty.StringVal("eu-west-gra"),
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `key=abc123 dc=eu-west-gra`
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestParseVarsJSON(t *testing.T) {
	data := []byte(`{"name": "world", "nested": {"key": "val"}}`)
	got, err := ParseVarsJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	if got["name"].AsString() != "world" {
		t.Fatalf("name: got %q, want %q", got["name"].AsString(), "world")
	}
	nested := got["nested"].AsValueMap()
	if nested["key"].AsString() != "val" {
		t.Fatalf("nested.key: got %q, want %q", nested["key"].AsString(), "val")
	}
}

func TestParseVarsJSONNotObject(t *testing.T) {
	_, err := ParseVarsJSON([]byte(`"just a string"`))
	if err == nil {
		t.Fatal("expected error for non-object JSON")
	}
}

func TestParseVarsFileEmpty(t *testing.T) {
	path := writeTempFile(t, "empty.json", "")
	got, err := ParseVarsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("expected nil for empty file, got %v", got)
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

func TestContentSimple(t *testing.T) {
	got, err := Content("hello ${name}", map[string]cty.Value{"name": cty.StringVal("world")})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello world" {
		t.Fatalf("got %q, want %q", got, "hello world")
	}
}

func TestContentNested(t *testing.T) {
	vars := map[string]cty.Value{
		"ca": cty.ObjectVal(map[string]cty.Value{
			"vault": cty.ObjectVal(map[string]cty.Value{
				"cert_pem": cty.StringVal("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"),
			}),
		}),
	}
	got, err := Content("${ca.vault.cert_pem}", vars)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n" {
		t.Fatalf("got %q", got)
	}
}

func TestContentNoVars(t *testing.T) {
	got, err := Content("static text", nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "static text" {
		t.Fatalf("got %q", got)
	}
}

func TestLoadConfigContent(t *testing.T) {
	path := writeTempFile(t, "render.hcl", `
template {
  content     = "hello"
  destination = "/tmp/out"
}
`)
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Templates[0].Content != "hello" {
		t.Fatalf("content = %q", cfg.Templates[0].Content)
	}
}

func TestLoadConfigSourceAndContent(t *testing.T) {
	path := writeTempFile(t, "render.hcl", `
template {
  source      = "/tmp/tpl"
  content     = "hello"
  destination = "/tmp/out"
}
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for source+content")
	}
}

func TestLoadConfigNoSourceNoContent(t *testing.T) {
	path := writeTempFile(t, "render.hcl", `
template {
  destination = "/tmp/out"
}
`)
	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for no source and no content")
	}
}
