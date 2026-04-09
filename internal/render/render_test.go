package render

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/shoenig/test/must"
	"github.com/zclconf/go-cty/cty"
)

func TestFileSimple(t *testing.T) {
	tpl := writeTempFile(t, "simple.tpl", `hello ${name}`)
	got, err := File(tpl, map[string]cty.Value{"name": cty.StringVal("world")})
	must.NoError(t, err)
	must.EqOp(t, "hello world", string(got))
}

func TestFileMultipleVars(t *testing.T) {
	tpl := writeTempFile(t, "multi.tpl", `dc=${datacenter} key=${gossip_key}`)
	got, err := File(tpl, map[string]cty.Value{
		"datacenter": cty.StringVal("eu-west-gra"),
		"gossip_key": cty.StringVal("abc123"),
	})
	must.NoError(t, err)
	must.EqOp(t, "dc=eu-west-gra key=abc123", string(got))
}

func TestFileGoTemplatePassthrough(t *testing.T) {
	// {{ }} must pass through as literal text — HCL template engine ignores them.
	tpl := writeTempFile(t, "passthrough.tpl", `bind_addr = "{{ GetInterfaceIP \"wg0\" }}"`)
	got, err := File(tpl, map[string]cty.Value{})
	must.NoError(t, err)
	must.EqOp(t, `bind_addr = "{{ GetInterfaceIP \"wg0\" }}"`, string(got))
}

func TestFileMixedSyntax(t *testing.T) {
	// Real-world pattern: HCL ${} interpolation alongside Go {{ }} passthrough.
	tpl := writeTempFile(t, "mixed.tpl", `encrypt = "${consul_encrypt}"
bind_addr = "{{ GetInterfaceIP \"wg0\" }}"`)
	got, err := File(tpl, map[string]cty.Value{"consul_encrypt": cty.StringVal("secret123")})
	must.NoError(t, err)
	want := "encrypt = \"secret123\"\nbind_addr = \"{{ GetInterfaceIP \\\"wg0\\\" }}\""
	must.EqOp(t, want, string(got))
}

func TestFileUndefinedVar(t *testing.T) {
	tpl := writeTempFile(t, "undef.tpl", `hello ${missing}`)
	_, err := File(tpl, map[string]cty.Value{})
	must.Error(t, err)
}

func TestFileInvalidSyntax(t *testing.T) {
	tpl := writeTempFile(t, "invalid.tpl", `hello ${`)
	_, err := File(tpl, map[string]cty.Value{})
	must.Error(t, err)
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
	must.NoError(t, err)
	want := `{
  "seeds": ["10.0.0.1", "10.0.0.2"],
  "gossip_key": "gk-base64",
  "wg_psk": "psk-base64"
}`
	must.EqOp(t, want, string(got))
}

func TestAtomicfileWriteOwned(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "output.txt")
	must.NoError(t, atomicfile.WriteOwned(path, []byte("content"), 0640, -1, -1))

	got, err := os.ReadFile(path)
	must.NoError(t, err)
	must.EqOp(t, "content", string(got))

	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		must.EqOp(t, os.FileMode(0640), info.Mode().Perm())
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
	must.NoError(t, err)
	must.EqOp(t, "key=abc123 dc=eu-west-gra", string(got))
}

func TestParseVarsJSON(t *testing.T) {
	data := []byte(`{"name": "world", "nested": {"key": "val"}}`)
	got, err := ParseVarsJSON(data)
	must.NoError(t, err)
	must.EqOp(t, "world", got["name"].AsString())
	must.EqOp(t, "val", got["nested"].AsValueMap()["key"].AsString())
}

func TestParseVarsJSONNotObject(t *testing.T) {
	_, err := ParseVarsJSON([]byte(`"just a string"`))
	must.Error(t, err)
}

func TestParseVarsFileEmpty(t *testing.T) {
	path := writeTempFile(t, "empty.json", "")
	got, err := ParseVarsFile(path)
	must.NoError(t, err)
	must.Nil(t, got)
}

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	must.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

func TestContentSimple(t *testing.T) {
	got, err := Content("hello ${name}", map[string]cty.Value{"name": cty.StringVal("world")})
	must.NoError(t, err)
	must.EqOp(t, "hello world", string(got))
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
	must.NoError(t, err)
	must.EqOp(t, "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n", string(got))
}

func TestContentNoVars(t *testing.T) {
	got, err := Content("static text", nil)
	must.NoError(t, err)
	must.EqOp(t, "static text", string(got))
}

func TestLoadConfigContent(t *testing.T) {
	path := writeTempFile(t, "render.hcl", `
template {
  content     = "hello"
  destination = "/tmp/out"
}
`)
	cfg, err := LoadConfig(path)
	must.NoError(t, err)
	must.EqOp(t, "hello", cfg.Templates[0].Content)
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
	must.Error(t, err)
}

func TestLoadConfigNoSourceNoContent(t *testing.T) {
	path := writeTempFile(t, "render.hcl", `
template {
  destination = "/tmp/out"
}
`)
	_, err := LoadConfig(path)
	must.Error(t, err)
}
