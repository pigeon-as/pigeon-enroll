package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/hcl/v2"
	hcljson "github.com/hashicorp/hcl/v2/json"
	"github.com/pigeon-as/pigeon-enroll/internal/action"
	"github.com/shoenig/test/must"
)

func testBody(t *testing.T, jsonStr string) hcl.Body {
	t.Helper()
	f, diags := hcljson.Parse([]byte(jsonStr), "test.json")
	if diags.HasErrors() {
		t.Fatalf("parse test body: %s", diags.Error())
	}
	return f.Body
}

func TestLoadDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`vars = { k = "v" }`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, ":8443", cfg.Listen)
	must.EqOp(t, "/etc/pigeon/enrollment-key", cfg.KeyPath)
	must.EqOp(t, 30*time.Minute, cfg.TokenWindow)
	must.EqOp(t, 720*time.Hour, cfg.ServerCertTTL)
}

func TestLoadTokenWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
vars = { k = "v" }
token_window = "15m"
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, 15*time.Minute, cfg.TokenWindow)
}

func TestLoadTokenWindowInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
vars = { k = "v" }
token_window = "bogus"
`), 0644)

	_, err := Load(path)
	must.Error(t, err)
}

func TestLoadTokenWindowTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
vars = { k = "v" }
token_window = "500ms"
`), 0644)

	_, err := Load(path)
	must.Error(t, err)
}

func TestLoadCertTTL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
vars = { k = "v" }
server_cert_ttl = "48h"
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, 48*time.Hour, cfg.ServerCertTTL)
}

func TestLoadCertTTLInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")

	os.WriteFile(path, []byte(`
vars = { k = "v" }
server_cert_ttl = "bogus"
`), 0644)
	_, err := Load(path)
	must.Error(t, err)
}

func TestLoadCertTTLTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")

	os.WriteFile(path, []byte(`
vars = { k = "v" }
server_cert_ttl = "100ms"
`), 0644)
	_, err := Load(path)
	must.Error(t, err)
}

func TestValidateSecretsOrVars(t *testing.T) {
	err := validate(Config{TokenWindow: time.Minute, ServerCertTTL: time.Hour})
	must.Error(t, err)
}

func TestValidateSecretSpec(t *testing.T) {
	tests := []struct {
		name string
		spec SecretSpec
		ok   bool
	}{
		{"valid base64", SecretSpec{Name: "k", Length: 32, Encoding: "base64"}, true},
		{"valid hex", SecretSpec{Name: "k", Length: 16, Encoding: "hex"}, true},
		{"missing name", SecretSpec{Length: 32, Encoding: "base64"}, false},
		{"zero length", SecretSpec{Name: "k", Length: 0, Encoding: "base64"}, false},
		{"bad encoding", SecretSpec{Name: "k", Length: 32, Encoding: "raw"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				TokenWindow:   time.Minute,
				ServerCertTTL: time.Hour,
				Secrets:       []SecretSpec{tt.spec},
			}
			err := validate(cfg)
			if tt.ok {
				must.NoError(t, err)
			} else {
				must.Error(t, err)
			}
		})
	}
}

func TestValidateDuplicateSecretName(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Secrets: []SecretSpec{
			{Name: "k", Length: 32, Encoding: "base64"},
			{Name: "k", Length: 16, Encoding: "hex"},
		},
	}
	must.Error(t, validate(cfg))
}

func TestValidateNameConflict(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Secrets:       []SecretSpec{{Name: "k", Length: 32, Encoding: "base64"}},
		Vars:          map[string]string{"k": "v"},
	}
	must.Error(t, validate(cfg))
}

func TestValidateVaultTokenRefersToSecret(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Secrets:       []SecretSpec{{Name: "vault_token", Length: 32, Encoding: "hex"}},
		Actions:       []action.Config{{Type: "vault-init", Body: testBody(t, `{"token": {"id": "vault_token"}}`)}},
	}
	must.NoError(t, validate(cfg))
}

func TestValidateVaultTokenRefersToMissingSecret(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Secrets:       []SecretSpec{{Name: "other", Length: 32, Encoding: "hex"}},
		Actions:       []action.Config{{Type: "vault-init", Body: testBody(t, `{"token": {"id": "nonexistent"}}`)}},
	}
	must.Error(t, validate(cfg))
}

func TestLoadActionConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
secret "mgmt" {
  length   = 32
  encoding = "hex"
}

action "vault-init" {
  token {
    id = "mgmt"
  }
}
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.SliceLen(t, 1, cfg.Actions)
	must.EqOp(t, "vault-init", cfg.Actions[0].Type)
}

func TestCheckKeyFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "enrollment-key")

	must.Error(t, CheckKeyFile(keyPath))

	os.WriteFile(keyPath, []byte("0123456789abcdef0123456789abcdef"), 0600)
	must.NoError(t, CheckKeyFile(keyPath))
}

func TestLoadCertBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
ca "auth" {
  scope = ["server"]
}

cert "auth_worker" {
  ca          = "auth"
  scope       = ["worker"]
  ttl         = "720h"
  client_auth = true
  cn          = "worker"
}

vars = { k = "v" }
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.SliceLen(t, 1, cfg.Certs)

	c := cfg.Certs[0]
	must.EqOp(t, "auth_worker", c.Name)
	must.EqOp(t, "auth", c.CA)
	must.EqOp(t, 720*time.Hour, c.TTL)
	must.EqOp(t, "worker", c.CN)
}

func TestLoadCertBlockDNSSANs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
ca "mesh" {
  scope = ["server"]
}

cert "mesh_worker" {
  ca          = "mesh"
  scope       = ["worker"]
  ttl         = "720h"
  client_auth = true
  server_auth = true
  dns_sans    = ["mesh.pigeon.internal"]
}

vars = { k = "v" }
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.SliceLen(t, 1, cfg.Certs)

	c := cfg.Certs[0]
	must.EqOp(t, "mesh_worker", c.Name)
	must.EqOp(t, "", c.CN)

	dns, ips, err := c.ResolveSANs("test-subject")
	must.NoError(t, err)
	must.SliceLen(t, 1, dns)
	must.EqOp(t, "mesh.pigeon.internal", dns[0])
	must.SliceLen(t, 0, ips)
}

func TestValidateCertMissingCA(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		CAs:           []CASpec{{Name: "auth"}},
		Certs:         []CertSpec{{Name: "c", CA: "nonexistent", Scope: []string{"worker"}, CN: "w", TTL: time.Hour}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateCertEmptyScope(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		CAs:           []CASpec{{Name: "auth"}},
		Certs:         []CertSpec{{Name: "c", CA: "auth", CN: "w", TTL: time.Hour}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateCertOptionalCN(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		CAs:           []CASpec{{Name: "auth"}},
		Certs:         []CertSpec{{Name: "c", CA: "auth", Scope: []string{"worker"}, TTL: time.Hour}},
	}
	must.NoError(t, validate(cfg))
}

func TestValidateCertTTLTooSmall(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		CAs:           []CASpec{{Name: "auth"}},
		Certs:         []CertSpec{{Name: "c", CA: "auth", Scope: []string{"worker"}, CN: "w", TTL: time.Second}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateCertNameConflictsWithCA(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		CAs:           []CASpec{{Name: "auth"}},
		Certs:         []CertSpec{{Name: "auth", CA: "auth", Scope: []string{"worker"}, CN: "w", TTL: time.Hour}},
	}
	must.Error(t, validate(cfg))
}

func TestLoadCertIPSANsValid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
ca "auth" {
  scope = ["server"]
}

cert "c" {
  ca       = "auth"
  scope    = ["worker"]
  ttl      = "1h"
  cn       = "w"
  ip_sans  = ["10.0.0.1", "::1"]
}

vars = { k = "v" }
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.SliceLen(t, 1, cfg.Certs)

	_, ips, err := cfg.Certs[0].ResolveSANs("test")
	must.NoError(t, err)
	must.SliceLen(t, 2, ips)
}

func TestLoadCertIPSANsInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
ca "auth" {
  scope = ["server"]
}

cert "c" {
  ca       = "auth"
  scope    = ["worker"]
  ttl      = "1h"
  cn       = "w"
  ip_sans  = ["not-an-ip"]
}

vars = { k = "v" }
`), 0644)

	_, err := Load(path)
	must.Error(t, err)
	must.StrContains(t, err.Error(), "ip_sans entry \"not-an-ip\" is not a valid IP address")
}

func TestLoadJWTBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
jwt "consul_auto_config" {
  issuer   = "pigeon-enroll"
  audience = "consul-auto-config"
  ttl      = "24h"
  scope    = "worker"
}

vars = { k = "v" }
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.SliceLen(t, 1, cfg.JWTs)

	j := cfg.JWTs[0]
	must.EqOp(t, "consul_auto_config", j.Name)
	must.EqOp(t, "pigeon-enroll", j.Issuer)
	must.EqOp(t, "consul-auto-config", j.Audience)
	must.EqOp(t, 24*time.Hour, j.TTL)
	must.EqOp(t, "worker", j.Scope)
}

func TestValidateJWTMissingIssuer(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		JWTs:          []JWTSpec{{Name: "j", Audience: "a", Scope: "s", TTL: time.Hour}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateJWTMissingScope(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		JWTs:          []JWTSpec{{Name: "j", Issuer: "i", Audience: "a", TTL: time.Hour}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateJWTTTLTooSmall(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		JWTs:          []JWTSpec{{Name: "j", Issuer: "i", Audience: "a", Scope: "s", TTL: time.Second}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateJWTDuplicateName(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		JWTs: []JWTSpec{
			{Name: "j", Issuer: "i", Audience: "a", Scope: "s", TTL: time.Hour},
			{Name: "j", Issuer: "i2", Audience: "a2", Scope: "s2", TTL: time.Hour},
		},
	}
	must.Error(t, validate(cfg))
}

func TestValidateJWTOnlyConfig(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		JWTs:          []JWTSpec{{Name: "j", Issuer: "i", Audience: "a", Scope: "s", TTL: time.Hour}},
	}
	must.NoError(t, validate(cfg))
}

func TestLoadCertDNSSANsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
ca "auth" {
  scope = ["server"]
}

cert "c" {
  ca       = "auth"
  scope    = ["worker"]
  ttl      = "1h"
  cn       = "w"
  dns_sans = [""]
}

vars = { k = "v" }
`), 0644)

	_, err := Load(path)
	must.Error(t, err)
}

func TestValidateCertModePush(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		CAs:           []CASpec{{Name: "auth"}},
		Certs:         []CertSpec{{Name: "c", CA: "auth", Scope: []string{"worker"}, CN: "w", TTL: time.Hour, Mode: "push"}},
	}
	must.NoError(t, validate(cfg))
}

func TestValidateCertModeCSR(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		CAs:           []CASpec{{Name: "auth"}},
		Certs:         []CertSpec{{Name: "c", CA: "auth", Scope: []string{"worker"}, CN: "w", TTL: time.Hour, Mode: "csr"}},
	}
	must.NoError(t, validate(cfg))
}

func TestValidateCertModeInvalid(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		CAs:           []CASpec{{Name: "auth"}},
		Certs:         []CertSpec{{Name: "c", CA: "auth", Scope: []string{"worker"}, CN: "w", TTL: time.Hour, Mode: "bogus"}},
	}
	must.Error(t, validate(cfg))
}

func TestResolveSANsSubjectInterpolation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
ca "auth" {
  scope = ["server"]
}

cert "c" {
  ca          = "auth"
  scope       = ["worker"]
  ttl         = "1h"
  server_auth = true
  dns_sans    = ["vault.service.internal", "${subject}"]
}

vars = { k = "v" }
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.SliceLen(t, 1, cfg.Certs)

	dns, ips, err := cfg.Certs[0].ResolveSANs("worker-01.dc1.example.com")
	must.NoError(t, err)
	must.SliceLen(t, 2, dns)
	must.EqOp(t, "vault.service.internal", dns[0])
	must.EqOp(t, "worker-01.dc1.example.com", dns[1])
	must.SliceLen(t, 0, ips)
}

func TestResolveSANsNoRemain(t *testing.T) {
	cs := CertSpec{Name: "test"}
	dns, ips, err := cs.ResolveSANs("anything")
	must.NoError(t, err)
	must.SliceLen(t, 0, dns)
	must.SliceLen(t, 0, ips)
}

func TestResolveSANsBody(t *testing.T) {
	cs := CertSpec{
		Name:   "test",
		Remain: testBody(t, `{"dns_sans": ["static.internal", "${subject}"], "ip_sans": ["10.0.0.1"]}`),
	}
	dns, ips, err := cs.ResolveSANs("node-01.dc1.example.com")
	must.NoError(t, err)
	must.SliceLen(t, 2, dns)
	must.EqOp(t, "static.internal", dns[0])
	must.EqOp(t, "node-01.dc1.example.com", dns[1])
	must.SliceLen(t, 1, ips)
	must.EqOp(t, "10.0.0.1", ips[0].String())
}

func TestLoadTemplateBlock(t *testing.T) {
	dir := t.TempDir()

	tplPath := filepath.Join(dir, "worker.sh.tpl")
	os.WriteFile(tplPath, []byte("#!/bin/bash\necho ${token}"), 0644)

	// Use forward slashes in HCL to avoid backslash escape issues on Windows.
	tplPathHCL := filepath.ToSlash(tplPath)

	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`
template "setup-worker" {
  source = "`+tplPathHCL+`"
  scope  = "worker"
}

client_cert_ttl = "12h"
vars = { k = "v" }
`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.SliceLen(t, 1, cfg.Templates)
	must.EqOp(t, "setup-worker", cfg.Templates[0].Name)
	must.EqOp(t, tplPathHCL, cfg.Templates[0].Source)
	must.EqOp(t, "worker", cfg.Templates[0].Scope)
	must.EqOp(t, 12*time.Hour, cfg.ClientCertTTL)
}

func TestValidateTemplateDuplicateName(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		ClientCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		Templates: []TemplateSpec{
			{Name: "t", Source: "/a.tpl", Scope: "worker"},
			{Name: "t", Source: "/b.tpl", Scope: "worker"},
		},
	}
	must.Error(t, validate(cfg))
}

func TestValidateTemplateMissingScope(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		ClientCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		Templates:     []TemplateSpec{{Name: "t", Source: "/a.tpl"}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateTemplateMissingSource(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		ClientCertTTL: time.Hour,
		Vars:          map[string]string{"k": "v"},
		Templates:     []TemplateSpec{{Name: "t", Scope: "worker"}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateTemplateClientCertTTLTooSmall(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		ClientCertTTL: time.Second,
		Vars:          map[string]string{"k": "v"},
		Templates:     []TemplateSpec{{Name: "t", Source: "/a.tpl", Scope: "worker"}},
	}
	must.Error(t, validate(cfg))
}

func TestValidateTemplateOnlyConfig(t *testing.T) {
	cfg := Config{
		TokenWindow:   time.Minute,
		ServerCertTTL: time.Hour,
		ClientCertTTL: time.Hour,
		Templates:     []TemplateSpec{{Name: "t", Source: "/a.tpl", Scope: "worker"}},
	}
	must.NoError(t, validate(cfg))
}

func TestLoadClientCertTTLDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.hcl")
	os.WriteFile(path, []byte(`vars = { k = "v" }`), 0644)

	cfg, err := Load(path)
	must.NoError(t, err)
	must.EqOp(t, 24*time.Hour, cfg.ClientCertTTL)
}
