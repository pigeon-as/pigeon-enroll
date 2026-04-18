package config

import (
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

const validConfig = `
trust_domain  = "pigeon.as"
listen        = ":9443"
renew_fraction = 0.5

attestor "tpm" {
  ek_ca_path   = "/etc/pigeon/ek-ca"
  ek_hash_path = "/etc/pigeon/ek-hashes"
}
attestor "hmac" {
  key_path = "/etc/pigeon/enrollment-key"
  window   = "30m"
}
attestor "bootstrap_cert" {}

ca "identity" {
  cn       = "pigeon identity CA"
  validity = "10y"
}
ca "mesh" {
  cn       = "pigeon mesh CA"
  validity = "10y"
}
ca "bootstrap" {
  cn       = "pigeon bootstrap CA"
  validity = "10y"
}

secret "gossip_key" {
  length   = 32
  encoding = "base64"
}

var "domain" { value = "infra.pigeon.as" }

jwt_key "consul_auto_config" {
  alg      = "EdDSA"
  issuer   = "pigeon-enroll"
  audience = "consul-auto-config"
  ttl      = "24h"
}

pki "mesh_worker" {
  ca            = ca.mesh
  ttl           = "168h"
  ext_key_usage = ["client_auth"]
  dns_sans      = ["${subject}"]
}

pki "identity_worker" {
  ca            = ca.identity
  ttl           = "720h"
}

template "mesh_json" { source = "/etc/pigeon/templates/mesh.json.tpl" }

policy "worker" {
  path "ca/bootstrap"             { capabilities = ["read"] }
  path "secret/gossip_key"        { capabilities = ["read"] }
  path "var/*"                    { capabilities = ["read"] }
  path "pki/mesh_worker"          { capabilities = ["write"] }
  path "jwt/consul_auto_config"   { capabilities = ["write"] }
  path "template/mesh_json"       { capabilities = ["read"] }
}

identity "worker" {
  attestors = [attestor.tpm, attestor.hmac, attestor.bootstrap_cert]
  pki       = pki.identity_worker
  policy    = policy.worker
}
`

func TestLoadValid(t *testing.T) {
	cfg, err := Parse([]byte(validConfig), "test.hcl")
	must.NoError(t, err)
	must.Eq(t, "pigeon.as", cfg.TrustDomain)
	must.Eq(t, ":9443", cfg.Listen)
	must.MapLen(t, 3, cfg.Attestors)
	must.EqOp(t, 30*time.Minute, cfg.Attestors["hmac"].Window)
	must.MapLen(t, 3, cfg.CAs)
	must.EqOp(t, 10*365*24*time.Hour, cfg.CAs["mesh"].Validity)
	must.Eq(t, "mesh", cfg.PKIs["mesh_worker"].CARef)
	id := cfg.Identities["worker"]
	must.NotNil(t, id)
	must.Eq(t, "identity_worker", id.PKIRef)
	must.Eq(t, "worker", id.PolicyRef)
	must.Eq(t, []string{"tpm", "hmac", "bootstrap_cert"}, id.Attestors)
	p := cfg.Policies["worker"]
	must.NotNil(t, p)
	must.SliceLen(t, 6, p.Paths)
}

func TestUnknownRefs(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "pki references unknown ca",
			body: `trust_domain = "x"
pki "p" {
  ca = ca.missing
}`,
			want: "missing",
		},
		{
			name: "identity references unknown pki",
			body: `trust_domain = "x"
ca "c" {}
pki "p" {
  ca = ca.c
}
policy "pol" {
  path "x" { capabilities = ["read"] }
}
identity "i" {
  attestors = []
  pki       = pki.missing
  policy    = policy.pol
}`,
			want: "missing",
		},
		{
			name: "identity references unknown attestor",
			body: `trust_domain = "x"
ca "c" {}
pki "p" {
  ca = ca.c
}
policy "pol" {
  path "x" { capabilities = ["read"] }
}
identity "i" {
  attestors = [attestor.missing]
  pki       = pki.p
  policy    = policy.pol
}`,
			want: "attestor",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.body), "t.hcl")
			must.ErrorContains(t, err, tc.want)
		})
	}
}

func TestDurationShorthand(t *testing.T) {
	cfg, err := Parse([]byte(`trust_domain = "x"
ca "c" { validity = "2y" }`), "t.hcl")
	must.NoError(t, err)
	must.EqOp(t, 2*365*24*time.Hour, cfg.CAs["c"].Validity)
}
