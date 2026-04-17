package config

import (
	"strings"
	"testing"
	"time"
)

const validConfig = `
trust_domain  = "pigeon.as"
listen        = ":9443"
identity_ttl  = "720h"
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
  path "ca/bootstrap/cert"             { capabilities = ["read"] }
  path "secret/gossip_key"             { capabilities = ["read"] }
  path "var/*"                         { capabilities = ["read"] }
  path "pki/mesh_worker"         { capabilities = ["write"] }
  path "jwt/consul_auto_config/sign"   { capabilities = ["write"] }
  path "template/mesh_json"            { capabilities = ["read"] }
}

identity "worker" {
  attestors = [attestor.tpm, attestor.hmac, attestor.bootstrap_cert]
  pki       = pki.identity_worker
  policy    = policy.worker
}
`

func TestLoadValid(t *testing.T) {
	cfg, err := Parse([]byte(validConfig), "test.hcl")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.TrustDomain != "pigeon.as" {
		t.Errorf("trust_domain = %q", cfg.TrustDomain)
	}
	if cfg.Listen != ":9443" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.IdentityTTL != 720*time.Hour {
		t.Errorf("identity_ttl = %v", cfg.IdentityTTL)
	}
	if len(cfg.Attestors) != 3 {
		t.Errorf("attestors = %d, want 3", len(cfg.Attestors))
	}
	if cfg.Attestors["hmac"].Window != 30*time.Minute {
		t.Errorf("hmac window = %v", cfg.Attestors["hmac"].Window)
	}
	if len(cfg.CAs) != 3 {
		t.Errorf("cas = %d, want 3", len(cfg.CAs))
	}
	if cfg.CAs["mesh"].Validity != 10*365*24*time.Hour {
		t.Errorf("mesh validity = %v", cfg.CAs["mesh"].Validity)
	}
	if cfg.PKIs["mesh_worker"].CARef != "mesh" {
		t.Errorf("pki.mesh_worker.ca = %q", cfg.PKIs["mesh_worker"].CARef)
	}
	id := cfg.Identities["worker"]
	if id == nil {
		t.Fatal("identity worker missing")
	}
	if id.PKIRef != "identity_worker" || id.PolicyRef != "worker" {
		t.Errorf("identity refs wrong: pki=%q policy=%q", id.PKIRef, id.PolicyRef)
	}
	want := []string{"tpm", "hmac", "bootstrap_cert"}
	if len(id.Attestors) != 3 {
		t.Fatalf("attestors = %v", id.Attestors)
	}
	for i, k := range want {
		if id.Attestors[i] != k {
			t.Errorf("attestors[%d] = %q, want %q", i, id.Attestors[i], k)
		}
	}
	p := cfg.Policies["worker"]
	if p == nil || len(p.Paths) != 6 {
		t.Fatalf("policy worker: %v", p)
	}
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
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %q, want contains %q", err.Error(), tc.want)
			}
		})
	}
}

func TestDurationShorthand(t *testing.T) {
	cfg, err := Parse([]byte(`trust_domain = "x"
ca "c" { validity = "2y" }`), "t.hcl")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CAs["c"].Validity != 2*365*24*time.Hour {
		t.Errorf("validity = %v", cfg.CAs["c"].Validity)
	}
}
