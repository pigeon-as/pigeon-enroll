package resource

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/policy"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	"github.com/shoenig/test/must"
)

// buildEngine constructs a policy engine from a single inline policy.
func buildEngine(t *testing.T, paths map[string][]string) *policy.Engine {
	t.Helper()
	pol := &config.Policy{Name: "worker"}
	for pattern, caps := range paths {
		pol.Paths = append(pol.Paths, config.PathRule{Pattern: pattern, Capabilities: caps})
	}
	eng, err := policy.New(map[string]*config.Policy{"worker": pol})
	must.NoError(t, err)
	return eng
}

func newTestResolver(t *testing.T, cfg *config.Config, paths map[string][]string) (*Resolver, *Caller) {
	t.Helper()
	eng := buildEngine(t, paths)
	ikm := bytes.Repeat([]byte{0x42}, 32)
	r, err := New(cfg, eng, ikm)
	must.NoError(t, err)
	return r, &Caller{Identity: "worker", Policy: "worker", Subject: "worker-01"}
}

func TestReadCA(t *testing.T) {
	cfg := &config.Config{CAs: map[string]*config.CA{"identity": {Name: "identity"}}}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"ca/identity": {"read"},
	})
	resp, err := r.Read(caller, "ca/identity")
	must.NoError(t, err)
	must.StrContains(t, string(resp.Content), "BEGIN CERTIFICATE")
}

func TestReadDeniedByPolicy(t *testing.T) {
	cfg := &config.Config{CAs: map[string]*config.CA{"identity": {Name: "identity"}}}
	r, caller := newTestResolver(t, cfg, nil)
	_, err := r.Read(caller, "ca/identity")
	must.ErrorContains(t, err, "permission denied")
}

func TestReadSecret(t *testing.T) {
	cfg := &config.Config{
		Secrets: map[string]*config.Secret{
			"gossip_key": {Name: "gossip_key", Length: 32, Encoding: "base64"},
		},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"secret/gossip_key": {"read"},
	})
	r1, err := r.Read(caller, "secret/gossip_key")
	must.NoError(t, err)
	r2, err := r.Read(caller, "secret/gossip_key")
	must.NoError(t, err)
	must.Eq(t, r1.Content, r2.Content)
	must.Positive(t, len(r1.Content))
}

func TestReadVar(t *testing.T) {
	cfg := &config.Config{
		Vars: map[string]*config.Var{"datacenter": {Name: "datacenter", Value: "dc1"}},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{"var/datacenter": {"read"}})
	resp, err := r.Read(caller, "var/datacenter")
	must.NoError(t, err)
	must.EqOp(t, "dc1", string(resp.Content))
}

func TestReadJWTKey(t *testing.T) {
	cfg := &config.Config{
		JWTKeys: map[string]*config.JWTKey{
			"auto_config": {Name: "auto_config", Alg: "EdDSA", Issuer: "pigeon-enroll", Audience: "consul", TTL: time.Hour},
		},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"jwt_key/auto_config": {"read"},
	})
	resp, err := r.Read(caller, "jwt_key/auto_config")
	must.NoError(t, err)
	must.StrContains(t, string(resp.Content), "PUBLIC KEY")
}

func TestWriteJWT(t *testing.T) {
	cfg := &config.Config{
		JWTKeys: map[string]*config.JWTKey{
			"auto_config": {Name: "auto_config", Alg: "EdDSA", Issuer: "pigeon-enroll", Audience: "consul", TTL: time.Hour},
		},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"jwt/auto_config": {"write"},
	})
	resp, err := r.Write(caller, "jwt/auto_config", nil)
	must.NoError(t, err)
	must.SliceLen(t, 3, bytes.Split(resp.Content, []byte(".")))
	must.EqOp(t, uint32(time.Hour.Seconds()), resp.TTLSeconds)
	must.EqOp(t, "application/jwt", resp.ContentType)
}

func TestWritePKI(t *testing.T) {
	cfg := &config.Config{
		CAs: map[string]*config.CA{"identity": {Name: "identity"}},
		PKIs: map[string]*config.PKI{
			"worker": {
				Name:        "worker",
				CARef:       "identity",
				TTL:         time.Hour,
				ExtKeyUsage: []string{"client_auth"},
			},
		},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"pki/worker": {"write"},
	})
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "ignored"},
	}, priv)
	must.NoError(t, err)
	resp, err := r.Write(caller, "pki/worker", map[string][]byte{"csr": csrDER})
	must.NoError(t, err)
	must.StrContains(t, string(resp.Content), "BEGIN CERTIFICATE")
	must.EqOp(t, "application/x-pem-file", resp.ContentType)
}

func TestWritePKIMissingCSR(t *testing.T) {
	cfg := &config.Config{
		CAs: map[string]*config.CA{"identity": {Name: "identity"}},
		PKIs: map[string]*config.PKI{
			"worker": {
				Name:        "worker",
				CARef:       "identity",
				TTL:         time.Hour,
				ExtKeyUsage: []string{"client_auth"},
			},
		},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"pki/worker": {"write"},
	})
	_, err := r.Write(caller, "pki/worker", nil)
	must.ErrorContains(t, err, "csr")
}

func TestUnknownKind(t *testing.T) {
	cfg := &config.Config{}
	r, caller := newTestResolver(t, cfg, map[string][]string{"ghost/*": {"read"}})
	_, err := r.Read(caller, "ghost/foo")
	must.Error(t, err)
}

// writeTempTemplate writes a template body to a tempdir and returns its path.
func writeTempTemplate(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "tpl")
	must.NoError(t, os.WriteFile(p, []byte(body), 0o644))
	return p
}

func TestReadTemplate(t *testing.T) {
	src := writeTempTemplate(t, "dc=${var.datacenter} key=${secret.gossip_key}\n")
	cfg := &config.Config{
		Vars:    map[string]*config.Var{"datacenter": {Name: "datacenter", Value: "dc1"}},
		Secrets: map[string]*config.Secret{"gossip_key": {Name: "gossip_key", Length: 32, Encoding: "hex"}},
		Templates: map[string]*config.Template{
			"setup": {Name: "setup", Source: src},
		},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"template/setup":    {"read"},
		"var/datacenter":    {"read"},
		"secret/gossip_key": {"read"},
	})
	resp, err := r.Read(caller, "template/setup")
	must.NoError(t, err)
	must.StrContains(t, string(resp.Content), "dc=dc1 key=")
	must.EqOp(t, "text/plain", resp.ContentType)
}

func TestReadTemplateDeniedInnerPath(t *testing.T) {
	// Caller has read on template/setup but not on the var it references.
	src := writeTempTemplate(t, "dc=${var.datacenter}\n")
	cfg := &config.Config{
		Vars:      map[string]*config.Var{"datacenter": {Name: "datacenter", Value: "dc1"}},
		Templates: map[string]*config.Template{"setup": {Name: "setup", Source: src}},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"template/setup": {"read"},
	})
	_, err := r.Read(caller, "template/setup")
	must.ErrorContains(t, err, "permission denied")
}

func TestReadTemplateRejectsWriteKinds(t *testing.T) {
	// Templates must not cause side effects; pki/jwt references are rejected.
	src := writeTempTemplate(t, "cert=${pki.worker}\n")
	cfg := &config.Config{
		Templates: map[string]*config.Template{"setup": {Name: "setup", Source: src}},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"template/setup": {"read"},
		"pki/*":          {"write"},
	})
	_, err := r.Read(caller, "template/setup")
	must.ErrorContains(t, err, "unsupported reference")
}

func TestReadTemplateUnknownName(t *testing.T) {
	cfg := &config.Config{Templates: map[string]*config.Template{}}
	r, caller := newTestResolver(t, cfg, map[string][]string{"template/*": {"read"}})
	_, err := r.Read(caller, "template/missing")
	must.ErrorContains(t, err, "not found")
}

// tokenTestConfig returns a config with an hmac attestor and a "worker"
// identity that accepts it. ikm used by newTestResolver is 32 * 0x42.
func tokenTestConfig() *config.Config {
	return &config.Config{
		Attestors: map[string]*config.Attestor{
			"hmac": {Kind: "hmac", Window: 30 * time.Minute},
		},
		Identities: map[string]*config.Identity{
			"worker": {Name: "worker", Attestors: []string{"hmac"}},
		},
	}
}

func TestWriteToken(t *testing.T) {
	cfg := tokenTestConfig()
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"token/worker": {"write"},
	})
	resp, err := r.Write(caller, "token/worker", nil)
	must.NoError(t, err)
	must.EqOp(t, "text/plain", resp.ContentType)
	must.EqOp(t, uint32((30 * time.Minute).Seconds()), resp.TTLSeconds)

	// The minted token must verify against the same ikm/window/scope.
	ikm := bytes.Repeat([]byte{0x42}, 32)
	must.True(t, token.Verify(ikm, string(resp.Content), time.Now(), 30*time.Minute, "worker"))
}

func TestWriteTokenPolicyDenied(t *testing.T) {
	cfg := tokenTestConfig()
	// Policy grants write on token/other, not token/worker.
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"token/other": {"write"},
	})
	_, err := r.Write(caller, "token/worker", nil)
	must.ErrorContains(t, err, "permission denied")
}

func TestWriteTokenUnknownIdentity(t *testing.T) {
	cfg := tokenTestConfig()
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"token/*": {"write"},
	})
	_, err := r.Write(caller, "token/ghost", nil)
	must.ErrorContains(t, err, "not found")
}

func TestWriteTokenIdentityRejectsHMAC(t *testing.T) {
	// Identity exists but does not list hmac among its attestors.
	cfg := &config.Config{
		Attestors: map[string]*config.Attestor{
			"hmac": {Kind: "hmac", Window: 30 * time.Minute},
		},
		Identities: map[string]*config.Identity{
			"worker": {Name: "worker", Attestors: []string{"tpm"}},
		},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"token/*": {"write"},
	})
	_, err := r.Write(caller, "token/worker", nil)
	must.ErrorContains(t, err, "does not accept the hmac attestor")
}

func TestWriteTokenNoHMACAttestor(t *testing.T) {
	// hmac attestor not configured at all.
	cfg := &config.Config{
		Identities: map[string]*config.Identity{
			"worker": {Name: "worker", Attestors: []string{"hmac"}},
		},
	}
	r, caller := newTestResolver(t, cfg, map[string][]string{
		"token/*": {"write"},
	})
	_, err := r.Write(caller, "token/worker", nil)
	must.ErrorContains(t, err, "hmac attestor not configured")
}
