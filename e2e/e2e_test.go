//go:build e2e

// Package e2e exercises pigeon-enroll as a black box via the built CLI.
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shoenig/test/must"
	"golang.org/x/crypto/hkdf"
)

const testAddr = "127.0.0.1:19200"

var binary string

func TestMain(m *testing.M) {
	wd, _ := os.Getwd()
	binary = filepath.Join(wd, "..", "build", "pigeon-enroll")
	if _, err := os.Stat(binary); err != nil {
		if p, err := exec.LookPath("pigeon-enroll"); err == nil {
			binary = p
		}
	}
	os.Exit(m.Run())
}

func run(t *testing.T, args ...string) string {
	t.Helper()
	t.Logf("RUN '%s %s'", binary, strings.Join(args, " "))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, args...)
	b, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(b))
	if err != nil {
		t.Log("ERR:", err)
		t.Log("OUT:", output)
		t.FailNow()
	}
	return output
}

func runExpectErr(t *testing.T, args ...string) string {
	t.Helper()
	t.Logf("RUN (expect-err) '%s %s'", binary, strings.Join(args, " "))
	cmd := exec.Command(binary, args...)
	b, err := cmd.CombinedOutput()
	must.Error(t, err)
	return string(b)
}

func randomIKM(t *testing.T) ([]byte, string) {
	t.Helper()
	ikm := make([]byte, 32)
	_, err := rand.Read(ikm)
	must.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "enrollment-key")
	must.NoError(t, os.WriteFile(keyPath, []byte(hex.EncodeToString(ikm)), 0o600))
	return ikm, keyPath
}

// deriveCAPEM reimplements pigeon-enroll's HKDF-Ed25519 CA derivation; a
// divergence between this and the server breaks the tests on purpose.
func deriveCAPEM(t *testing.T, ikm []byte, name string) []byte {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, ikm, nil, []byte("pigeon-enroll ca "+name+" key v1"))
	_, err := io.ReadFull(r, seed)
	must.NoError(t, err)
	key := ed25519.NewKeyFromSeed(seed)

	td := &url.URL{Scheme: "spiffe", Host: "pigeon.test"}
	h := sha256.Sum256(seed)
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(h[:16]),
		Subject:               pkix.Name{CommonName: name},
		URIs:                  []*url.URL{td},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	must.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
}

func writeIdentityCA(t *testing.T, ikm []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	must.NoError(t, os.WriteFile(path, deriveCAPEM(t, ikm, "identity"), 0o644))
	return path
}

func writeConfig(t *testing.T, listen string) string {
	t.Helper()
	cfg := fmt.Sprintf(`
trust_domain   = "pigeon.test"
listen         = "%s"
renew_fraction = 0.5

attestor "hmac" {
  window = "30m"
}

ca "identity" { cn = "pigeon identity CA" }
ca "mesh"     { cn = "pigeon mesh CA" }

secret "gossip_key" {
  length   = 32
  encoding = "hex"
}

var "domain" { value = "infra.pigeon.test" }

pki "identity_worker" {
  ca            = ca.identity
  ttl           = "1h"
  ext_key_usage = ["client_auth"]
}

pki "mesh_worker" {
  ca            = ca.mesh
  ttl           = "1h"
  ext_key_usage = ["client_auth", "server_auth"]
  dns_sans      = ["${subject}"]
}

pki "forbidden" {
  ca            = ca.mesh
  ttl           = "1h"
  ext_key_usage = ["client_auth"]
}

policy "worker" {
  path "var/domain"        { capabilities = ["read"] }
  path "secret/gossip_key" { capabilities = ["read"] }
  path "ca/mesh"           { capabilities = ["read"] }
  path "pki/mesh_worker"   { capabilities = ["write"] }
}

identity "worker" {
  attestors = [attestor.hmac]
  pki       = pki.identity_worker
  policy    = policy.worker
}

identity "control_plane" {
  attestors = [attestor.hmac]
  pki       = pki.identity_worker
  policy    = policy.worker
}
`, listen)
	path := filepath.Join(t.TempDir(), "enroll.hcl")
	must.NoError(t, os.WriteFile(path, []byte(cfg), 0o644))
	return path
}

func startServer(t *testing.T, cfgPath, keyPath, addr string) {
	t.Helper()
	noncePath := filepath.Join(t.TempDir(), "nonces")
	bindingsPath := filepath.Join(t.TempDir(), "bindings")
	cmd := exec.Command(binary,
		"server",
		"-config="+cfgPath,
		"-key-path="+keyPath,
		"-nonce-store="+noncePath,
		"-bindings-store="+bindingsPath,
		"-log-level=debug",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must.NoError(t, cmd.Start())

	t.Cleanup(func() {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	must.Unreachable(t, must.Sprintf("server at %s did not become ready in 10s", addr))
}

func mintToken(t *testing.T, keyPath, cfgPath, identity string) string {
	t.Helper()
	t.Logf("RUN '%s generate-token -identity=%s -key-path=%s'",
		binary, identity, keyPath)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "generate-token",
		"-config="+cfgPath,
		"-identity="+identity,
		"-key-path="+keyPath,
	)
	out, err := cmd.Output()
	must.NoError(t, err)
	return strings.TrimSpace(string(out))
}

func register(t *testing.T, keyPath, cfgPath, caPath, identity, subject string) string {
	t.Helper()
	tok := mintToken(t, keyPath, cfgPath, identity)
	outDir := filepath.Join(t.TempDir(), "identity")
	must.NoError(t, os.MkdirAll(outDir, 0o755))
	run(t, "register",
		"-addr="+testAddr,
		"-ca="+caPath,
		"-identity="+identity,
		"-subject="+subject,
		"-token="+tok,
		"-identity-dir="+outDir,
		"-skip-tpm",
	)
	return outDir
}

func parseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	must.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	must.NoError(t, err)
	return cert
}

func newCSR(t *testing.T, cn string) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}},
		priv,
	)
	must.NoError(t, err)
	path := filepath.Join(t.TempDir(), "csr.der")
	must.NoError(t, os.WriteFile(path, csrDER, 0o644))
	return path
}

func TestBinary(t *testing.T) {
	must.FileExists(t, binary)
}

func TestVersion(t *testing.T) {
	must.StrContains(t, run(t, "version"), "pigeon-enroll")
}

func TestRegister_IssuesIdentityCert(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, keyPath, cfgPath, caPath, "worker", "worker-01")

	must.FileExists(t, filepath.Join(outDir, "cert.pem"))
	must.FileExists(t, filepath.Join(outDir, "key.pem"))
	must.FileExists(t, filepath.Join(outDir, "ca.pem"))
	must.FileExists(t, filepath.Join(outDir, "bundle.pem"))

	certPEM, err := os.ReadFile(filepath.Join(outDir, "cert.pem"))
	must.NoError(t, err)
	cert := parseCert(t, certPEM)
	must.EqOp(t, "worker-01", cert.Subject.CommonName)
	must.SliceContains(t, cert.Subject.OrganizationalUnit, "worker")
	must.SliceContains(t, cert.Subject.Organization, "worker")
}

func TestRead_VarAndSecret(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, keyPath, cfgPath, caPath, "worker", "worker-01")

	got := run(t, "read",
		"-addr="+testAddr, "-ca="+caPath, "-identity-dir="+outDir,
		"var/domain",
	)
	must.EqOp(t, "infra.pigeon.test", got)

	got = run(t, "read",
		"-addr="+testAddr, "-ca="+caPath, "-identity-dir="+outDir,
		"secret/gossip_key",
	)
	must.EqOp(t, 64, len(got))
}

func TestWrite_PKIRole(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, keyPath, cfgPath, caPath, "worker", "worker-01")

	csrPath := newCSR(t, "worker-01")
	outCert := filepath.Join(t.TempDir(), "signed.pem")
	run(t, "write",
		"-addr="+testAddr, "-ca="+caPath, "-identity-dir="+outDir,
		"-o="+outCert,
		"pki/mesh_worker",
		"csr=@"+csrPath,
	)

	certPEM, err := os.ReadFile(outCert)
	must.NoError(t, err)
	cert := parseCert(t, certPEM)

	meshCABlock, _ := pem.Decode(deriveCAPEM(t, ikm, "mesh"))
	must.NotNil(t, meshCABlock)
	meshCA, err := x509.ParseCertificate(meshCABlock.Bytes)
	must.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(meshCA)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	must.NoError(t, err)
	must.EqOp(t, "worker-01", cert.Subject.CommonName)
}

func TestRead_DeniedPath(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, keyPath, cfgPath, caPath, "worker", "worker-01")

	out := runExpectErr(t, "read",
		"-addr="+testAddr, "-ca="+caPath, "-identity-dir="+outDir,
		"ca/identity",
	)
	must.StrContains(t, strings.ToLower(out), "permission")
}

func TestRenew_IssuesLaterExpiry(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, keyPath, cfgPath, caPath, "worker", "worker-01")

	oldPEM, err := os.ReadFile(filepath.Join(outDir, "cert.pem"))
	must.NoError(t, err)
	oldCert := parseCert(t, oldPEM)

	time.Sleep(1100 * time.Millisecond)

	run(t, "renew",
		"-addr="+testAddr, "-ca="+caPath, "-identity-dir="+outDir,
	)

	newPEM, err := os.ReadFile(filepath.Join(outDir, "cert.pem"))
	must.NoError(t, err)
	must.NotEq(t, string(oldPEM), string(newPEM))
	newCert := parseCert(t, newPEM)
	must.True(t, newCert.NotAfter.After(oldCert.NotAfter))
}

func TestGenerateToken_RejectsUnknownIdentity(t *testing.T) {
	_, keyPath := randomIKM(t)
	cfgPath := writeConfig(t, "")

	out := runExpectErr(t, "generate-token",
		"-config="+cfgPath,
		"-identity=ghost",
		"-key-path="+keyPath,
	)
	must.StrContains(t, strings.ToLower(out), "ghost")
}

func TestNonceReplay(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	tok := mintToken(t, keyPath, cfgPath, "worker")

	outDir1 := filepath.Join(t.TempDir(), "identity-1")
	must.NoError(t, os.MkdirAll(outDir1, 0o755))
	run(t, "register",
		"-addr="+testAddr, "-ca="+caPath,
		"-identity=worker", "-subject=worker-01",
		"-token="+tok,
		"-identity-dir="+outDir1, "-skip-tpm",
	)

	outDir2 := filepath.Join(t.TempDir(), "identity-2")
	must.NoError(t, os.MkdirAll(outDir2, 0o755))
	out := runExpectErr(t, "register",
		"-addr="+testAddr, "-ca="+caPath,
		"-identity=worker", "-subject=worker-02",
		"-token="+tok,
		"-identity-dir="+outDir2, "-skip-tpm",
	)
	must.StrContains(t, strings.ToLower(out), "consumed")
}

func TestScopeBinding(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	workerTok := mintToken(t, keyPath, cfgPath, "worker")

	outDir := filepath.Join(t.TempDir(), "identity")
	must.NoError(t, os.MkdirAll(outDir, 0o755))
	out := runExpectErr(t, "register",
		"-addr="+testAddr, "-ca="+caPath,
		"-identity=control_plane", "-subject=cp-01",
		"-token="+workerTok,
		"-identity-dir="+outDir, "-skip-tpm",
	)
	must.StrContains(t, strings.ToLower(out), "hmac")
}

func TestCSR_SubjectOverridden(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, keyPath, cfgPath, caPath, "worker", "worker-01")

	csrPath := newCSR(t, "admin")
	outCert := filepath.Join(t.TempDir(), "signed.pem")
	run(t, "write",
		"-addr="+testAddr, "-ca="+caPath, "-identity-dir="+outDir,
		"-o="+outCert,
		"pki/mesh_worker",
		"csr=@"+csrPath,
	)

	certPEM, err := os.ReadFile(outCert)
	must.NoError(t, err)
	cert := parseCert(t, certPEM)

	must.EqOp(t, "worker-01", cert.Subject.CommonName)
	must.NotEq(t, "admin", cert.Subject.CommonName)
}

func TestWrite_DeniedPath(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, keyPath, cfgPath, caPath, "worker", "worker-01")

	csrPath := newCSR(t, "worker-01")
	out := runExpectErr(t, "write",
		"-addr="+testAddr, "-ca="+caPath, "-identity-dir="+outDir,
		"pki/forbidden",
		"csr=@"+csrPath,
	)
	must.StrContains(t, strings.ToLower(out), "permission")
}
