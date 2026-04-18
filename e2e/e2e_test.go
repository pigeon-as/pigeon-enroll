//go:build e2e

// Package e2e exercises pigeon-enroll end-to-end (Decision 65).
package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shoenig/test/must"

	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
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

// run executes pigeon-enroll and fails the test on non-zero exit.
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

// runExpectErr executes pigeon-enroll and returns combined output; fails if
// the command succeeded.
func runExpectErr(t *testing.T, args ...string) string {
	t.Helper()
	t.Logf("RUN (expect-err) '%s %s'", binary, strings.Join(args, " "))
	cmd := exec.Command(binary, args...)
	b, err := cmd.CombinedOutput()
	must.Error(t, err)
	return string(b)
}

// randomIKM returns 32 random bytes and writes them to a file at mode 0600.
func randomIKM(t *testing.T) ([]byte, string) {
	t.Helper()
	ikm := make([]byte, 32)
	_, err := rand.Read(ikm)
	must.NoError(t, err)
	keyPath := filepath.Join(t.TempDir(), "enrollment-key")
	must.NoError(t, os.WriteFile(keyPath, ikm, 0o600))
	return ikm, keyPath
}

// writeIdentityCA derives the "identity" CA cert and writes its PEM to a
// temp file for clients to use as -ca.
func writeIdentityCA(t *testing.T, ikm []byte) string {
	t.Helper()
	ca, err := pki.DeriveCAByName(ikm, "identity")
	must.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	must.NoError(t, os.WriteFile(path, ca.CertPEM, 0o644))
	return path
}

// writeConfig writes a minimal Decision 65 HCL config exercising every
// primitive the tests need.
func writeConfig(t *testing.T, listen, keyPath string) string {
	t.Helper()
	cfg := fmt.Sprintf(`
trust_domain   = "pigeon.test"
listen         = "%s"
identity_ttl   = "1h"
renew_fraction = 0.5

attestor "hmac" {
  key_path = "%s"
  window   = "30m"
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

policy "worker" {
  path "var/domain"         { capabilities = ["read"] }
  path "secret/gossip_key"  { capabilities = ["read"] }
  path "ca/mesh"            { capabilities = ["read"] }
  path "pki/mesh_worker"    { capabilities = ["write"] }
}

identity "worker" {
  attestors = [attestor.hmac]
  pki       = pki.identity_worker
  policy    = policy.worker
}
`, listen, filepath.ToSlash(keyPath))
	path := filepath.Join(t.TempDir(), "enroll.hcl")
	must.NoError(t, os.WriteFile(path, []byte(cfg), 0o644))
	return path
}

// startServer launches pigeon-enroll server as a subprocess and waits for
// the TCP listener. A SIGTERM cleanup is registered.
func startServer(t *testing.T, cfgPath, keyPath, addr string) {
	t.Helper()
	noncePath := filepath.Join(t.TempDir(), "nonces")
	cmd := exec.Command(binary,
		"server",
		"-config="+cfgPath,
		"-key-path="+keyPath,
		"-nonce-store="+noncePath,
		"-hosts=127.0.0.1",
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

// register runs `pigeon-enroll register` with an HMAC token and returns the
// identity output directory.
func register(t *testing.T, ikm []byte, caPath, subject string) string {
	t.Helper()
	tok := token.Generate(ikm, time.Now(), 30*time.Minute, "worker")
	outDir := filepath.Join(t.TempDir(), "identity")
	must.NoError(t, os.MkdirAll(outDir, 0o755))
	run(t,
		"register",
		"-addr="+testAddr,
		"-ca="+caPath,
		"-identity=worker",
		"-subject="+subject,
		"-token="+tok,
		"-identity-dir="+outDir,
		"-skip-tpm",
	)
	return outDir
}

// parseCert decodes the first CERTIFICATE block in pemBytes.
func parseCert(t *testing.T, pemBytes []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	must.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	must.NoError(t, err)
	return cert
}

// --- Tests ---

func TestBinary(t *testing.T) {
	must.FileExists(t, binary)
}

func TestVersion(t *testing.T) {
	must.StrContains(t, run(t, "version"), "pigeon-enroll")
}

func TestRegister_IssuesIdentityCert(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr, keyPath)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, ikm, caPath, "worker-01")

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
	cfgPath := writeConfig(t, testAddr, keyPath)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, ikm, caPath, "worker-01")

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
	cfgPath := writeConfig(t, testAddr, keyPath)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, ikm, caPath, "worker-01")

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "worker-01"}},
		priv)
	must.NoError(t, err)
	csrPath := filepath.Join(t.TempDir(), "csr.der")
	must.NoError(t, os.WriteFile(csrPath, csrDER, 0o644))

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

	meshCA, err := pki.DeriveCAByName(ikm, "mesh")
	must.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(meshCA.Cert)
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
	cfgPath := writeConfig(t, testAddr, keyPath)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, ikm, caPath, "worker-01")

	out := runExpectErr(t, "read",
		"-addr="+testAddr, "-ca="+caPath, "-identity-dir="+outDir,
		"ca/identity",
	)
	must.StrContains(t, strings.ToLower(out), "permission")
}

func TestRenew_IssuesLaterExpiry(t *testing.T) {
	ikm, keyPath := randomIKM(t)
	caPath := writeIdentityCA(t, ikm)
	cfgPath := writeConfig(t, testAddr, keyPath)
	startServer(t, cfgPath, keyPath, testAddr)

	outDir := register(t, ikm, caPath, "worker-01")

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
