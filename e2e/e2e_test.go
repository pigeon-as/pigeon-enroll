//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

const (
	testAddr = "127.0.0.1:19200"
	testURL  = "http://" + testAddr
)

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

// run executes pigeon-enroll with the given args, logs the command,
// and returns stdout+stderr. Fails the test on error.
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

// enrollmentKey generates a random 32-byte enrollment key, writes it to a
// temp file with mode 0600, and returns the file path.
func enrollmentKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	must.NoError(t, err)
	path := filepath.Join(t.TempDir(), "enrollment-key")
	must.NoError(t, os.WriteFile(path, []byte(hex.EncodeToString(key)), 0600))
	return path
}

// writeFile writes content to a temp file and returns its path.
func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	must.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

// startServer starts pigeon-enroll server with --skip-tls, waits for the
// health endpoint, and registers cleanup to send SIGTERM.
func startServer(t *testing.T, cfgPath string) {
	t.Helper()
	cmd := exec.Command(binary, "server", "-config="+cfgPath, "-log-level=debug", "-skip-tls")
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
			cmd.Process.Kill()
			<-done
		}
	})

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(testURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("server not healthy after 10s")
}

// claimResult is the JSON structure written by the claim CLI.
type claimResult struct {
	Secrets map[string]string            `json:"secrets"`
	Vars    map[string]string            `json:"vars"`
	CA      map[string]map[string]string `json:"ca"`
	Certs   map[string]map[string]string `json:"certs"`
	JWTs    map[string]string            `json:"jwts"`
	JWTKeys map[string]string            `json:"jwt_keys"`
}

// claim runs the claim CLI against testURL and returns the parsed result.
func claim(t *testing.T, token string, extra ...string) claimResult {
	t.Helper()
	output := filepath.Join(t.TempDir(), "claim.json")
	args := append([]string{"claim",
		"-url=" + testURL,
		"-token=" + token,
		"-output=" + output,
		"-insecure", "-skip-tpm",
	}, extra...)
	run(t, args...)

	data, err := os.ReadFile(output)
	must.NoError(t, err)
	var cr claimResult
	must.NoError(t, json.Unmarshal(data, &cr))
	return cr
}

// --- Tests ---

func TestBinary(t *testing.T) {
	must.FileExists(t, binary)
}

func TestVersion(t *testing.T) {
	output := run(t, "version")
	must.StrContains(t, output, "pigeon-enroll")
}

func TestServer_Health(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(testURL + "/health")
	must.NoError(t, err)
	defer resp.Body.Close()
	must.EqOp(t, 200, resp.StatusCode)
}

func TestGenerateToken(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"

secret "test" {
  length   = 16
  encoding = "hex"
}
`, testAddr, keyPath))

	token := run(t, "generate-token", "-config="+cfgPath)
	// Token = 32 hex nonce + 64 hex HMAC = 96 chars.
	must.EqOp(t, 96, len(token))
}

func TestClaim_Secrets(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "gossip_key" {
  length   = 32
  encoding = "base64"
}

secret "wg_psk" {
  length   = 32
  encoding = "base64"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	token := run(t, "generate-token", "-config="+cfgPath)
	result := claim(t, token)

	must.MapLen(t, 2, result.Secrets)
	must.MapContainsKey(t, result.Secrets, "gossip_key")
	must.MapContainsKey(t, result.Secrets, "wg_psk")
}

func TestClaim_ScopedSecrets(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "shared" {
  length   = 16
  encoding = "hex"
}

secret "server_only" {
  length   = 16
  encoding = "hex"
  scope    = "server"
}

secret "worker_only" {
  length   = 16
  encoding = "hex"
  scope    = "worker"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	// Worker scope: shared + worker_only.
	token := run(t, "generate-token", "-config="+cfgPath, "-scope=worker")
	result := claim(t, token, "-scope=worker")

	must.MapContainsKey(t, result.Secrets, "shared")
	must.MapContainsKey(t, result.Secrets, "worker_only")
	must.MapNotContainsKey(t, result.Secrets, "server_only")

	// Server scope: shared + server_only.
	token2 := run(t, "generate-token", "-config="+cfgPath, "-scope=server")
	result2 := claim(t, token2, "-scope=server")

	must.MapContainsKey(t, result2.Secrets, "shared")
	must.MapContainsKey(t, result2.Secrets, "server_only")
	must.MapNotContainsKey(t, result2.Secrets, "worker_only")
}

func TestClaim_Vars(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}

vars = {
  datacenter        = "eu-west-gra"
  consul_retry_join = "10.0.0.1,10.0.0.2"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	token := run(t, "generate-token", "-config="+cfgPath)
	result := claim(t, token)

	must.EqOp(t, "eu-west-gra", result.Vars["datacenter"])
	must.EqOp(t, "10.0.0.1,10.0.0.2", result.Vars["consul_retry_join"])
}

func TestClaim_ReplayRejected(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	token := run(t, "generate-token", "-config="+cfgPath)

	// First claim succeeds.
	_ = claim(t, token)

	// Second claim with same token fails.
	cmd := exec.Command(binary, "claim",
		"-url="+testURL, "-token="+token,
		"-output="+filepath.Join(t.TempDir(), "replay.json"),
		"-insecure", "-skip-tpm",
	)
	b, err := cmd.CombinedOutput()
	must.Error(t, err)
	must.StrContains(t, string(b), "already used")
}

func TestClaim_InvalidToken(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	cmd := exec.Command(binary, "claim",
		"-url="+testURL, "-token=invalid-token",
		"-output="+filepath.Join(t.TempDir(), "bad.json"),
		"-insecure", "-skip-tpm",
	)
	b, err := cmd.CombinedOutput()
	must.Error(t, err)
	must.StrContains(t, string(b), "invalid")
}

func TestClaim_CA(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}

ca "enroll" {}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	token := run(t, "generate-token", "-config="+cfgPath)
	result := claim(t, token)

	must.MapContainsKey(t, result.CA, "enroll")
	must.StrContains(t, result.CA["enroll"]["cert_pem"], "BEGIN CERTIFICATE")
	// Unscoped CA — private key NOT returned.
	must.EqOp(t, "", result.CA["enroll"]["private_key_pem"])
}

func TestClaim_ScopedCA(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}

ca "enroll" {
  scope = ["server"]
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	// Matching scope — gets private key.
	token := run(t, "generate-token", "-config="+cfgPath, "-scope=server")
	result := claim(t, token, "-scope=server")
	must.StrContains(t, result.CA["enroll"]["private_key_pem"], "PRIVATE KEY")

	// Non-matching scope — no private key.
	token2 := run(t, "generate-token", "-config="+cfgPath, "-scope=worker")
	result2 := claim(t, token2, "-scope=worker")
	must.EqOp(t, "", result2.CA["enroll"]["private_key_pem"])
}

func TestClaim_Cert(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}

ca "enroll" {}

cert "node" {
  ca          = "enroll"
  scope       = ["worker"]
  ttl         = "24h"
  client_auth = true
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	// Matching scope + subject — gets leaf cert.
	token := run(t, "generate-token", "-config="+cfgPath, "-scope=worker")
	result := claim(t, token, "-scope=worker", "-subject=worker-01.dc1")

	must.MapContainsKey(t, result.Certs, "node")
	must.StrContains(t, result.Certs["node"]["cert_pem"], "BEGIN CERTIFICATE")
	must.StrContains(t, result.Certs["node"]["key_pem"], "PRIVATE KEY")

	// Non-matching scope — no cert.
	token2 := run(t, "generate-token", "-config="+cfgPath, "-scope=server")
	result2 := claim(t, token2, "-scope=server", "-subject=server-01")
	must.MapEmpty(t, result2.Certs)
}

func TestClaim_JWT(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}

jwt "consul_auto_config" {
  issuer   = "pigeon-enroll"
  audience = "consul-auto-config"
  ttl      = "24h"
  scope    = "worker"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	// Matching scope — gets JWT.
	token := run(t, "generate-token", "-config="+cfgPath, "-scope=worker")
	result := claim(t, token, "-scope=worker", "-subject=worker-01.dc1")

	must.MapContainsKey(t, result.JWTs, "consul_auto_config")
	parts := strings.Split(result.JWTs["consul_auto_config"], ".")
	must.SliceLen(t, 3, parts)

	// Public key always returned.
	must.MapContainsKey(t, result.JWTKeys, "consul_auto_config")
	must.StrContains(t, result.JWTKeys["consul_auto_config"], "PUBLIC KEY")

	// Non-matching scope — no JWT, but still gets public key.
	token2 := run(t, "generate-token", "-config="+cfgPath, "-scope=server")
	result2 := claim(t, token2, "-scope=server", "-subject=server-01")
	must.MapEmpty(t, result2.JWTs)
	must.MapContainsKey(t, result2.JWTKeys, "consul_auto_config")
}

func TestClaim_Deterministic(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"

secret "key" {
  length   = 32
  encoding = "base64"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces")))

	startServer(t, cfgPath)

	token1 := run(t, "generate-token", "-config="+cfgPath)
	result1 := claim(t, token1)

	token2 := run(t, "generate-token", "-config="+cfgPath)
	result2 := claim(t, token2)

	must.EqOp(t, result1.Secrets["key"], result2.Secrets["key"])
}

func TestServer_SecretsPersisted(t *testing.T) {
	keyPath := enrollmentKey(t)
	secretsPath := filepath.Join(t.TempDir(), "secrets.json")
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"
nonce_path   = "%s"
secrets_path = "%s"

secret "test" {
  length   = 16
  encoding = "hex"
}
`, testAddr, keyPath, filepath.Join(t.TempDir(), "nonces"), secretsPath))

	startServer(t, cfgPath)

	// secrets_path should have been written on startup.
	data, err := os.ReadFile(secretsPath)
	must.NoError(t, err, must.Sprint("secrets file should be written on startup"))

	var persisted struct {
		Secrets map[string]string `json:"secrets"`
	}
	must.NoError(t, json.Unmarshal(data, &persisted))
	must.MapContainsKey(t, persisted.Secrets, "test")
}

func TestRender_File(t *testing.T) {
	dir := t.TempDir()

	varsPath := filepath.Join(dir, "vars.json")
	must.NoError(t, os.WriteFile(varsPath,
		[]byte(`{"secrets":{"gossip":"mysecret"},"vars":{"dc":"gra"}}`), 0644))

	tplPath := filepath.Join(dir, "consul.hcl.tpl")
	must.NoError(t, os.WriteFile(tplPath,
		[]byte("encrypt = \"${secrets.gossip}\"\ndatacenter = \"${vars.dc}\""), 0644))

	destPath := filepath.Join(dir, "consul.hcl")
	renderCfgPath := filepath.Join(dir, "render.hcl")
	must.NoError(t, os.WriteFile(renderCfgPath, []byte(fmt.Sprintf(`
template {
  source      = %q
  destination = %q
}
`, tplPath, destPath)), 0644))

	run(t, "render", "-config="+renderCfgPath, "-vars="+varsPath)

	must.FileContains(t, destPath, `encrypt = "mysecret"`)
	must.FileContains(t, destPath, `datacenter = "gra"`)
}

func TestRender_InlineContent(t *testing.T) {
	dir := t.TempDir()

	varsPath := filepath.Join(dir, "vars.json")
	must.NoError(t, os.WriteFile(varsPath, []byte(`{"secrets":{"key":"val123"}}`), 0644))

	destPath := filepath.Join(dir, "out.txt")
	renderCfgPath := filepath.Join(dir, "render.hcl")
	must.NoError(t, os.WriteFile(renderCfgPath, []byte(fmt.Sprintf(`
template {
  content     = "key=$${secrets.key}"
  destination = %q
}
`, destPath)), 0644))

	run(t, "render", "-config="+renderCfgPath, "-vars="+varsPath)

	must.FileContains(t, destPath, "key=val123")
}

func TestGenerateCert(t *testing.T) {
	keyPath := enrollmentKey(t)
	cfgPath := writeFile(t, "enroll.hcl", fmt.Sprintf(`
listen       = "%s"
key_path     = "%s"
token_window = "30m"

secret "test" {
  length   = 16
  encoding = "hex"
}
`, testAddr, keyPath))

	bundlePath := filepath.Join(t.TempDir(), "bundle.pem")
	run(t, "generate-cert",
		"-config="+cfgPath,
		"-bundle="+bundlePath,
		"-cn=test-node",
		"-ttl=1h",
	)

	must.FileContains(t, bundlePath, "BEGIN CERTIFICATE")
	must.FileContains(t, bundlePath, "PRIVATE KEY")
}
