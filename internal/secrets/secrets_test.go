package secrets

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"github.com/shoenig/test/must"
)

var testSpecs = []config.SecretSpec{
	{Name: "gossip_key", Length: 32, Encoding: "base64"},
	{Name: "wg_psk", Length: 32, Encoding: "base64"},
	{Name: "consul_encrypt", Length: 16, Encoding: "base64"},
	{Name: "token", Length: 16, Encoding: "hex"},
}

// Fixed IKM for deterministic test output.
var testIKM = make([]byte, 32) // all zeros — fine for tests

func TestResolveDerives(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	secrets, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, path, testIKM, "", "")
	must.NoError(t, err)
	must.MapLen(t, 4, secrets)

	// Verify base64 values are valid and correct length.
	for _, name := range []string{"gossip_key", "wg_psk"} {
		b, err := base64.StdEncoding.DecodeString(secrets[name])
		must.NoError(t, err, must.Sprintf("%s: invalid base64", name))
		must.EqOp(t, 32, len(b), must.Sprintf("%s: decoded length", name))
	}
	b, err := base64.StdEncoding.DecodeString(secrets["consul_encrypt"])
	must.NoError(t, err)
	must.EqOp(t, 16, len(b))

	// Verify hex value.
	hb, err := hex.DecodeString(secrets["token"])
	must.NoError(t, err)
	must.EqOp(t, 16, len(hb))

	// File should exist.
	_, err = os.Stat(path)
	must.NoError(t, err)
}

func TestResolveDeterministic(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	s1, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, filepath.Join(dir1, "s.json"), testIKM, "", "")
	must.NoError(t, err)
	s2, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, filepath.Join(dir2, "s.json"), testIKM, "", "")
	must.NoError(t, err)

	for k, v := range s1 {
		must.EqOp(t, v, s2[k], must.Sprintf("key %q differs", k))
	}
}

func TestResolveDifferentIKM(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	ikm2 := make([]byte, 32)
	ikm2[0] = 1 // one bit different

	s1, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, filepath.Join(dir1, "s.json"), testIKM, "", "")
	must.NoError(t, err)
	s2, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, filepath.Join(dir2, "s.json"), ikm2, "", "")
	must.NoError(t, err)

	for k := range s1 {
		must.NotEq(t, s1[k], s2[k], must.Sprintf("key %q should differ with different IKM", k))
	}
}

func TestResolveLoadsExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	first, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, path, testIKM, "", "")
	must.NoError(t, err)

	second, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, path, testIKM, "", "")
	must.NoError(t, err)

	for k, v := range first {
		must.EqOp(t, v, second[k], must.Sprintf("key %q changed", k))
	}
}

func TestResolveEmptySpecs(t *testing.T) {
	secrets, _, _, _, err := Resolve(nil, nil, nil, nil, nil, "", nil, "", "")
	must.NoError(t, err)
	must.Nil(t, secrets)
}

func TestResolveEmptyPath(t *testing.T) {
	secrets, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, "", testIKM, "", "")
	must.NoError(t, err)
	must.MapLen(t, 4, secrets)
}

func TestResolveMissingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	data, _ := json.Marshal(persistedFile{Secrets: map[string]string{"gossip_key": "abc"}})
	os.WriteFile(path, data, 0600)

	_, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, path, testIKM, "", "")
	must.Error(t, err)
}

func TestResolveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "deep", "secrets.json")

	secrets, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, path, testIKM, "", "")
	must.NoError(t, err)
	must.MapLen(t, 4, secrets)
}

func TestValidateIKM(t *testing.T) {
	must.NoError(t, ValidateIKM(make([]byte, 32)))
	must.Error(t, ValidateIKM(make([]byte, 16)))
	must.Error(t, ValidateIKM(make([]byte, 0)))
}

func TestDeriveHMACKey(t *testing.T) {
	key, err := DeriveHMACKey(testIKM)
	must.NoError(t, err)
	must.EqOp(t, 32, len(key))

	// Deterministic: same IKM → same key.
	key2, _ := DeriveHMACKey(testIKM)
	must.True(t, bytes.Equal(key, key2))

	// Different IKM → different key.
	otherIKM := make([]byte, 32)
	otherIKM[0] = 1
	key3, _ := DeriveHMACKey(otherIKM)
	must.False(t, bytes.Equal(key, key3))
}

func TestResolveRepersistsOnVarsChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	oldVars := map[string]string{"dc": "eu-west"}

	first, _, _, _, err := Resolve(testSpecs, nil, nil, nil, oldVars, path, testIKM, "", "")
	must.NoError(t, err)

	data, _ := os.ReadFile(path)
	var pf1 persistedFile
	json.Unmarshal(data, &pf1)
	must.EqOp(t, "eu-west", pf1.Vars["dc"])

	// Second resolve with updated vars.
	newVars := map[string]string{"dc": "us-east", "extra": "val"}
	second, _, _, _, err := Resolve(testSpecs, nil, nil, nil, newVars, path, testIKM, "", "")
	must.NoError(t, err)

	// Secrets should be unchanged.
	for k, v := range first {
		must.EqOp(t, v, second[k], must.Sprintf("secret %q changed", k))
	}

	// Vars on disk should be updated.
	data, _ = os.ReadFile(path)
	var pf2 persistedFile
	json.Unmarshal(data, &pf2)
	must.EqOp(t, "us-east", pf2.Vars["dc"])
	must.EqOp(t, "val", pf2.Vars["extra"])
}

func TestResolveSkipsRepersistWhenVarsUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")
	vars := map[string]string{"dc": "eu-west"}

	_, _, _, _, err := Resolve(testSpecs, nil, nil, nil, vars, path, testIKM, "", "")
	must.NoError(t, err)

	infoBefore, err := os.Stat(path)
	must.NoError(t, err)

	_, _, _, _, err = Resolve(testSpecs, nil, nil, nil, vars, path, testIKM, "", "")
	must.NoError(t, err)

	infoAfter, err := os.Stat(path)
	must.NoError(t, err)
	must.True(t, os.SameFile(infoBefore, infoAfter), must.Sprint("file was replaced despite vars being unchanged"))
}

var testCAs = []config.CASpec{
	{Name: "mesh"},
}

func TestResolveDerivesCA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	_, cas, _, _, err := Resolve(testSpecs, testCAs, nil, nil, nil, path, testIKM, "", "")
	must.NoError(t, err)
	must.MapLen(t, 1, cas)
	must.MapContainsKey(t, cas, "mesh")

	ca := cas["mesh"]
	must.NotEq(t, "", ca.CertPEM)
	must.NotEq(t, "", ca.PrivateKeyPEM)
}

func TestResolveCAValid(t *testing.T) {
	dir := t.TempDir()

	_, cas, _, _, err := Resolve(testSpecs, testCAs, nil, nil, nil, filepath.Join(dir, "s.json"), testIKM, "", "")
	must.NoError(t, err)
	ca := cas["mesh"]

	block, _ := pem.Decode([]byte(ca.PrivateKeyPEM))
	must.NotNil(t, block)
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	must.NoError(t, err)
	_, ok := parsed.(ed25519.PrivateKey)
	must.True(t, ok)

	certBlock, _ := pem.Decode([]byte(ca.CertPEM))
	must.NotNil(t, certBlock)
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	must.NoError(t, err)
	must.True(t, cert.IsCA)
}

func TestResolveCADeterministic(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	_, cas1, _, _, err := Resolve(testSpecs, testCAs, nil, nil, nil, filepath.Join(dir1, "s.json"), testIKM, "", "")
	must.NoError(t, err)
	_, cas2, _, _, err := Resolve(testSpecs, testCAs, nil, nil, nil, filepath.Join(dir2, "s.json"), testIKM, "", "")
	must.NoError(t, err)

	must.EqOp(t, cas1["mesh"].CertPEM, cas2["mesh"].CertPEM)
	must.EqOp(t, cas1["mesh"].PrivateKeyPEM, cas2["mesh"].PrivateKeyPEM)
}

func TestResolvePersistedCA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	_, first, _, _, err := Resolve(testSpecs, testCAs, nil, nil, nil, path, testIKM, "", "")
	must.NoError(t, err)

	_, second, _, _, err := Resolve(testSpecs, testCAs, nil, nil, nil, path, testIKM, "", "")
	must.NoError(t, err)

	must.EqOp(t, first["mesh"].CertPEM, second["mesh"].CertPEM)
	must.EqOp(t, first["mesh"].PrivateKeyPEM, second["mesh"].PrivateKeyPEM)
}

func TestResolveMissingCA(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	// Persist without CAs.
	if _, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, path, testIKM, "", ""); err != nil {
		t.Fatal(err)
	}

	// Now try to load with a CA requirement — should fail.
	_, _, _, _, err := Resolve(testSpecs, testCAs, nil, nil, nil, path, testIKM, "", "")
	if err == nil {
		t.Fatal("expected error for missing CA in persisted file")
	}
}

var testJWTs = []config.JWTSpec{
	{Name: "consul_auto_config", Issuer: "pigeon-enroll", Audience: "consul-auto-config"},
}

func TestResolveDerivesJWTKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	_, _, _, jwtKeys, err := Resolve(testSpecs, nil, nil, testJWTs, nil, path, testIKM, "", "")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(jwtKeys) != 1 {
		t.Fatalf("expected 1 JWT key, got %d", len(jwtKeys))
	}
	key, ok := jwtKeys["consul_auto_config"]
	if !ok {
		t.Fatal("missing JWT key 'consul_auto_config'")
	}
	if key.PublicKeyPEM == "" {
		t.Error("public_key_pem is empty")
	}
	if key.PrivateKey == nil {
		t.Error("private key is nil")
	}

	// Public key PEM should parse as valid Ed25519.
	block, _ := pem.Decode([]byte(key.PublicKeyPEM))
	if block == nil {
		t.Fatal("failed to decode public key PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Errorf("expected Ed25519 public key, got %T", pub)
	}
}

func TestResolvePersistedJWTKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	// First resolve: derive + persist.
	_, _, _, first, err := Resolve(testSpecs, nil, nil, testJWTs, nil, path, testIKM, "", "")
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}

	// Second resolve: load from disk.
	_, _, _, second, err := Resolve(testSpecs, nil, nil, testJWTs, nil, path, testIKM, "", "")
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}

	// Public key PEM should round-trip through persist (newline escaping/unescaping).
	if first["consul_auto_config"].PublicKeyPEM != second["consul_auto_config"].PublicKeyPEM {
		t.Errorf("public key PEM changed after round-trip:\n  first:  %q\n  second: %q",
			first["consul_auto_config"].PublicKeyPEM, second["consul_auto_config"].PublicKeyPEM)
	}

	// Private key is re-derived from IKM, should match.
	if !bytes.Equal(first["consul_auto_config"].PrivateKey, second["consul_auto_config"].PrivateKey) {
		t.Error("private key changed after round-trip")
	}
}

func TestResolveMissingJWTKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	// Persist without JWT keys.
	if _, _, _, _, err := Resolve(testSpecs, nil, nil, nil, nil, path, testIKM, "", ""); err != nil {
		t.Fatal(err)
	}

	// Now try to load with a JWT requirement — should fail.
	_, _, _, _, err := Resolve(testSpecs, nil, nil, testJWTs, nil, path, testIKM, "", "")
	if err == nil {
		t.Fatal("expected error for missing JWT key in persisted file")
	}
}

var testCertSpecs = []config.CertSpec{
	{Name: "mesh_server", CA: "mesh", Scope: []string{"server"}, TTL: 720 * time.Hour, CN: "server.local"},
}

func TestResolveReissuesExpiredCert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	// First resolve: derive secrets + CAs + certs.
	_, cas, certs1, _, err := Resolve(testSpecs, testCAs, testCertSpecs, nil, nil, path, testIKM, "server", "server.local")
	must.NoError(t, err)
	must.MapLen(t, 1, certs1)
	must.MapContainsKey(t, certs1, "mesh_server")

	// Tamper: replace the cert with an already-expired one.
	caEntry := cas["mesh"]
	pemData := append([]byte(caEntry.CertPEM), []byte(caEntry.PrivateKeyPEM)...)
	ca, err := pki.LoadCA(pemData)
	must.NoError(t, err)

	// Issue a cert that is already expired so the test does not rely on sleeping.
	expiredCert, expiredKey, err := pki.IssueCert(ca, "server.local", nil, nil, -time.Hour, false, true)
	must.NoError(t, err)

	// Read persisted file, replace cert entry, write back.
	data, err := os.ReadFile(path)
	must.NoError(t, err)
	var pf persistedFile
	must.NoError(t, json.Unmarshal(data, &pf))
	pf.Certs["mesh_server"] = CertEntry{CertPEM: string(expiredCert), KeyPEM: string(expiredKey)}
	data, err = json.Marshal(pf)
	must.NoError(t, err)
	must.NoError(t, os.WriteFile(path, data, 0600))

	// Second resolve: should detect expired cert and re-issue.
	_, _, certs2, _, err := Resolve(testSpecs, testCAs, testCertSpecs, nil, nil, path, testIKM, "server", "server.local")
	must.NoError(t, err)
	must.MapLen(t, 1, certs2)

	// Cert PEM should differ (new cert issued).
	must.NotEq(t, certs1["mesh_server"].CertPEM, certs2["mesh_server"].CertPEM)

	// New cert should not be expired.
	block, _ := pem.Decode([]byte(certs2["mesh_server"].CertPEM))
	must.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	must.NoError(t, err)
	must.True(t, cert.NotAfter.After(time.Now()))
}

func TestResolveReusesValidCachedCert(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	// First resolve: derive + persist.
	_, _, certs1, _, err := Resolve(testSpecs, testCAs, testCertSpecs, nil, nil, path, testIKM, "server", "server.local")
	must.NoError(t, err)
	must.MapLen(t, 1, certs1)

	// Second resolve: should reuse cached cert (not re-issue).
	_, _, certs2, _, err := Resolve(testSpecs, testCAs, testCertSpecs, nil, nil, path, testIKM, "server", "server.local")
	must.NoError(t, err)

	must.EqOp(t, certs1["mesh_server"].CertPEM, certs2["mesh_server"].CertPEM)
	must.EqOp(t, certs1["mesh_server"].KeyPEM, certs2["mesh_server"].KeyPEM)
}

func TestResolvePrunesStaleCerts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	// First resolve: derive + persist with a cert.
	_, _, certs1, _, err := Resolve(testSpecs, testCAs, testCertSpecs, nil, nil, path, testIKM, "server", "server.local")
	must.NoError(t, err)
	must.MapLen(t, 1, certs1)

	// Verify the cert is on disk.
	data, err := os.ReadFile(path)
	must.NoError(t, err)
	var pf1 persistedFile
	must.NoError(t, json.Unmarshal(data, &pf1))
	must.MapContainsKey(t, pf1.Certs, "mesh_server")

	// Second resolve: remove the cert spec from config (empty certs slice).
	// Vars unchanged, so only stale-detection triggers re-persist.
	_, _, certs2, _, err := Resolve(testSpecs, testCAs, nil, nil, nil, path, testIKM, "server", "server.local")
	must.NoError(t, err)
	must.Nil(t, certs2)

	// Verify stale cert was pruned from disk.
	data, err = os.ReadFile(path)
	must.NoError(t, err)
	var pf2 persistedFile
	must.NoError(t, json.Unmarshal(data, &pf2))
	must.MapEmpty(t, pf2.Certs)
}
