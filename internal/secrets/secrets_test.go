package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
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

	secrets, err := Resolve(testSpecs, path, testIKM)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(secrets) != 4 {
		t.Fatalf("expected 4 secrets, got %d", len(secrets))
	}

	// Verify base64 values are valid and correct length.
	for _, name := range []string{"gossip_key", "wg_psk"} {
		b, err := base64.StdEncoding.DecodeString(secrets[name])
		if err != nil {
			t.Errorf("%s: invalid base64: %v", name, err)
		}
		if len(b) != 32 {
			t.Errorf("%s: decoded length = %d, want 32", name, len(b))
		}
	}
	b, err := base64.StdEncoding.DecodeString(secrets["consul_encrypt"])
	if err != nil {
		t.Errorf("consul_encrypt: invalid base64: %v", err)
	}
	if len(b) != 16 {
		t.Errorf("consul_encrypt: decoded length = %d, want 16", len(b))
	}

	// Verify hex value.
	hb, err := hex.DecodeString(secrets["token"])
	if err != nil {
		t.Errorf("token: invalid hex: %v", err)
	}
	if len(hb) != 16 {
		t.Errorf("token: decoded length = %d, want 16", len(hb))
	}

	// File should exist.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("secrets file not created: %v", err)
	}
}

func TestResolveDeterministic(t *testing.T) {
	// Same IKM + same specs → identical secrets (the whole point of HKDF).
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	s1, err := Resolve(testSpecs, filepath.Join(dir1, "s.json"), testIKM)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Resolve(testSpecs, filepath.Join(dir2, "s.json"), testIKM)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range s1 {
		if s2[k] != v {
			t.Errorf("key %q differs: %q vs %q", k, v, s2[k])
		}
	}
}

func TestResolveDifferentIKM(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	ikm2 := make([]byte, 32)
	ikm2[0] = 1 // one bit different

	s1, err := Resolve(testSpecs, filepath.Join(dir1, "s.json"), testIKM)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Resolve(testSpecs, filepath.Join(dir2, "s.json"), ikm2)
	if err != nil {
		t.Fatal(err)
	}
	for k := range s1 {
		if s1[k] == s2[k] {
			t.Errorf("key %q should differ with different IKM", k)
		}
	}
}

func TestResolveLoadsExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	first, err := Resolve(testSpecs, path, testIKM)
	if err != nil {
		t.Fatalf("first resolve: %v", err)
	}

	// Second run loads from disk — values identical.
	second, err := Resolve(testSpecs, path, testIKM)
	if err != nil {
		t.Fatalf("second resolve: %v", err)
	}
	for k, v := range first {
		if second[k] != v {
			t.Errorf("key %q changed: %q vs %q", k, v, second[k])
		}
	}
}

func TestResolveEmptySpecs(t *testing.T) {
	secrets, err := Resolve(nil, "", nil)
	if err != nil {
		t.Fatalf("resolve nil specs: %v", err)
	}
	if secrets != nil {
		t.Errorf("expected nil, got %v", secrets)
	}
}

func TestResolveEmptyPath(t *testing.T) {
	// Empty path: derive fresh, no file written.
	secrets, err := Resolve(testSpecs, "", testIKM)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(secrets) != 4 {
		t.Fatalf("expected 4 secrets, got %d", len(secrets))
	}
}

func TestResolveMissingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.json")

	data, _ := json.Marshal(map[string]string{"gossip_key": "abc"})
	os.WriteFile(path, data, 0600)

	_, err := Resolve(testSpecs, path, testIKM)
	if err == nil {
		t.Fatal("expected error for missing key in secrets file")
	}
}

func TestResolveCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "deep", "secrets.json")

	secrets, err := Resolve(testSpecs, path, testIKM)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if len(secrets) != 4 {
		t.Fatalf("expected 4 secrets, got %d", len(secrets))
	}
}

func TestValidateIKM(t *testing.T) {
	if err := ValidateIKM(make([]byte, 32)); err != nil {
		t.Errorf("32 bytes should be valid: %v", err)
	}
	if err := ValidateIKM(make([]byte, 16)); err == nil {
		t.Error("16 bytes should be invalid")
	}
	if err := ValidateIKM(make([]byte, 0)); err == nil {
		t.Error("0 bytes should be invalid")
	}
}

func TestDeriveHMACKey(t *testing.T) {
	key, err := DeriveHMACKey(testIKM)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Deterministic: same IKM → same key.
	key2, _ := DeriveHMACKey(testIKM)
	if !bytes.Equal(key, key2) {
		t.Error("DeriveHMACKey should be deterministic")
	}

	// Different IKM → different key.
	otherIKM := make([]byte, 32)
	otherIKM[0] = 1
	key3, _ := DeriveHMACKey(otherIKM)
	if bytes.Equal(key, key3) {
		t.Error("different IKM should produce different HMAC key")
	}
}
