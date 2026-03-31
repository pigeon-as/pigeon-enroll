package attest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadHashFile(t *testing.T) {
	// Create a temp hash file.
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hashes")
	content := "# EK hashes\nabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n\n# another\n1111111111111111111111111111111111111111111111111111111111111111\n"
	if err := os.WriteFile(hashPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	hashes, err := loadHashFile(hashPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(hashes))
	}
	if !hashes["abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"] {
		t.Fatal("expected hash not found")
	}
}

func TestLoadHashFile_InvalidHex(t *testing.T) {
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hashes")
	if err := os.WriteFile(hashPath, []byte("not-hex\n"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := loadHashFile(hashPath)
	if err == nil {
		t.Fatal("expected error for invalid hex")
	}
}

func TestEKValidator_HashMatch(t *testing.T) {
	// Generate a test key.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Compute the hash.
	ekDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	h := sha256.Sum256(ekDER)
	hash := hex.EncodeToString(h[:])

	// Create hash file.
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hashes")
	if err := os.WriteFile(hashPath, []byte(hash+"\n"), 0600); err != nil {
		t.Fatal(err)
	}

	v, err := NewEKValidator("", hashPath)
	if err != nil {
		t.Fatal(err)
	}

	// Should pass.
	if err := v.Validate(&key.PublicKey, nil); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	// Different key should fail.
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := v.Validate(&key2.PublicKey, nil); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestEKValidator_CertChain(t *testing.T) {
	// Create self-signed CA.
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test EK CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caCertDER)

	// Create EK cert signed by CA.
	ekKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ekTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test EK"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	ekCertDER, err := x509.CreateCertificate(rand.Reader, ekTemplate, caCert, &ekKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ekCert, _ := x509.ParseCertificate(ekCertDER)

	// Write CA cert to directory as PEM.
	caDir := t.TempDir()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	if err := os.WriteFile(filepath.Join(caDir, "ca.pem"), caPEM, 0600); err != nil {
		t.Fatal(err)
	}

	v, err := NewEKValidator(caDir, "")
	if err != nil {
		t.Fatal(err)
	}

	// Valid cert chain should pass.
	if err := v.Validate(&ekKey.PublicKey, ekCert); err != nil {
		t.Fatalf("expected valid, got: %v", err)
	}

	// Cert without matching pubkey should fail.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err := v.Validate(&otherKey.PublicKey, ekCert); err == nil {
		t.Fatal("expected error for mismatched pubkey")
	}

	// Nil cert with CA-only validator should fail.
	if err := v.Validate(&ekKey.PublicKey, nil); err == nil {
		t.Fatal("expected error for nil cert with CA-only validator")
	}
}

func TestEKValidator_EmptyCADir(t *testing.T) {
	dir := t.TempDir()
	_, err := NewEKValidator(dir, "")
	if err == nil {
		t.Fatal("expected error for empty CA directory")
	}
}

func TestEKValidator_UnparseableCAFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "garbage.txt"), []byte("not a cert"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := NewEKValidator(dir, "")
	if err == nil {
		t.Fatal("expected error for unparseable file in CA directory")
	}
}
