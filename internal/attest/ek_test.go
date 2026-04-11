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

	"github.com/shoenig/test/must"
)

func TestLoadHashFile(t *testing.T) {
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hashes")
	content := "# EK hashes\nabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n\n# another\n1111111111111111111111111111111111111111111111111111111111111111\n"
	must.NoError(t, os.WriteFile(hashPath, []byte(content), 0600))

	hashes, err := loadHashFile(hashPath)
	must.NoError(t, err)
	must.MapLen(t, 2, hashes)
	must.MapContainsKey(t, hashes, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
}

func TestLoadHashFile_InvalidHex(t *testing.T) {
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hashes")
	must.NoError(t, os.WriteFile(hashPath, []byte("not-hex\n"), 0600))

	_, err := loadHashFile(hashPath)
	must.Error(t, err)
}

func TestLoadHashFile_WrongLength(t *testing.T) {
	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hashes")
	// Valid hex but not SHA-256 length (only 16 bytes / 32 hex chars).
	must.NoError(t, os.WriteFile(hashPath, []byte("abcdef0123456789abcdef0123456789\n"), 0600))

	_, err := loadHashFile(hashPath)
	must.Error(t, err)
}

func TestEKValidator_HashMatch(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(t, err)

	ekDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	h := sha256.Sum256(ekDER)
	hash := hex.EncodeToString(h[:])

	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hashes")
	must.NoError(t, os.WriteFile(hashPath, []byte(hash+"\n"), 0600))

	v, err := NewEKValidator("", hashPath)
	must.NoError(t, err)

	must.NoError(t, v.Validate(&key.PublicKey, nil))

	// Different key should fail.
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.Error(t, v.Validate(&key2.PublicKey, nil))
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
	must.NoError(t, err)
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
	must.NoError(t, err)
	ekCert, _ := x509.ParseCertificate(ekCertDER)

	// Write CA cert to directory as PEM.
	caDir := t.TempDir()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertDER})
	must.NoError(t, os.WriteFile(filepath.Join(caDir, "ca.pem"), caPEM, 0600))

	v, err := NewEKValidator(caDir, "")
	must.NoError(t, err)

	// Valid cert chain should pass.
	must.NoError(t, v.Validate(&ekKey.PublicKey, ekCert))

	// Cert without matching pubkey should fail.
	otherKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.Error(t, v.Validate(&otherKey.PublicKey, ekCert))

	// Nil cert with CA-only validator should fail.
	must.Error(t, v.Validate(&ekKey.PublicKey, nil))
}

func TestEKValidator_HashHotReload(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(t, err)

	ekDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	h := sha256.Sum256(ekDER)
	hash := hex.EncodeToString(h[:])

	dir := t.TempDir()
	hashPath := filepath.Join(dir, "hashes")

	// Start with an empty hash file — key should be rejected.
	must.NoError(t, os.WriteFile(hashPath, []byte("# empty\n"), 0600))
	v, err := NewEKValidator("", hashPath)
	must.NoError(t, err)
	must.Error(t, v.Validate(&key.PublicKey, nil))

	// Append hash — same validator should now accept without restart.
	f, err := os.OpenFile(hashPath, os.O_APPEND|os.O_WRONLY, 0600)
	must.NoError(t, err)
	_, err = f.WriteString(hash + "\n")
	must.NoError(t, err)
	must.NoError(t, f.Close())

	must.NoError(t, v.Validate(&key.PublicKey, nil))
}

func TestEKValidator_EmptyCADir(t *testing.T) {
	dir := t.TempDir()
	_, err := NewEKValidator(dir, "")
	must.Error(t, err)
}

func TestEKValidator_UnparseableCAFile(t *testing.T) {
	dir := t.TempDir()
	must.NoError(t, os.WriteFile(filepath.Join(dir, "garbage.txt"), []byte("not a cert"), 0600))
	_, err := NewEKValidator(dir, "")
	must.Error(t, err)
}
