package attestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/nonce"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	enrollv1 "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
)

func newHMACAttestor(t *testing.T) (*hmacAttestor, []byte, *nonce.Store) {
	t.Helper()
	dir := t.TempDir()
	key := []byte("0123456789abcdef0123456789abcdef")
	keyPath := filepath.Join(dir, "key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	ns, err := nonce.New(time.Hour, filepath.Join(dir, "nonces"))
	if err != nil {
		t.Fatal(err)
	}
	at, err := newHMAC(&config.Attestor{KeyPath: keyPath, Window: 30 * time.Minute}, ns)
	if err != nil {
		t.Fatal(err)
	}
	return at, key, ns
}

func TestHMACAttestor_Valid(t *testing.T) {
	at, key, _ := newHMACAttestor(t)
	tok := token.Generate(key, time.Now(), 30*time.Minute, "worker")
	ev := Evidence{HMAC: &enrollv1.HMACEvidence{Token: tok, Scope: "worker"}}
	res, err := at.Verify(context.Background(), ev, "subj", nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Subject != "hmac:worker" {
		t.Fatalf("subject = %q", res.Subject)
	}
}

func TestHMACAttestor_InvalidToken(t *testing.T) {
	at, _, _ := newHMACAttestor(t)
	ev := Evidence{HMAC: &enrollv1.HMACEvidence{Token: "not-a-token", Scope: "worker"}}
	if _, err := at.Verify(context.Background(), ev, "subj", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestHMACAttestor_WrongScope(t *testing.T) {
	at, key, _ := newHMACAttestor(t)
	tok := token.Generate(key, time.Now(), 30*time.Minute, "worker")
	ev := Evidence{HMAC: &enrollv1.HMACEvidence{Token: tok, Scope: "server"}}
	if _, err := at.Verify(context.Background(), ev, "subj", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestHMACAttestor_Replay(t *testing.T) {
	at, key, _ := newHMACAttestor(t)
	tok := token.Generate(key, time.Now(), 30*time.Minute, "worker")
	ev := Evidence{HMAC: &enrollv1.HMACEvidence{Token: tok, Scope: "worker"}}
	if _, err := at.Verify(context.Background(), ev, "subj", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := at.Verify(context.Background(), ev, "subj", nil); err == nil {
		t.Fatal("expected replay error")
	}
}

func TestHMACAttestor_Missing(t *testing.T) {
	at, _, _ := newHMACAttestor(t)
	if _, err := at.Verify(context.Background(), Evidence{}, "subj", nil); err == nil {
		t.Fatal("expected error")
	}
}

// ---- bootstrap_cert ----

func genCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, priv
}

func genLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func TestBootstrapCertAttestor_Valid(t *testing.T) {
	ca, caKey := genCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	at := newBootstrapCert(pool)
	leaf := genLeaf(t, ca, caKey, "worker-01")
	res, err := at.Verify(context.Background(), Evidence{PeerCerts: []*x509.Certificate{leaf}}, "subj", nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Subject != "cert:worker-01" {
		t.Fatalf("subject = %q", res.Subject)
	}
}

func TestBootstrapCertAttestor_UnknownCA(t *testing.T) {
	rogueCA, rogueKey := genCA(t)
	at := newBootstrapCert(x509.NewCertPool()) // empty pool
	leaf := genLeaf(t, rogueCA, rogueKey, "rogue")
	if _, err := at.Verify(context.Background(), Evidence{PeerCerts: []*x509.Certificate{leaf}}, "subj", nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestBootstrapCertAttestor_NoCert(t *testing.T) {
	at := newBootstrapCert(x509.NewCertPool())
	if _, err := at.Verify(context.Background(), Evidence{}, "subj", nil); err == nil {
		t.Fatal("expected error")
	}
}
