package attestor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/nonce"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	enrollv1 "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
	"github.com/shoenig/test/must"
)

func newHMACAttestor(t *testing.T) (*hmacAttestor, []byte, *nonce.Store) {
	t.Helper()
	dir := t.TempDir()
	ikm := []byte("0123456789abcdef0123456789abcdef")
	ns, err := nonce.New(time.Hour, filepath.Join(dir, "nonces"))
	must.NoError(t, err)
	at, err := newHMAC(&config.Attestor{Window: 30 * time.Minute}, ns, ikm)
	must.NoError(t, err)
	hmacKey, err := token.DeriveHMACKey(ikm)
	must.NoError(t, err)
	return at, hmacKey, ns
}

func TestHMACAttestor_Valid(t *testing.T) {
	at, key, _ := newHMACAttestor(t)
	tok := token.Generate(key, time.Now(), 30*time.Minute, "worker")
	ev := Evidence{HMAC: &enrollv1.HMACEvidence{Token: tok, Scope: "worker"}}
	res, err := at.Verify(context.Background(), ev, "subj", nil)
	must.NoError(t, err)
	must.Eq(t, "hmac:worker", res.Subject)
}

func TestHMACAttestor_InvalidToken(t *testing.T) {
	at, _, _ := newHMACAttestor(t)
	ev := Evidence{HMAC: &enrollv1.HMACEvidence{Token: "not-a-token", Scope: "worker"}}
	_, err := at.Verify(context.Background(), ev, "subj", nil)
	must.Error(t, err)
}

func TestHMACAttestor_WrongScope(t *testing.T) {
	at, key, _ := newHMACAttestor(t)
	tok := token.Generate(key, time.Now(), 30*time.Minute, "worker")
	ev := Evidence{HMAC: &enrollv1.HMACEvidence{Token: tok, Scope: "server"}}
	_, err := at.Verify(context.Background(), ev, "subj", nil)
	must.Error(t, err)
}

func TestHMACAttestor_Replay(t *testing.T) {
	at, key, _ := newHMACAttestor(t)
	tok := token.Generate(key, time.Now(), 30*time.Minute, "worker")
	ev := Evidence{HMAC: &enrollv1.HMACEvidence{Token: tok, Scope: "worker"}}
	_, err := at.Verify(context.Background(), ev, "subj", nil)
	must.NoError(t, err)
	_, err = at.Verify(context.Background(), ev, "subj", nil)
	must.Error(t, err)
}

func TestHMACAttestor_Missing(t *testing.T) {
	at, _, _ := newHMACAttestor(t)
	_, err := at.Verify(context.Background(), Evidence{}, "subj", nil)
	must.Error(t, err)
}

// ---- bootstrap_cert ----

func genCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(t, err)
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
	must.NoError(t, err)
	ca, err := x509.ParseCertificate(der)
	must.NoError(t, err)
	return ca, priv
}

func genLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, cn string) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &priv.PublicKey, caKey)
	must.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	must.NoError(t, err)
	return leaf
}

func TestBootstrapCertAttestor_Valid(t *testing.T) {
	ca, caKey := genCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	at := newBootstrapCert(pool)
	leaf := genLeaf(t, ca, caKey, "worker-01")
	res, err := at.Verify(context.Background(), Evidence{PeerCerts: []*x509.Certificate{leaf}}, "subj", nil)
	must.NoError(t, err)
	must.Eq(t, "cert:worker-01", res.Subject)
}

func TestBootstrapCertAttestor_UnknownCA(t *testing.T) {
	rogueCA, rogueKey := genCA(t)
	at := newBootstrapCert(x509.NewCertPool()) // empty pool
	leaf := genLeaf(t, rogueCA, rogueKey, "rogue")
	_, err := at.Verify(context.Background(), Evidence{PeerCerts: []*x509.Certificate{leaf}}, "subj", nil)
	must.Error(t, err)
}

func TestBootstrapCertAttestor_NoCert(t *testing.T) {
	at := newBootstrapCert(x509.NewCertPool())
	_, err := at.Verify(context.Background(), Evidence{}, "subj", nil)
	must.Error(t, err)
}
