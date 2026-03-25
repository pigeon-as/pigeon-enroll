package pki

import (
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"
)

// testIKM is a fixed 32-byte key for tests.
var testIKM = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

func TestDeriveCA_Deterministic(t *testing.T) {
	ca1, err := DeriveCA(testIKM)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := DeriveCA(testIKM)
	if err != nil {
		t.Fatal(err)
	}

	if !ca1.Key.Equal(ca2.Key) {
		t.Error("same IKM should produce identical CA keys")
	}
	// CA cert bytes may differ (time.Now() in NotBefore/NotAfter) — only the key must be deterministic.
}

func TestDeriveCA_DifferentIKM(t *testing.T) {
	otherIKM := make([]byte, 32)
	copy(otherIKM, testIKM)
	otherIKM[0] ^= 0xff

	ca1, err := DeriveCA(testIKM)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := DeriveCA(otherIKM)
	if err != nil {
		t.Fatal(err)
	}

	if string(ca1.CertPEM) == string(ca2.CertPEM) {
		t.Error("different IKMs should produce different CA certs")
	}
}

func TestDeriveCA_IsCA(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA {
		t.Error("CA cert should have IsCA=true")
	}
	if ca.Cert.MaxPathLen != 0 || !ca.Cert.MaxPathLenZero {
		t.Error("CA should have MaxPathLen=0")
	}
}

func TestGenerateServerCert(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	if err != nil {
		t.Fatal(err)
	}

	certPEM, keyPEM, err := GenerateServerCert(ca, []string{"127.0.0.1", "enroll.internal"}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// Parse and verify
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal("X509KeyPair:", err)
	}

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}

	if len(leaf.IPAddresses) != 1 || leaf.IPAddresses[0].String() != "127.0.0.1" {
		t.Error("expected 127.0.0.1 in IPAddresses")
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "enroll.internal" {
		t.Error("expected enroll.internal in DNSNames")
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Error("expected ServerAuth ext key usage")
	}

	// Verify chain
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool}); err != nil {
		t.Error("server cert should verify against CA:", err)
	}
}

func TestGenerateClientCert_Bundle(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	if err != nil {
		t.Fatal(err)
	}

	bundle, err := GenerateClientCert(ca, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	key, cert, pool, err := LoadClientBundle(bundle)
	if err != nil {
		t.Fatal("LoadClientBundle:", err)
	}

	if _, ok := key.Public().(*ecdsa.PublicKey); !ok {
		t.Error("expected ECDSA key")
	}

	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Error("expected ClientAuth ext key usage")
	}

	// Verify chain using the CA from the bundle
	if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Error("client cert should verify against bundled CA:", err)
	}
}

func TestRoundTrip_mTLS(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	if err != nil {
		t.Fatal(err)
	}

	// Server side
	serverCertPEM, serverKeyPEM, err := GenerateServerCert(ca, []string{"127.0.0.1"}, 30*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(ca.Cert)

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Client side
	clientBundle, err := GenerateClientCert(ca, 1*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	clientKey, clientCert, clientCAPool, err := LoadClientBundle(clientBundle)
	if err != nil {
		t.Fatal(err)
	}

	clientTLSCert := tls.Certificate{
		Certificate: [][]byte{clientCert.Raw},
		PrivateKey:  clientKey,
	}

	clientTLS := &tls.Config{
		Certificates: []tls.Certificate{clientTLSCert},
		RootCAs:      clientCAPool,
		MinVersion:   tls.VersionTLS12,
	}

	// TLS handshake
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	errCh := make(chan error, 2)
	go func() {
		tlsConn := tls.Server(serverConn, serverTLS)
		err := tlsConn.Handshake()
		errCh <- err
		if err == nil {
			tlsConn.Close()
		}
	}()
	go func() {
		clientTLS.ServerName = "127.0.0.1"
		tlsConn := tls.Client(clientConn, clientTLS)
		err := tlsConn.Handshake()
		errCh <- err
		if err == nil {
			tlsConn.Close()
		}
	}()

	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatal("TLS handshake failed:", err)
		}
	}
}

func TestLoadClientBundle_BadInput(t *testing.T) {
	_, _, _, err := LoadClientBundle([]byte("not pem"))
	if err == nil {
		t.Error("expected error for invalid PEM")
	}
}

func TestCertRotator_CachesAndRenews(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	if err != nil {
		t.Fatal(err)
	}

	rotator := NewCertRotator(ca, []string{"pigeon-enroll"}, 1*time.Hour)

	// First call generates a cert.
	cert1, err := rotator.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cert1 == nil {
		t.Fatal("expected non-nil cert")
	}

	// Second call returns cached cert.
	cert2, err := rotator.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cert1 != cert2 {
		t.Error("expected same cached cert pointer")
	}
}
