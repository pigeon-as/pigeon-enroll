package pki

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/shoenig/test/must"
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
	must.NoError(t, err)
	ca2, err := DeriveCA(testIKM)
	must.NoError(t, err)

	must.EqOp(t, string(ca1.CertPEM), string(ca2.CertPEM))
	must.True(t, ca1.Key.Equal(ca2.Key))
}

func TestDeriveCA_DifferentIKM(t *testing.T) {
	otherIKM := make([]byte, 32)
	copy(otherIKM, testIKM)
	otherIKM[0] ^= 0xff

	ca1, err := DeriveCA(testIKM)
	must.NoError(t, err)
	ca2, err := DeriveCA(otherIKM)
	must.NoError(t, err)

	must.NotEq(t, string(ca1.CertPEM), string(ca2.CertPEM))
}

func TestDeriveCA_IsCA(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)
	must.True(t, ca.Cert.IsCA)
	must.EqOp(t, 0, ca.Cert.MaxPathLen)
	must.True(t, ca.Cert.MaxPathLenZero)
}

func TestGenerateServerCert(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)

	certPEM, keyPEM, err := GenerateCert(ca, "enroll.internal", []string{"127.0.0.1", "enroll.internal"}, 30*24*time.Hour)
	must.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	must.NoError(t, err)

	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	must.NoError(t, err)

	must.SliceLen(t, 1, leaf.IPAddresses)
	must.EqOp(t, "127.0.0.1", leaf.IPAddresses[0].String())
	must.SliceLen(t, 1, leaf.DNSNames)
	must.EqOp(t, "enroll.internal", leaf.DNSNames[0])
	must.EqOp(t, "enroll.internal", leaf.Subject.CommonName)

	// With SANs: dual EKU (ServerAuth + ClientAuth)
	must.SliceLen(t, 2, leaf.ExtKeyUsage)
	must.EqOp(t, x509.ExtKeyUsageServerAuth, leaf.ExtKeyUsage[0])
	must.EqOp(t, x509.ExtKeyUsageClientAuth, leaf.ExtKeyUsage[1])

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool})
	must.NoError(t, err)
}

func TestGenerateClientCert_Bundle(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)

	bundle, err := GenerateClientCert(ca, 1*time.Hour)
	must.NoError(t, err)

	key, cert, pool, err := LoadClientBundle(bundle)
	must.NoError(t, err)

	_, ok := key.Public().(ed25519.PublicKey)
	must.True(t, ok)

	must.SliceLen(t, 1, cert.ExtKeyUsage)
	must.EqOp(t, x509.ExtKeyUsageClientAuth, cert.ExtKeyUsage[0])

	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	must.NoError(t, err)
}

func TestRoundTrip_mTLS(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)

	// Server side
	serverCertPEM, serverKeyPEM, err := GenerateCert(ca, "pigeon-enroll", []string{"127.0.0.1"}, 30*24*time.Hour)
	must.NoError(t, err)
	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	must.NoError(t, err)

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
	must.NoError(t, err)
	clientKey, clientCert, clientCAPool, err := LoadClientBundle(clientBundle)
	must.NoError(t, err)

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
		must.NoError(t, <-errCh)
	}
}

func TestLoadClientBundle_BadInput(t *testing.T) {
	_, _, _, err := LoadClientBundle([]byte("not pem"))
	must.Error(t, err)
}

func TestCertRotator_CachesAndRenews(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)

	rotator := NewCertRotator(ca, []string{"pigeon-enroll"}, 1*time.Hour)

	cert1, err := rotator.GetCertificate(nil)
	must.NoError(t, err)
	must.NotNil(t, cert1)

	cert2, err := rotator.GetCertificate(nil)
	must.NoError(t, err)
	must.EqOp(t, cert1, cert2, must.Sprint("expected same cached cert pointer"))
}

func TestGenerateClientCert_NoSANs(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)

	certPEM, keyPEM, err := GenerateCert(ca, "vault-agent", nil, 1*time.Hour)
	must.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	must.NoError(t, err)
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	must.NoError(t, err)

	must.EqOp(t, "vault-agent", leaf.Subject.CommonName)
	must.SliceLen(t, 1, leaf.ExtKeyUsage)
	must.EqOp(t, x509.ExtKeyUsageClientAuth, leaf.ExtKeyUsage[0])
	must.SliceLen(t, 0, leaf.IPAddresses)
	must.SliceLen(t, 0, leaf.DNSNames)

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	must.NoError(t, err)
}

func TestGenerateServerCert_CustomCN(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)

	certPEM, keyPEM, err := GenerateCert(ca, "pigeon", []string{"localhost", "10.0.0.1"}, 24*time.Hour)
	must.NoError(t, err)

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	must.NoError(t, err)
	leaf, err := x509.ParseCertificate(tlsCert.Certificate[0])
	must.NoError(t, err)

	must.EqOp(t, "pigeon", leaf.Subject.CommonName)
	must.SliceLen(t, 1, leaf.DNSNames)
	must.EqOp(t, "localhost", leaf.DNSNames[0])
	must.SliceLen(t, 1, leaf.IPAddresses)
	must.EqOp(t, "10.0.0.1", leaf.IPAddresses[0].String())

	hasServer, hasClient := false, false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServer = true
		}
		if eku == x509.ExtKeyUsageClientAuth {
			hasClient = true
		}
	}
	must.True(t, hasServer, must.Sprint("expected ServerAuth EKU"))
	must.True(t, hasClient, must.Sprint("expected ClientAuth EKU"))
}

func TestDeriveNamedCA_Deterministic(t *testing.T) {
	ca1, err := DeriveNamedCA(testIKM, "mesh")
	must.NoError(t, err)
	ca2, err := DeriveNamedCA(testIKM, "mesh")
	must.NoError(t, err)

	must.EqOp(t, string(ca1.CertPEM), string(ca2.CertPEM))
	must.EqOp(t, string(ca1.KeyPEM), string(ca2.KeyPEM))
}

func TestDeriveNamedCA_DifferentNames(t *testing.T) {
	ca1, err := DeriveNamedCA(testIKM, "mesh")
	must.NoError(t, err)
	ca2, err := DeriveNamedCA(testIKM, "other")
	must.NoError(t, err)

	must.NotEq(t, string(ca1.KeyPEM), string(ca2.KeyPEM))
}

func TestDeriveNamedCA_IsCA(t *testing.T) {
	ca, err := DeriveNamedCA(testIKM, "mesh")
	must.NoError(t, err)

	block, _ := pem.Decode(ca.CertPEM)
	must.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	must.NoError(t, err)
	must.True(t, cert.IsCA)
	must.EqOp(t, "mesh", cert.Subject.CommonName)
}

func TestLoadCA_RoundTrip(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)

	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	must.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	var bundle []byte
	bundle = append(bundle, ca.CertPEM...)
	bundle = append(bundle, keyPEM...)

	loaded, err := LoadCA(bundle)
	must.NoError(t, err)
	must.True(t, loaded.Cert.Equal(ca.Cert))
	must.True(t, loaded.Key.Equal(ca.Key))

	// Verify the loaded CA can sign certs.
	certPEM, _, err := GenerateCert(loaded, "test", []string{"localhost"}, time.Hour)
	must.NoError(t, err)
	block, _ := pem.Decode(certPEM)
	must.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	must.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(loaded.Cert)
	_, err = leaf.Verify(x509.VerifyOptions{Roots: pool})
	must.NoError(t, err)
}

func TestLoadCA_NotCA(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)
	certPEM, keyPEM, err := GenerateCert(ca, "leaf", nil, time.Hour)
	must.NoError(t, err)
	var bundle []byte
	bundle = append(bundle, certPEM...)
	bundle = append(bundle, keyPEM...)

	_, err = LoadCA(bundle)
	must.Error(t, err)
}

func TestLoadCA_MissingParts(t *testing.T) {
	ca, err := DeriveCA(testIKM)
	must.NoError(t, err)

	// Cert only — no key.
	_, err = LoadCA(ca.CertPEM)
	must.Error(t, err)

	// Key only — no cert.
	keyDER, _ := x509.MarshalPKCS8PrivateKey(ca.Key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	_, err = LoadCA(keyPEM)
	must.Error(t, err)
}

func TestLoadCA_MismatchedKeyAndCert(t *testing.T) {
	ca1, err := DeriveCA(testIKM)
	must.NoError(t, err)

	otherIKM := make([]byte, 32)
	copy(otherIKM, testIKM)
	otherIKM[0] ^= 0xff
	ca2, err := DeriveCA(otherIKM)
	must.NoError(t, err)

	keyDER, _ := x509.MarshalPKCS8PrivateKey(ca2.Key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	mixed := append(ca1.CertPEM, keyPEM...)

	_, err = LoadCA(mixed)
	must.Error(t, err)
	must.StrContains(t, err.Error(), "do not match")
}

func TestDeriveJWTKey_Deterministic(t *testing.T) {
	pub1, priv1, err := DeriveJWTKey(testIKM, "consul_auto_config")
	must.NoError(t, err)
	pub2, priv2, err := DeriveJWTKey(testIKM, "consul_auto_config")
	must.NoError(t, err)
	must.True(t, pub1.Equal(pub2))
	must.True(t, priv1.Equal(priv2))
}

func TestDeriveJWTKey_DifferentNames(t *testing.T) {
	pub1, _, err := DeriveJWTKey(testIKM, "key_a")
	must.NoError(t, err)
	pub2, _, err := DeriveJWTKey(testIKM, "key_b")
	must.NoError(t, err)
	must.False(t, pub1.Equal(pub2))
}

func TestDeriveJWTKey_SignVerify(t *testing.T) {
	pub, priv, err := DeriveJWTKey(testIKM, "test")
	must.NoError(t, err)
	msg := []byte("hello world")
	sig := ed25519.Sign(priv, msg)
	must.True(t, ed25519.Verify(pub, msg, sig))
}
