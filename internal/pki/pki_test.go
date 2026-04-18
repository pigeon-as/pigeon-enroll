package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

var testIKM = []byte{
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
}

func buildCSR(t *testing.T, priv ed25519.PrivateKey) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, priv)
	must.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	must.NoError(t, err)
	return csr
}

func TestDeriveCA_Deterministic(t *testing.T) {
	ca1, err := DeriveCA(testIKM, "identity")
	must.NoError(t, err)
	ca2, err := DeriveCA(testIKM, "identity")
	must.NoError(t, err)
	must.EqOp(t, string(ca1.CertPEM), string(ca2.CertPEM))
	must.True(t, ca1.Key.Equal(ca2.Key))
}

func TestDeriveCA_DifferentNames(t *testing.T) {
	ca1, err := DeriveCA(testIKM, "identity")
	must.NoError(t, err)
	ca2, err := DeriveCA(testIKM, "mesh")
	must.NoError(t, err)
	must.NotEq(t, string(ca1.CertPEM), string(ca2.CertPEM))
	must.False(t, ca1.Key.Equal(ca2.Key))
}

func TestDeriveCA_DifferentIKM(t *testing.T) {
	otherIKM := make([]byte, 32)
	copy(otherIKM, testIKM)
	otherIKM[0] ^= 0xff

	ca1, err := DeriveCA(testIKM, "identity")
	must.NoError(t, err)
	ca2, err := DeriveCA(otherIKM, "identity")
	must.NoError(t, err)
	must.NotEq(t, string(ca1.CertPEM), string(ca2.CertPEM))
}

func TestDeriveCA_IsCA(t *testing.T) {
	ca, err := DeriveCA(testIKM, "mesh")
	must.NoError(t, err)
	must.True(t, ca.Cert.IsCA)
	must.EqOp(t, "mesh", ca.Cert.Subject.CommonName)
	must.EqOp(t, 0, ca.Cert.MaxPathLen)
	must.True(t, ca.Cert.MaxPathLenZero)
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
	pub1, _, err := DeriveJWTKey(testIKM, "a")
	must.NoError(t, err)
	pub2, _, err := DeriveJWTKey(testIKM, "b")
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

func TestIssueIdentityCert_SubjectShape(t *testing.T) {
	ca, err := DeriveCA(testIKM, "identity")
	must.NoError(t, err)

	certPEM, _, err := IssueIdentityCert(
		ca, "worker-01", "worker", "worker",
		[]string{"worker-01.mesh.internal"}, nil,
		time.Hour, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	must.NoError(t, err)

	block, _ := pem.Decode(certPEM)
	must.NotNil(t, block)
	cert, err := x509.ParseCertificate(block.Bytes)
	must.NoError(t, err)

	must.EqOp(t, "worker-01", cert.Subject.CommonName)
	must.SliceContains(t, cert.Subject.OrganizationalUnit, "worker")
	must.SliceContains(t, cert.Subject.Organization, "worker")

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	must.NoError(t, err)
}

func TestSignIdentityCSR_UsesCallerPublicKey(t *testing.T) {
	ca, err := DeriveCA(testIKM, "identity")
	must.NoError(t, err)
	callerPub, callerPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(t, err)
	csr := buildCSR(t, callerPriv)

	certPEM, err := SignIdentityCSR(
		ca, csr, "worker-01", "worker", "worker",
		nil, nil,
		time.Hour, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	must.NoError(t, err)

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	must.NoError(t, err)
	must.True(t, callerPub.Equal(cert.PublicKey))
	must.SliceContains(t, cert.Subject.OrganizationalUnit, "worker")
}

func TestSignCSR_SubjectAndSANs(t *testing.T) {
	ca, err := DeriveCA(testIKM, "mesh")
	must.NoError(t, err)
	callerPub, callerPriv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(t, err)
	csr := buildCSR(t, callerPriv)

	certPEM, err := SignCSR(
		ca, csr,
		"worker-01",
		[]string{"mesh.internal"}, []net.IP{net.ParseIP("10.0.0.1")},
		time.Hour, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	)
	must.NoError(t, err)

	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	must.NoError(t, err)

	must.EqOp(t, "worker-01", cert.Subject.CommonName)
	must.SliceLen(t, 1, cert.DNSNames)
	must.EqOp(t, "mesh.internal", cert.DNSNames[0])
	must.SliceLen(t, 1, cert.IPAddresses)
	must.EqOp(t, "10.0.0.1", cert.IPAddresses[0].String())
	must.True(t, callerPub.Equal(cert.PublicKey))

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	_, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	must.NoError(t, err)
}

func TestParseExtKeyUsage(t *testing.T) {
	eku, err := ParseExtKeyUsage([]string{"client_auth", "server_auth"})
	must.NoError(t, err)
	must.SliceLen(t, 2, eku)
	must.EqOp(t, x509.ExtKeyUsageClientAuth, eku[0])
	must.EqOp(t, x509.ExtKeyUsageServerAuth, eku[1])

	_, err = ParseExtKeyUsage([]string{"bogus"})
	must.Error(t, err)
}

func TestCertRotator_CachesUntilExpiry(t *testing.T) {
	ca, err := DeriveCA(testIKM, "identity")
	must.NoError(t, err)

	r := NewCertRotator(ca, []string{"127.0.0.1", "enroll.internal"}, time.Hour)
	cert1, err := r.GetCertificate(nil)
	must.NoError(t, err)
	cert2, err := r.GetCertificate(nil)
	must.NoError(t, err)
	// Same *tls.Certificate returned (cached).
	must.Eq(t, cert1, cert2)

	leaf, err := x509.ParseCertificate(cert1.Certificate[0])
	must.NoError(t, err)
	must.EqOp(t, "pigeon-enroll", leaf.Subject.CommonName)
	must.SliceContains(t, leaf.DNSNames, "enroll.internal")
	must.SliceContains(t, leafIPStrings(leaf), "127.0.0.1")

	hasServer, hasClient := false, false
	for _, eku := range leaf.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			hasServer = true
		case x509.ExtKeyUsageClientAuth:
			hasClient = true
		}
	}
	must.True(t, hasServer)
	must.True(t, hasClient)
}

func TestCertRotator_IsUsableViaTLS(t *testing.T) {
	ca, err := DeriveCA(testIKM, "identity")
	must.NoError(t, err)
	r := NewCertRotator(ca, []string{"127.0.0.1"}, time.Hour)
	tc := &tls.Config{GetCertificate: r.GetCertificate}
	cert, err := tc.GetCertificate(nil)
	must.NoError(t, err)
	must.NotNil(t, cert)
}

func leafIPStrings(cert *x509.Certificate) []string {
	out := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}
