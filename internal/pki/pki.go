// Package pki derives a deterministic CA from the enrollment key and issues
// ephemeral TLS certificates for mTLS between the enrollment server and
// claim clients.
//
// The CA key is derived via HKDF-SHA256 from the enrollment key (IKM).
// Every server with the same enrollment key independently produces the same
// CA — no coordination needed.
//
// Leaf certificates (server + client) use ephemeral P-256 keys.
package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	hkdfInfoCAKey = "pigeon-enroll ca key v1"
)

// CA holds a deterministic CA certificate and private key.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     ed25519.PrivateKey
}

// DeriveCA produces a deterministic Ed25519 CA from the enrollment key.
// The CA certificate is self-signed with a 1-year validity.
func DeriveCA(ikm []byte) (*CA, error) {
	seed := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfoCAKey))
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("derive CA seed: %w", err)
	}
	key := ed25519.NewKeyFromSeed(seed)

	serialBytes := make([]byte, 16)
	// Deterministic serial from the seed so the CA cert is identical everywhere.
	h := sha256.Sum256(seed)
	copy(serialBytes, h[:16])
	serial := new(big.Int).SetBytes(serialBytes)

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pigeon-enroll CA"},
		NotBefore:    now.Add(-5 * time.Minute), // clock skew tolerance
		NotAfter:     now.Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("create CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	return &CA{Cert: cert, CertPEM: certPEM, Key: key}, nil
}

// GenerateServerCert creates a P-256 server certificate signed by the CA.
// The certificate is valid for 30 days and includes the provided IPs/hostnames.
func GenerateServerCert(ca *CA, hosts []string) (certPEM, keyPEM []byte, err error) {
	return generateLeaf(ca, hosts, x509.ExtKeyUsageServerAuth, 30*24*time.Hour)
}

// GenerateClientCert creates a P-256 client certificate bundle (cert + key + CA cert)
// signed by the CA. The certificate is valid for 1 hour.
// Returns the PEM bundle as a single byte slice.
func GenerateClientCert(ca *CA) ([]byte, error) {
	certPEM, keyPEM, err := generateLeaf(ca, nil, x509.ExtKeyUsageClientAuth, 1*time.Hour)
	if err != nil {
		return nil, err
	}
	// Bundle: client cert + client key + CA cert
	var bundle []byte
	bundle = append(bundle, certPEM...)
	bundle = append(bundle, keyPEM...)
	bundle = append(bundle, ca.CertPEM...)
	return bundle, nil
}

// LoadClientBundle parses a PEM bundle (client cert + key + CA cert) and returns
// a tls-ready certificate and CA pool.
func LoadClientBundle(bundlePEM []byte) (*ecdsa.PrivateKey, *x509.Certificate, *x509.CertPool, error) {
	var certDER, keyDER []byte
	pool := x509.NewCertPool()

	rest := bundlePEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if certDER == nil {
				certDER = block.Bytes
			} else {
				// Second cert is the CA
				pool.AddCert(mustParseCert(block.Bytes))
			}
		case "EC PRIVATE KEY":
			keyDER = block.Bytes
		}
	}

	if certDER == nil {
		return nil, nil, nil, fmt.Errorf("no certificate found in bundle")
	}
	if keyDER == nil {
		return nil, nil, nil, fmt.Errorf("no private key found in bundle")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse client cert: %w", err)
	}
	key, err := x509.ParseECPrivateKey(keyDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse client key: %w", err)
	}

	return key, cert, pool, nil
}

func generateLeaf(ca *CA, hosts []string, usage x509.ExtKeyUsage, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pigeon-enroll"},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf cert: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

func mustParseCert(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic("pki: invalid CA certificate in bundle: " + err.Error())
	}
	return cert
}
