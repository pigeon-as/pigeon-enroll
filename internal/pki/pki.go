// Package pki derives a deterministic CA from the enrollment key and issues
// ephemeral TLS certificates for mTLS between the enrollment server and
// claim clients.
//
// The CA key is derived via HKDF-SHA256 from the enrollment key (IKM).
// Every server with the same enrollment key independently produces the same
// CA — no coordination needed.
//
// Ed25519 is used for all keys (CA and leaf). CA keys are deterministic via
// NewKeyFromSeed; leaf keys are ephemeral via GenerateKey.
package pki

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	hkdfInfoCAKey = "pigeon-enroll ca key v1"

	// hkdfInfoCAPrefix is the HKDF info prefix for named CA derivation.
	// Full info string: "pigeon-enroll ca <name> key v1".
	hkdfInfoCAPrefix = "pigeon-enroll ca "
	hkdfInfoCASuffix = " key v1"
)

// CA holds a deterministic CA certificate and private key.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     ed25519.PrivateKey
}

// DeriveCA produces a fully deterministic Ed25519 CA from the enrollment key.
// Every server with the same IKM produces byte-identical CA certs (fixed validity
// window, deterministic serial, Ed25519 deterministic signing).
func DeriveCA(ikm []byte) (*CA, error) {
	return deriveCA(ikm, hkdfInfoCAKey, "pigeon-enroll CA")
}

// NamedCA holds a deterministic Ed25519 CA certificate and private key in PEM format.
type NamedCA struct {
	CertPEM []byte
	KeyPEM  []byte
}

// DeriveNamedCA produces a deterministic Ed25519 CA from the enrollment key.
// The name is used in the HKDF info string for domain separation.
// Ed25519 key derivation and signing are both fully deterministic, so every
// server with the same IKM produces byte-identical CA certs.
func DeriveNamedCA(ikm []byte, name string) (*NamedCA, error) {
	info := hkdfInfoCAPrefix + name + hkdfInfoCASuffix
	ca, err := deriveCA(ikm, info, name)
	if err != nil {
		return nil, fmt.Errorf("derive CA for %q: %w", name, err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.Key)
	if err != nil {
		return nil, fmt.Errorf("marshal CA key for %q: %w", name, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &NamedCA{CertPEM: ca.CertPEM, KeyPEM: keyPEM}, nil
}

// deriveCA is the shared implementation for DeriveCA and DeriveNamedCA.
func deriveCA(ikm []byte, info string, cn string) (*CA, error) {
	seed := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, ikm, nil, []byte(info))
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("derive CA seed: %w", err)
	}
	key := ed25519.NewKeyFromSeed(seed)

	h := sha256.Sum256(seed)
	serial := new(big.Int).SetBytes(h[:16])

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
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

// GenerateCert creates an ephemeral Ed25519 certificate signed by the CA.
// EKU is inferred from inputs (mkcert approach):
//   - hosts non-empty → ServerAuth + ClientAuth (dual EKU)
//   - hosts empty → ClientAuth only
func GenerateCert(ca *CA, cn string, hosts []string, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	return generateLeaf(ca, cn, hosts, ttl)
}

// IssueCert creates an ephemeral Ed25519 leaf certificate with explicit EKU control.
// Used by cert blocks to auto-issue leaf certs during claim.
func IssueCert(ca *CA, cn string, ttl time.Duration, serverAuth, clientAuth bool) (certPEM, keyPEM []byte, err error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	var eku []x509.ExtKeyUsage
	if serverAuth {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	if clientAuth {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf cert: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf key: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// GenerateClientCert creates an ephemeral Ed25519 client certificate bundle
// (cert + key + CA cert) signed by the CA.
// Returns the PEM bundle as a single byte slice.
func GenerateClientCert(ca *CA, ttl time.Duration) ([]byte, error) {
	certPEM, keyPEM, err := generateLeaf(ca, "pigeon-enroll", nil, ttl)
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

// LoadCA parses a PEM file containing a CA certificate and private key and
// returns a CA struct suitable for GenerateCert. The PEM file must contain
// exactly one CERTIFICATE block (which must be a CA) and one PRIVATE KEY block.
func LoadCA(pemData []byte) (*CA, error) {
	var certDER, keyDER []byte
	var keyType string

	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			if certDER != nil {
				return nil, fmt.Errorf("multiple certificates in CA file")
			}
			certDER = block.Bytes
		case "PRIVATE KEY", "EC PRIVATE KEY":
			if keyDER != nil {
				return nil, fmt.Errorf("multiple private keys in CA file")
			}
			keyDER = block.Bytes
			keyType = block.Type
		}
	}

	if certDER == nil {
		return nil, fmt.Errorf("no certificate found in CA file")
	}
	if keyDER == nil {
		return nil, fmt.Errorf("no private key found in CA file")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse CA cert: %w", err)
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("certificate is not a CA")
	}

	signer, err := parsePrivateKey(keyDER, keyType)
	if err != nil {
		return nil, fmt.Errorf("parse CA key: %w", err)
	}

	edKey, ok := signer.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("CA key must be Ed25519, got %T", signer)
	}

	// Verify cert and key form a matching pair.
	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok || !certPub.Equal(edKey.Public()) {
		return nil, fmt.Errorf("CA certificate and private key do not match")
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	return &CA{Cert: cert, CertPEM: certPEM, Key: edKey}, nil
}

// LoadClientBundle parses a PEM bundle (client cert + key + CA cert) and returns
// a tls-ready private key, certificate, and CA pool.
// Accepts PKCS#8 ("PRIVATE KEY") and SEC1 ("EC PRIVATE KEY") key encodings.
func LoadClientBundle(bundlePEM []byte) (crypto.Signer, *x509.Certificate, *x509.CertPool, error) {
	var certDER, keyDER []byte
	var keyType string
	var hasCA bool
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
				caCert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, nil, nil, fmt.Errorf("parse CA cert in bundle: %w", err)
				}
				pool.AddCert(caCert)
				hasCA = true
			}
		case "PRIVATE KEY", "EC PRIVATE KEY":
			keyDER = block.Bytes
			keyType = block.Type
		}
	}

	if certDER == nil {
		return nil, nil, nil, fmt.Errorf("no certificate found in bundle")
	}
	if keyDER == nil {
		return nil, nil, nil, fmt.Errorf("no private key found in bundle")
	}
	if !hasCA {
		return nil, nil, nil, fmt.Errorf("no CA certificate found in bundle")
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse client cert: %w", err)
	}

	key, err := parsePrivateKey(keyDER, keyType)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("parse client key: %w", err)
	}

	return key, cert, pool, nil
}

// parsePrivateKey parses a DER-encoded private key. Tries PKCS#8 first for
// "PRIVATE KEY" blocks, SEC1 for "EC PRIVATE KEY" blocks.
func parsePrivateKey(der []byte, pemType string) (crypto.Signer, error) {
	if pemType == "PRIVATE KEY" {
		parsed, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		s, ok := parsed.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, not a signer", parsed)
		}
		return s, nil
	}
	// SEC1 (EC PRIVATE KEY)
	key, err := x509.ParseECPrivateKey(der)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func generateLeaf(ca *CA, cn string, hosts []string, validity time.Duration) (certPEM, keyPEM []byte, err error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}

	// Infer EKU from inputs: SANs present → server+client, otherwise client-only.
	eku := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	if len(hosts) > 0 {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  eku,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("sign leaf cert: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal leaf key: %w", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// CertRotator lazily generates and caches a server TLS certificate,
// regenerating it at 50% of its lifetime. Implements tls.Config.GetCertificate.
type CertRotator struct {
	ca    *CA
	hosts []string
	ttl   time.Duration

	mu      sync.Mutex
	cached  *tls.Certificate
	expires time.Time
}

// NewCertRotator returns a rotator that issues server certs with the given TTL.
func NewCertRotator(ca *CA, hosts []string, ttl time.Duration) *CertRotator {
	return &CertRotator{ca: ca, hosts: hosts, ttl: ttl}
}

// GetCertificate returns a cached server cert, regenerating when past 50% lifetime.
func (r *CertRotator) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cached != nil && time.Now().Before(r.expires) {
		return r.cached, nil
	}

	certPEM, keyPEM, err := GenerateCert(r.ca, "pigeon-enroll", r.hosts, r.ttl)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	r.cached = &tlsCert
	r.expires = time.Now().Add(r.ttl / 2) // renew at 50% lifetime
	return r.cached, nil
}
