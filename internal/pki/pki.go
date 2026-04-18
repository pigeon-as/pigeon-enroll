// Package pki derives a deterministic CA from the enrollment key and issues
// ephemeral TLS certificates for mTLS between the enrollment server and
// claim clients.
//
// Follows the Vault PKI secrets engine pattern: deterministic CA with
// ephemeral leaf certificate issuance. The CA key is derived via HKDF-SHA256
// from the enrollment key (IKM) with nil salt per RFC 5869 §3.1 (IKM is
// uniformly random). Every server with the same enrollment key independently
// produces the same CA — no coordination needed.
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
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

const (
	// Full CA info string: "pigeon-enroll ca <name> key v1".
	hkdfInfoCAPrefix = "pigeon-enroll ca "
	hkdfInfoCASuffix = " key v1"

	// Full JWT info string: "pigeon-enroll jwt <name> key v1".
	hkdfInfoJWTPrefix = "pigeon-enroll jwt "
	hkdfInfoJWTSuffix = " key v1"
)

// CA holds a deterministic CA certificate and private key.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     ed25519.PrivateKey
}

// DeriveCA returns a deterministic, signing-capable CA keyed to `name`.
// Every server with the same IKM produces byte-identical CA certs (fixed
// validity window, deterministic serial, Ed25519 deterministic signing).
//
// The CA cert carries a URI SAN `spiffe://<trustDomain>` per the SPIFFE
// X.509-SVID spec; clients verifying any leaf signed by this CA can read
// that SAN to learn the trust domain without needing an out-of-band config.
func DeriveCA(ikm []byte, trustDomain, name string) (*CA, error) {
	if trustDomain == "" {
		return nil, fmt.Errorf("trust domain is required")
	}
	seed := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfoCAPrefix+name+hkdfInfoCASuffix))
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, fmt.Errorf("derive CA seed: %w", err)
	}
	key := ed25519.NewKeyFromSeed(seed)

	td := &url.URL{Scheme: "spiffe", Host: trustDomain}
	h := sha256.Sum256(seed)
	tmpl := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(h[:16]),
		Subject:               pkix.Name{CommonName: name},
		URIs:                  []*url.URL{td},
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
	return &CA{
		Cert:    cert,
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		Key:     key,
	}, nil
}

// TrustDomainFromCA extracts the SPIFFE trust domain from a CA cert's URI
// SAN (`spiffe://<trust_domain>`). Returns an error if no SPIFFE URI SAN is
// present. Matches the SPIFFE X.509-SVID convention that any cert in a
// SPIFFE trust bundle carries the trust domain as a URI SAN.
func TrustDomainFromCA(cert *x509.Certificate) (string, error) {
	for _, u := range cert.URIs {
		if u.Scheme == "spiffe" && u.Host != "" {
			return u.Host, nil
		}
	}
	return "", fmt.Errorf("ca cert has no spiffe:// URI SAN")
}

// DeriveJWTKey produces a deterministic Ed25519 key pair from the enrollment
// key. The name is used in the HKDF info string for domain separation.
func DeriveJWTKey(ikm []byte, name string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	r := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfoJWTPrefix+name+hkdfInfoJWTSuffix))
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, fmt.Errorf("derive JWT key %q: %w", name, err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	return key.Public().(ed25519.PublicKey), key, nil
}

// IssueIdentityCert issues the pigeon-enroll identity cert. The caller's
// subject is encoded as CN=cn, OU=[policy], O=[identity]. Renew reads O to
// re-issue without re-attestation; Read/Write read OU to look up the
// capability policy. Keeping this one function authoritative means auditors
// only need to read it (and SignIdentityCSR below) to know what shape the
// identity cert has.
func IssueIdentityCert(ca *CA, cn, policyName, identityName string, dnsSANs []string, ipSANs []net.IP, ttl time.Duration, eku []x509.ExtKeyUsage) (certPEM, keyPEM []byte, err error) {
	return signLeaf(ca, identityCertTemplate(cn, policyName, identityName, dnsSANs, ipSANs, ttl, eku))
}

// SignIdentityCSR signs a caller-supplied CSR as the pigeon-enroll identity
// cert. Only the CSR's public key is used; Subject (CN/O/OU), SANs, EKU, and
// TTL are all server-controlled (SPIRE pattern). The CSR's self-signature
// is verified inside — callers pass the parsed request, not a bare pubkey,
// so proof-of-possession is impossible to accidentally skip.
func SignIdentityCSR(ca *CA, csr *x509.CertificateRequest, cn, policyName, identityName string, dnsSANs []string, ipSANs []net.IP, ttl time.Duration, eku []x509.ExtKeyUsage) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature: %w", err)
	}
	return signCSR(ca, csr.PublicKey, identityCertTemplate(cn, policyName, identityName, dnsSANs, ipSANs, ttl, eku))
}

// SignCSR signs a CSR with a server-controlled template. Only the public
// key is extracted from the CSR — subject, SANs, EKU, and validity are all
// set by the server. Same privilege-escalation protection as SignIdentityCSR,
// without the identity-shape (OU/O) encoding. The CSR's self-signature is
// verified inside.
func SignCSR(ca *CA, csr *x509.CertificateRequest, cn string, dnsSANs []string, ipSANs []net.IP, ttl time.Duration, eku []x509.ExtKeyUsage) ([]byte, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: cn},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: eku,
		DNSNames:    dnsSANs,
		IPAddresses: ipSANs,
	}
	return signCSR(ca, csr.PublicKey, tmpl)
}

// ParseExtKeyUsage converts a list of EKU name strings ("client_auth",
// "server_auth") to x509.ExtKeyUsage values. Unknown names return an error.
func ParseExtKeyUsage(names []string) ([]x509.ExtKeyUsage, error) {
	out := make([]x509.ExtKeyUsage, 0, len(names))
	for _, n := range names {
		switch n {
		case "client_auth":
			out = append(out, x509.ExtKeyUsageClientAuth)
		case "server_auth":
			out = append(out, x509.ExtKeyUsageServerAuth)
		default:
			return nil, fmt.Errorf("unknown ext_key_usage %q", n)
		}
	}
	return out, nil
}

// CertRotator lazily generates and caches a server TLS certificate,
// regenerating it at 50% of its lifetime. Implements tls.Config.GetCertificate.
//
// The leaf carries a single URI SAN `spiffe://<trustDomain>/<spiffePath>`
// (SPIFFE X.509-SVID). No DNS/IP SANs — clients verify by SPIFFE ID, not by
// hostname, so the server doesn't need to know how it's addressed.
type CertRotator struct {
	ca          *CA
	trustDomain string
	spiffePath  string
	ttl         time.Duration

	mu      sync.Mutex
	cached  *tls.Certificate
	expires time.Time
}

// NewCertRotator returns a rotator that issues server certs with the given
// TTL, carrying `spiffe://<trustDomain>/<spiffePath>` as URI SAN.
func NewCertRotator(ca *CA, trustDomain, spiffePath string, ttl time.Duration) *CertRotator {
	return &CertRotator{ca: ca, trustDomain: trustDomain, spiffePath: spiffePath, ttl: ttl}
}

// GetCertificate returns a cached server cert, regenerating when past 50% lifetime.
func (r *CertRotator) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.cached != nil && time.Now().Before(r.expires) {
		return r.cached, nil
	}

	id := &url.URL{Scheme: "spiffe", Host: r.trustDomain, Path: "/" + r.spiffePath}
	now := time.Now()
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: r.spiffePath},
		URIs:        []*url.URL{id},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(r.ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	certPEM, keyPEM, err := signLeaf(r.ca, tmpl)
	if err != nil {
		return nil, err
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	r.cached = &tlsCert
	r.expires = time.Now().Add(r.ttl / 2)
	return r.cached, nil
}

// identityCertTemplate builds the x509 template for an identity cert with
// subject CN=cn, OU=[policyName], O=[identityName].
func identityCertTemplate(cn, policyName, identityName string, dnsSANs []string, ipSANs []net.IP, ttl time.Duration, eku []x509.ExtKeyUsage) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		Subject: pkix.Name{
			CommonName:         cn,
			OrganizationalUnit: []string{policyName},
			Organization:       []string{identityName},
		},
		NotBefore:   now.Add(-5 * time.Minute),
		NotAfter:    now.Add(ttl),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: eku,
		DNSNames:    dnsSANs,
		IPAddresses: ipSANs,
	}
}

// signLeaf generates an ephemeral Ed25519 key, assigns a random serial, and
// signs the certificate template with the CA. Returns PEM-encoded cert and key.
func signLeaf(ca *CA, tmpl *x509.Certificate) (certPEM, keyPEM []byte, err error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl.SerialNumber = serial
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

// signCSR signs a caller-supplied public key with the given template, using
// a server-generated random serial.
func signCSR(ca *CA, pubKey crypto.PublicKey, tmpl *x509.Certificate) ([]byte, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl.SerialNumber = serial
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pubKey, ca.Key)
	if err != nil {
		return nil, fmt.Errorf("sign CSR cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}
