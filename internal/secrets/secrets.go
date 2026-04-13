// Package secrets resolves derived secrets: loads from disk on restart,
// derives and optionally persists on first start.
//
// Key derivation uses HKDF-SHA256 with nil salt per RFC 5869 §3.1 (IKM is
// uniformly random). Unique info strings per secret provide domain separation
// per NIST SP 800-108 §7.4. A dedicated HMAC signing key is derived from the
// enrollment key — the raw key is never used directly for HMAC.
//
// References:
//   - RFC 5869 (HKDF): https://datatracker.ietf.org/doc/html/rfc5869
//   - NIST SP 800-108 (KDF in Counter Mode): https://csrc.nist.gov/pubs/sp/800/108/r1/final
package secrets

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/pki"
	"golang.org/x/crypto/hkdf"
)

const (
	// IKMLength is the required enrollment key size (256-bit).
	IKMLength = 32

	// hkdfInfoPrefix is the domain separator for HKDF secret derivation.
	// Changing this changes all derived secrets.
	hkdfInfoPrefix = "pigeon-enroll derive "

	// hkdfInfoHMACKey is the HKDF info string for the HMAC signing key.
	// Changing this changes the signing key and invalidates all tokens.
	hkdfInfoHMACKey = "pigeon-enroll hmac-signing-key"
)

// ValidateIKM checks that the enrollment key is exactly IKMLength bytes.
func ValidateIKM(ikm []byte) error {
	if len(ikm) != IKMLength {
		return fmt.Errorf("enrollment key must be %d bytes, got %d", IKMLength, len(ikm))
	}
	return nil
}

// DeriveHMACKey derives a separate 32-byte HMAC signing key from the IKM.
func DeriveHMACKey(ikm []byte) ([]byte, error) {
	if err := ValidateIKM(ikm); err != nil {
		return nil, fmt.Errorf("derive HMAC key: %w", err)
	}
	r := hkdf.New(sha256.New, ikm, nil, []byte(hkdfInfoHMACKey))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive HMAC key: %w", err)
	}
	return key, nil
}

// CAEntry holds a derived CA certificate and private key in PEM format.
// JSON field names follow the Terraform TLS provider output convention.
type CAEntry struct {
	CertPEM       string `json:"cert_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

// CertEntry holds an auto-issued leaf certificate and private key in PEM format.
type CertEntry struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// JWTKeyEntry holds a derived JWT signing key pair.
type JWTKeyEntry struct {
	PublicKeyPEM string            `json:"public_key_pem"`
	PrivateKey   ed25519.PrivateKey `json:"-"` // not persisted
}

// Resolve loads persisted secrets from path, or derives them from ikm
// via HKDF-SHA256 and persists atomically. If path is empty, derives fresh.
// The persisted format is {"secrets":{...},"vars":{...}} with optional "ca", "certs", and "jwt_keys" fields.
// Returns secrets, CAs, certs, and JWT keys as separate maps.
//
// When scope is non-empty, cert blocks matching that scope are issued locally
// using hostname as the default CN (when the cert spec has no static CN).
// This allows servers to self-issue leaf certs from HKDF-derived CAs without
// going through the claim API.
func Resolve(specs []config.SecretSpec, cas []config.CASpec, certs []config.CertSpec, jwts []config.JWTSpec, vars map[string]string, path string, ikm []byte, scope, hostname string) (map[string]string, map[string]CAEntry, map[string]CertEntry, map[string]JWTKeyEntry, error) {
	if len(specs) == 0 && len(cas) == 0 && len(certs) == 0 && len(jwts) == 0 {
		return nil, nil, nil, nil, nil
	}

	// Normalize so persisted JSON uses {} instead of null.
	if vars == nil {
		vars = map[string]string{}
	}

	if path == "" {
		// No persistence path — derive fresh.
		return deriveAll(specs, cas, certs, jwts, ikm, scope, hostname)
	}

	data, err := os.ReadFile(path)
	if err == nil {
		loaded, loadedCAs, allCerts, loadedJWTKeys, diskVars, loadErr := load(data, specs, cas, jwts, ikm)
		if loadErr != nil {
			return nil, nil, nil, nil, loadErr
		}
		// Issue any scope-matching certs missing from the persisted file.
		// This self-heals when new cert blocks are added to config after
		// the secrets file was already created (Consul auto_config pattern).
		needPersist := !maps.Equal(diskVars, vars)
		var myCerts map[string]CertEntry
		if scope != "" {
			for _, cs := range certs {
				if cs.Mode == "csr" {
					continue // CSR-mode certs are issued via gRPC Claim (csr_der), not self-issued server-side
				}
				if !scopeMatch(cs.Scope, scope) {
					continue
				}
				if entry, ok := allCerts[cs.Name]; ok && !certExpired(entry) {
					if myCerts == nil {
						myCerts = make(map[string]CertEntry)
					}
					myCerts[cs.Name] = entry
					continue
				}
				// Missing cert — issue and cache it.
				issued, err := issueCert(cs, loadedCAs, hostname)
				if err != nil {
					return nil, nil, nil, nil, err
				}
				if allCerts == nil {
					allCerts = make(map[string]CertEntry)
				}
				allCerts[cs.Name] = issued
				if myCerts == nil {
					myCerts = make(map[string]CertEntry)
				}
				myCerts[cs.Name] = issued
				needPersist = true
			}
		}
		// Detect stale persisted cert entries (cert block removed from config).
		// Without this, needPersist stays false and old private keys linger.
		if !needPersist && len(allCerts) > 0 {
			configured := make(map[string]struct{}, len(certs))
			for _, cs := range certs {
				configured[cs.Name] = struct{}{}
			}
			for name := range allCerts {
				if _, ok := configured[name]; !ok {
					needPersist = true
					break
				}
			}
		}
		if needPersist {
			// Prune certs no longer in config before persisting.
			// Disk should mirror config — stale private keys don't linger.
			pruned := make(map[string]CertEntry, len(certs))
			for _, cs := range certs {
				if entry, ok := allCerts[cs.Name]; ok {
					pruned[cs.Name] = entry
				}
			}
			if err := persist(loaded, loadedCAs, pruned, loadedJWTKeys, vars, path); err != nil {
				return nil, nil, nil, nil, err
			}
		}
		return loaded, loadedCAs, myCerts, loadedJWTKeys, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, nil, nil, fmt.Errorf("read secrets: %w", err)
	}
	secrets, derivedCAs, derivedCerts, jwtKeys, err := deriveAll(specs, cas, certs, jwts, ikm, scope, hostname)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if err := persist(secrets, derivedCAs, derivedCerts, jwtKeys, vars, path); err != nil {
		return nil, nil, nil, nil, err
	}
	return secrets, derivedCAs, derivedCerts, jwtKeys, nil
}

// persistedFile is the on-disk format: {"secrets":{...},"vars":{...}} with optional "ca", "certs", and "jwt_keys" fields.
type persistedFile struct {
	Secrets map[string]string    `json:"secrets"`
	Vars    map[string]string    `json:"vars"`
	CA      map[string]CAEntry   `json:"ca,omitempty"`
	Certs   map[string]CertEntry `json:"certs,omitempty"`
	JWTKeys map[string]string    `json:"jwt_keys,omitempty"` // name → PEM public key
}

// load parses the persisted secrets file and validates that all required
// specs are present. Returns all persisted certs as-is (no scope filtering) —
// the caller checks for missing scope-matching certs and issues them
// (Consul auto_config cache pattern).
func load(data []byte, specs []config.SecretSpec, cas []config.CASpec, jwts []config.JWTSpec, ikm []byte) (map[string]string, map[string]CAEntry, map[string]CertEntry, map[string]JWTKeyEntry, map[string]string, error) {
	var pf persistedFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("parse secrets file: %w", err)
	}
	filteredSecrets := make(map[string]string, len(specs))
	for _, s := range specs {
		v, ok := pf.Secrets[s.Name]
		if !ok {
			return nil, nil, nil, nil, nil, fmt.Errorf("secrets file missing key %q", s.Name)
		}
		filteredSecrets[s.Name] = v
	}
	var filteredCAs map[string]CAEntry
	for _, ca := range cas {
		entry, ok := pf.CA[ca.Name]
		if !ok {
			return nil, nil, nil, nil, nil, fmt.Errorf("secrets file missing CA %q", ca.Name)
		}
		if filteredCAs == nil {
			filteredCAs = make(map[string]CAEntry, len(cas))
		}
		filteredCAs[ca.Name] = entry
	}
	// JWT keys: re-derive private keys from IKM (not persisted), load public keys from file.
	var jwtKeys map[string]JWTKeyEntry
	for _, j := range jwts {
		pubPEM, ok := pf.JWTKeys[j.Name]
		if !ok {
			return nil, nil, nil, nil, nil, fmt.Errorf("secrets file missing JWT key %q", j.Name)
		}
		_, privKey, err := pki.DeriveJWTKey(ikm, j.Name)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("re-derive JWT key %q: %w", j.Name, err)
		}
		if jwtKeys == nil {
			jwtKeys = make(map[string]JWTKeyEntry, len(jwts))
		}
		jwtKeys[j.Name] = JWTKeyEntry{PublicKeyPEM: strings.ReplaceAll(pubPEM, "\\n", "\n"), PrivateKey: privKey}
	}
	return filteredSecrets, filteredCAs, pf.Certs, jwtKeys, pf.Vars, nil
}



// deriveAll produces secrets from ikm via HKDF-SHA256, derives CA certs,
// issues leaf certs for scope-matching cert blocks, and derives JWT key pairs.
func deriveAll(specs []config.SecretSpec, cas []config.CASpec, certs []config.CertSpec, jwts []config.JWTSpec, ikm []byte, scope, hostname string) (map[string]string, map[string]CAEntry, map[string]CertEntry, map[string]JWTKeyEntry, error) {
	secrets, err := derive(specs, ikm)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	caMap := make(map[string]CAEntry, len(cas))
	for _, ca := range cas {
		derived, err := pki.DeriveNamedCA(ikm, ca.Name)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("derive CA %q: %w", ca.Name, err)
		}
		caMap[ca.Name] = CAEntry{
			CertPEM:       string(derived.CertPEM),
			PrivateKeyPEM: string(derived.KeyPEM),
		}
	}
	// Issue leaf certs for scope-matching cert blocks.
	var certMap map[string]CertEntry
	if scope != "" {
		for _, cs := range certs {
			if cs.Mode == "csr" {
				continue // CSR-mode certs are issued via gRPC Claim (csr_der), not self-issued server-side
			}
			if !scopeMatch(cs.Scope, scope) {
				continue
			}
			entry, err := issueCert(cs, caMap, hostname)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			if certMap == nil {
				certMap = make(map[string]CertEntry, len(certs))
			}
			certMap[cs.Name] = entry
		}
	}
	jwtKeys := make(map[string]JWTKeyEntry, len(jwts))
	for _, j := range jwts {
		pubKey, privKey, err := pki.DeriveJWTKey(ikm, j.Name)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("derive JWT key %q: %w", j.Name, err)
		}
		pubDER, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("marshal JWT public key %q: %w", j.Name, err)
		}
		pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))
		jwtKeys[j.Name] = JWTKeyEntry{PublicKeyPEM: pubPEM, PrivateKey: privKey}
	}
	return secrets, caMap, certMap, jwtKeys, nil
}

// derive produces secrets from ikm via HKDF-SHA256.
// Info string: "pigeon-enroll derive [<scope> ]<name>".
func derive(specs []config.SecretSpec, ikm []byte) (map[string]string, error) {
	secrets := make(map[string]string, len(specs))
	for _, s := range specs {
		var info []byte
		if s.Scope != "" {
			info = []byte(hkdfInfoPrefix + s.Scope + " " + s.Name)
		} else {
			info = []byte(hkdfInfoPrefix + s.Name)
		}
		r := hkdf.New(sha256.New, ikm, nil, info)
		b := make([]byte, s.Length)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, fmt.Errorf("derive %q: %w", s.Name, err)
		}
		switch s.Encoding {
		case "base64":
			secrets[s.Name] = base64.StdEncoding.EncodeToString(b)
		case "hex":
			secrets[s.Name] = hex.EncodeToString(b)
		default:
			return nil, fmt.Errorf("derive %q: unknown encoding %q", s.Name, s.Encoding)
		}
	}
	return secrets, nil
}

// issueCert issues a leaf certificate from a CA entry for the given cert spec.
// Used by both deriveAll (initial creation) and Resolve (self-healing on load).
func issueCert(cs config.CertSpec, caMap map[string]CAEntry, hostname string) (CertEntry, error) {
	caEntry, ok := caMap[cs.CA]
	if !ok {
		return CertEntry{}, fmt.Errorf("cert %q references unknown CA %q", cs.Name, cs.CA)
	}
	pemData := append([]byte(caEntry.CertPEM), []byte(caEntry.PrivateKeyPEM)...)
	ca, err := pki.LoadCA(pemData)
	if err != nil {
		return CertEntry{}, fmt.Errorf("load CA %q for cert %q: %w", cs.CA, cs.Name, err)
	}
	cn := cs.CN
	if cn == "" {
		cn = hostname
	}
	if cn == "" {
		return CertEntry{}, fmt.Errorf("cert %q: cn is empty and no hostname provided", cs.Name)
	}
	serverAuth := cs.ServerAuth != nil && *cs.ServerAuth
	clientAuth := cs.ClientAuth == nil || *cs.ClientAuth
	dnsSANs, ipSANs, err := cs.ResolveSANs(hostname)
	if err != nil {
		return CertEntry{}, fmt.Errorf("cert %q: %w", cs.Name, err)
	}
	certPEM, keyPEM, err := pki.IssueCert(ca, cn, dnsSANs, ipSANs, cs.TTL, serverAuth, clientAuth)
	if err != nil {
		return CertEntry{}, fmt.Errorf("issue cert %q: %w", cs.Name, err)
	}
	return CertEntry{CertPEM: string(certPEM), KeyPEM: string(keyPEM)}, nil
}

// certExpired reports whether a cached cert has expired or is unparseable.
// Expired certs are treated as missing — the caller will re-issue.
func certExpired(entry CertEntry) bool {
	block, _ := pem.Decode([]byte(entry.CertPEM))
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return time.Now().After(cert.NotAfter)
}

// scopeMatch reports whether a spec's scope list includes the given scope.
// An empty spec scope matches everything (unscoped).
func scopeMatch(specScope []string, scope string) bool {
	if len(specScope) == 0 {
		return true
	}
	for _, s := range specScope {
		if s == scope {
			return true
		}
	}
	return false
}

// persist writes secrets atomically to path via temp file + rename.
func persist(secrets map[string]string, cas map[string]CAEntry, certs map[string]CertEntry, jwtKeys map[string]JWTKeyEntry, vars map[string]string, path string) error {
	// Persist secrets, CA entries (including private keys), cert entries
	// (including leaf private keys), vars, and JWT public keys.
	// Only JWT private keys are omitted — they are re-derived from IKM on load.
	// Escape newlines so pigeon-template can interpolate PEM into HCL quoted strings.
	// HCL v2 unescapes \n back to newlines, giving valid PEM.
	jwtPubs := make(map[string]string, len(jwtKeys))
	for name, entry := range jwtKeys {
		jwtPubs[name] = strings.ReplaceAll(entry.PublicKeyPEM, "\n", "\\n")
	}
	data, err := json.Marshal(persistedFile{Secrets: secrets, CA: cas, Certs: certs, JWTKeys: jwtPubs, Vars: vars})
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}
	return atomicfile.Write(path, data, 0600)
}
