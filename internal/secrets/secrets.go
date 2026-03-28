// Package secrets resolves derived secrets: loads from disk on restart,
// derives and optionally persists on first start.
package secrets

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

// Resolve loads persisted secrets from path, or derives them from ikm
// via HKDF-SHA256 and persists atomically. If path is empty, derives fresh.
// The persisted format is {"secrets":{...},"vars":{...}} with an optional "ca" field when CAs are configured.
// Returns secrets and CAs as separate maps.
func Resolve(specs []config.SecretSpec, cas []config.CASpec, vars map[string]string, path string, ikm []byte) (map[string]string, map[string]CAEntry, error) {
	if len(specs) == 0 && len(cas) == 0 {
		return nil, nil, nil
	}

	// Normalize so persisted JSON uses {} instead of null.
	if vars == nil {
		vars = map[string]string{}
	}

	if path == "" {
		// No persistence path — derive fresh.
		return deriveAll(specs, cas, ikm)
	}

	data, err := os.ReadFile(path)
	if err == nil {
		loaded, loadedCAs, diskVars, loadErr := load(data, specs, cas)
		if loadErr != nil {
			return nil, nil, loadErr
		}
		// Re-persist only when vars have changed.
		if !mapsEqual(diskVars, vars) {
			if err := persist(loaded, loadedCAs, vars, path); err != nil {
				return nil, nil, err
			}
		}
		return loaded, loadedCAs, nil
	}
	if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read secrets: %w", err)
	}
	secrets, derivedCAs, err := deriveAll(specs, cas, ikm)
	if err != nil {
		return nil, nil, err
	}
	if err := persist(secrets, derivedCAs, vars, path); err != nil {
		return nil, nil, err
	}
	return secrets, derivedCAs, nil
}

// persistedFile is the on-disk format: {"secrets":{...},"vars":{...}} with an optional "ca" field.
type persistedFile struct {
	Secrets map[string]string  `json:"secrets"`
	Vars    map[string]string  `json:"vars"`
	CA      map[string]CAEntry `json:"ca,omitempty"`
}

// load parses persisted secrets and vars, and checks all specs are present.
func load(data []byte, specs []config.SecretSpec, cas []config.CASpec) (map[string]string, map[string]CAEntry, map[string]string, error) {
	var pf persistedFile
	if err := json.Unmarshal(data, &pf); err != nil {
		return nil, nil, nil, fmt.Errorf("parse secrets file: %w", err)
	}
	filteredSecrets := make(map[string]string, len(specs))
	for _, s := range specs {
		v, ok := pf.Secrets[s.Name]
		if !ok {
			return nil, nil, nil, fmt.Errorf("secrets file missing key %q", s.Name)
		}
		filteredSecrets[s.Name] = v
	}
	var filteredCAs map[string]CAEntry
	for _, ca := range cas {
		entry, ok := pf.CA[ca.Name]
		if !ok {
			return nil, nil, nil, fmt.Errorf("secrets file missing CA %q", ca.Name)
		}
		if filteredCAs == nil {
			filteredCAs = make(map[string]CAEntry, len(cas))
		}
		filteredCAs[ca.Name] = entry
	}
	return filteredSecrets, filteredCAs, pf.Vars, nil
}

// mapsEqual reports whether two string maps have identical keys and values.
func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// deriveAll produces secrets from ikm via HKDF-SHA256 and derives CA certs.
func deriveAll(specs []config.SecretSpec, cas []config.CASpec, ikm []byte) (map[string]string, map[string]CAEntry, error) {
	secrets, err := derive(specs, ikm)
	if err != nil {
		return nil, nil, err
	}
	caMap := make(map[string]CAEntry, len(cas))
	for _, ca := range cas {
		derived, err := pki.DeriveNamedCA(ikm, ca.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("derive CA %q: %w", ca.Name, err)
		}
		caMap[ca.Name] = CAEntry{
			CertPEM:       string(derived.CertPEM),
			PrivateKeyPEM: string(derived.KeyPEM),
		}
	}
	return secrets, caMap, nil
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

// persist writes secrets atomically to path via temp file + rename.
func persist(secrets map[string]string, cas map[string]CAEntry, vars map[string]string, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create secrets directory: %w", err)
	}
	data, err := json.Marshal(persistedFile{Secrets: secrets, CA: cas, Vars: vars})
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return fmt.Errorf("rename temp file to %s: %w", path, err)
	}
	return nil
}
