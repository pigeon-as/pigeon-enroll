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
	"golang.org/x/crypto/hkdf"
)

// ValidateIKM checks that the enrollment key is exactly 32 bytes.
func ValidateIKM(ikm []byte) error {
	if len(ikm) != 32 {
		return fmt.Errorf("enrollment key must be 32 bytes, got %d", len(ikm))
	}
	return nil
}

// DeriveHMACKey derives a separate 32-byte HMAC signing key from the IKM.
func DeriveHMACKey(ikm []byte) ([]byte, error) {
	if err := ValidateIKM(ikm); err != nil {
		return nil, fmt.Errorf("derive HMAC key: %w", err)
	}
	r := hkdf.New(sha256.New, ikm, nil, []byte("pigeon-enroll hmac-signing-key"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive HMAC key: %w", err)
	}
	return key, nil
}

// Resolve loads persisted secrets from path, or derives them from ikm
// via HKDF-SHA256 and persists atomically. If path is empty, derives fresh.
func Resolve(specs []config.SecretSpec, path string, ikm []byte) (map[string]string, error) {
	if len(specs) == 0 {
		return nil, nil
	}

	if path == "" {
		// No persistence path — derive fresh.
		return derive(specs, ikm)
	}

	data, err := os.ReadFile(path)
	if err == nil {
		return load(data, specs)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read secrets: %w", err)
	}
	secrets, err := derive(specs, ikm)
	if err != nil {
		return nil, err
	}
	if err := persist(secrets, path); err != nil {
		return nil, err
	}
	return secrets, nil
}

// load parses persisted secrets and checks all specs are present.
func load(data []byte, specs []config.SecretSpec) (map[string]string, error) {
	var secrets map[string]string
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, fmt.Errorf("parse secrets file: %w", err)
	}
	for _, s := range specs {
		if _, ok := secrets[s.Name]; !ok {
			return nil, fmt.Errorf("secrets file missing key %q", s.Name)
		}
	}
	return secrets, nil
}

// derive produces secrets from ikm via HKDF-SHA256.
// Info string: "pigeon-enroll derive [<scope> ]<name>".
func derive(specs []config.SecretSpec, ikm []byte) (map[string]string, error) {
	secrets := make(map[string]string, len(specs))
	for _, s := range specs {
		var info []byte
		if s.Scope != "" {
			info = []byte("pigeon-enroll derive " + s.Scope + " " + s.Name)
		} else {
			info = []byte("pigeon-enroll derive " + s.Name)
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
func persist(secrets map[string]string, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create secrets directory: %w", err)
	}
	data, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshal secrets: %w", err)
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".secrets-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
