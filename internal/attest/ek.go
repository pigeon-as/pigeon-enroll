package attest

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// EKValidator checks whether an EK public key is trusted.
// Follows the SPIRE community TPM plugin pattern:
//   - ek_ca_path: validate EK certificate chain against manufacturer CA certs
//   - ek_hash_path: check EK public key hash against an allowlist
//
// Hash file is reloaded on each Validate() call so that appended hashes
// take effect without restarting the server (Terraform appends during provisioning).
type EKValidator struct {
	caRoots  *x509.CertPool
	hashPath string
}

// NewEKValidator creates a validator from optional CA directory and hash file paths.
// At least one should be non-empty (caller is responsible for ensuring this).
func NewEKValidator(caPath, hashPath string) (*EKValidator, error) {
	v := &EKValidator{hashPath: hashPath}

	if caPath != "" {
		roots, err := loadCACerts(caPath)
		if err != nil {
			return nil, fmt.Errorf("load EK CA certs: %w", err)
		}
		v.caRoots = roots
	}

	// Validate hash file is readable at startup (fail-fast), but don't
	// cache the contents — Validate() reloads on each call.
	if hashPath != "" {
		if _, err := loadHashFile(hashPath); err != nil {
			return nil, fmt.Errorf("load EK hashes: %w", err)
		}
	}

	return v, nil
}

// Validate checks whether the given EK is trusted.
// Checks hash allowlist first (SPIRE community plugin order), then certificate chain.
// Hash file is reloaded on each call so appended hashes take effect immediately.
func (v *EKValidator) Validate(ekPub crypto.PublicKey, ekCert *x509.Certificate) error {
	ekDER, err := x509.MarshalPKIXPublicKey(ekPub)
	if err != nil {
		return fmt.Errorf("marshal EK public key: %w", err)
	}
	h := sha256.Sum256(ekDER)
	hash := hex.EncodeToString(h[:])

	// Check hash allowlist first (reloaded each call).
	if v.hashPath != "" {
		hashes, err := loadHashFile(v.hashPath)
		if err != nil {
			return fmt.Errorf("reload EK hashes: %w", err)
		}
		if hashes[hash] {
			return nil
		}
	}

	// Check certificate chain.
	if v.caRoots != nil && ekCert != nil {
		if err := verifyCert(v.caRoots, ekCert, ekDER); err == nil {
			return nil
		}
	}

	return fmt.Errorf("EK not trusted (hash %s)", hash)
}

// verifyCert validates the EK certificate chain and checks that the
// certificate's public key matches the provided EK public key.
func verifyCert(roots *x509.CertPool, ekCert *x509.Certificate, ekDER []byte) error {
	// TPM EK certificates often have SAN extensions with TPM-specific data
	// that Go's x509 marks as "unhandled critical" and rejects during Verify.
	// SPIRE tpmdevid strips the SAN OID from UnhandledCriticalExtensions
	// before verification. We do the same.
	subjectAltNameOID := asn1.ObjectIdentifier{2, 5, 29, 17}
	var filtered []asn1.ObjectIdentifier
	for _, oid := range ekCert.UnhandledCriticalExtensions {
		if !oid.Equal(subjectAltNameOID) {
			filtered = append(filtered, oid)
		}
	}
	ekCert.UnhandledCriticalExtensions = filtered

	_, err := ekCert.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return err
	}

	// Verify cert's public key matches the provided EK public key.
	certDER, err := x509.MarshalPKIXPublicKey(ekCert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal EK cert public key: %w", err)
	}
	if !bytes.Equal(ekDER, certDER) {
		return fmt.Errorf("EK certificate public key does not match provided EK public key")
	}

	return nil
}

// loadCACerts loads all PEM and DER certificates from a directory.
func loadCACerts(dir string) (*x509.CertPool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	count := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}

		// Try PEM first.
		if block, _ := pem.Decode(data); block != nil {
			if pool.AppendCertsFromPEM(data) {
				count++
				continue
			}
		}
		// Try DER.
		if cert, err := x509.ParseCertificate(data); err == nil {
			pool.AddCert(cert)
			count++
			continue
		}
		// SPIRE community pattern: fail-closed on unparseable files.
		return nil, fmt.Errorf("could not parse cert data for %q", name)
	}
	if count == 0 {
		return nil, fmt.Errorf("no valid certificates found in %s", dir)
	}
	return pool, nil
}

// loadHashFile reads EK public key hashes from a file.
// Format: one hex-encoded SHA-256 hash per line. Lines starting with #
// are comments. Empty lines are skipped.
func loadHashFile(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hashes := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		decoded, err := hex.DecodeString(line)
		if err != nil {
			return nil, fmt.Errorf("invalid hex hash %q: %w", line, err)
		}
		if len(decoded) != sha256.Size {
			return nil, fmt.Errorf("invalid EK hash %q: expected %d-byte SHA-256 hash", line, sha256.Size)
		}
		hashes[strings.ToLower(line)] = true
	}
	return hashes, scanner.Err()
}

// EKHashFromKey computes the SHA-256 hash of a PKIX-encoded public key.
// Returns the hex-encoded hash, or empty string on error.
func EKHashFromKey(pub crypto.PublicKey) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}
