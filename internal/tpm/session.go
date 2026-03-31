//go:build linux

// Package tpm provides client-side TPM operations for node attestation.
// Follows the SPIRE community TPM plugin pattern: EK-based identity,
// credential activation via go-attestation/attest.
package tpm

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/google/go-attestation/attest"
)

// Session wraps a TPM connection and ephemeral AK for a single attestation.
type Session struct {
	tpm *attest.TPM
	ak  *attest.AK
	ek  attest.EK
}

// Available reports whether a TPM is accessible on this host.
func Available() bool {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{})
	if err != nil {
		return false
	}
	tpm.Close()
	return true
}

// Open creates a new attestation session. It opens the TPM, reads the EK,
// and creates a fresh AK (matches SPIRE community plugin: new AK per session).
func Open() (*Session, error) {
	tpm, err := attest.OpenTPM(&attest.OpenConfig{})
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}

	eks, err := tpm.EKs()
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("read EK: %w", err)
	}
	if len(eks) == 0 {
		tpm.Close()
		return nil, fmt.Errorf("no endorsement key found")
	}

	ak, err := tpm.NewAK(&attest.AKConfig{})
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("create AK: %w", err)
	}

	return &Session{tpm: tpm, ak: ak, ek: eks[0]}, nil
}

// EKPublic returns the EK's public key.
func (s *Session) EKPublic() crypto.PublicKey {
	return s.ek.Public
}

// EKCertificate returns the EK's certificate, or nil if the TPM
// does not have a manufacturer certificate provisioned.
func (s *Session) EKCertificate() *x509.Certificate {
	return s.ek.Certificate
}

// EKHash returns the SHA-256 hash of the EK public key in hex.
// Used as a stable hardware identifier for audit logging.
func (s *Session) EKHash() (string, error) {
	pub, err := x509.MarshalPKIXPublicKey(s.ek.Public)
	if err != nil {
		return "", fmt.Errorf("marshal EK public key: %w", err)
	}
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:]), nil
}

// AKParams returns the AK attestation parameters to send to the server.
func (s *Session) AKParams() attest.AttestationParameters {
	return s.ak.AttestationParameters()
}

// ActivateCredential decrypts a credential activation challenge from the server.
// This proves the AK is resident on the same TPM as the EK.
func (s *Session) ActivateCredential(ec attest.EncryptedCredential) ([]byte, error) {
	return s.ak.ActivateCredential(s.tpm, ec)
}

// Close releases all TPM resources.
func (s *Session) Close() error {
	if s.ak != nil {
		s.ak.Close(s.tpm)
	}
	if s.tpm != nil {
		return s.tpm.Close()
	}
	return nil
}
