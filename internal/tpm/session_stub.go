//go:build !linux

package tpm

import (
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/google/go-attestation/attest"
)

// Available reports whether a TPM is accessible. Always false on non-Linux.
func Available() bool { return false }

// Session is a stub on non-Linux platforms.
type Session struct{}

// Open is not supported on non-Linux platforms.
func Open() (*Session, error) {
	return nil, errors.New("TPM not supported on this platform")
}

func (s *Session) EKPublic() crypto.PublicKey                { return nil }
func (s *Session) EKCertificate() *x509.Certificate          { return nil }
func (s *Session) EKHash() (string, error)                   { return "", nil }
func (s *Session) AKParams() attest.AttestationParameters    { return attest.AttestationParameters{} }
func (s *Session) ActivateCredential(attest.EncryptedCredential) ([]byte, error) { return nil, nil }
func (s *Session) Quote([]byte, []int) (*attest.Quote, []attest.PCR, error) {
	return nil, nil, nil
}
func (s *Session) ReadPCRs() ([]attest.PCR, error) { return nil, nil }
func (s *Session) Close() error                     { return nil }
