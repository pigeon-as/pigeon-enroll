// Package attest provides server-side TPM attestation verification.
// Follows the SPIRE community TPM plugin pattern: credential activation
// challenge-response with EK identity validation.
package attest

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/go-attestation/attest"
)

const (
	sessionTTL     = 60 * time.Second
	cleanupPeriod  = 30 * time.Second
	sessionIDBytes = 32
)

// session holds state for an in-flight attestation between /attest and /claim.
type session struct {
	id      string
	scope   string
	subject string
	secret  []byte // expected credential activation response
	ekHash    string
	token     string // original HMAC token, consumed on success
	expiresAt time.Time
	claimed   bool // true after successful /claim; session kept for /csr
}

// Verifier manages attestation sessions and verifies TPM responses.
type Verifier struct {
	mu       sync.RWMutex
	sessions map[string]*session
	done     chan struct{}
	ek       *EKValidator
	once     sync.Once
}

// NewVerifier creates a Verifier and starts the session cleanup goroutine.
// If ek is non-nil, EK identity is validated before generating challenges.
func NewVerifier(ek *EKValidator) *Verifier {
	v := &Verifier{
		sessions: make(map[string]*session),
		done:     make(chan struct{}),
		ek:       ek,
	}
	go v.cleanupLoop()
	return v
}

// Close stops the cleanup goroutine. Safe to call multiple times.
func (v *Verifier) Close() {
	v.once.Do(func() { close(v.done) })
}

// StartRequest is the input for StartAttestation.
type StartRequest struct {
	Token   string
	Scope   string
	Subject string
	EKPub   crypto.PublicKey
	EKCert   *x509.Certificate // optional, for CA chain validation
	AKParams attest.AttestationParameters
}

// StartResponse is returned by StartAttestation.
type StartResponse struct {
	SessionID           string
	EncryptedCredential *attest.EncryptedCredential
}

// StartAttestation begins a new attestation session. It validates EK identity
// (SPIRE pattern) and generates the credential activation challenge.
func (v *Verifier) StartAttestation(req StartRequest) (*StartResponse, error) {
	// Validate EK identity (SPIRE community plugin pattern).
	if v.ek != nil {
		if err := v.ek.Validate(req.EKPub, req.EKCert); err != nil {
			return nil, fmt.Errorf("EK validation failed: %w", err)
		}
	}

	// Generate credential activation challenge.
	ap := attest.ActivationParameters{
		EK:   req.EKPub,
		AK:   req.AKParams,
		Rand: rand.Reader,
	}
	if err := ap.CheckAKParameters(); err != nil {
		return nil, fmt.Errorf("invalid AK parameters: %w", err)
	}
	secret, ec, err := ap.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate credential activation challenge: %w", err)
	}

	// Generate session ID.
	idBytes := make([]byte, sessionIDBytes)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, fmt.Errorf("generate session ID: %w", err)
	}
	sessionID := hex.EncodeToString(idBytes)

	// Compute EK hash for audit.
	ekDER, err := x509.MarshalPKIXPublicKey(req.EKPub)
	if err != nil {
		return nil, fmt.Errorf("marshal EK public key: %w", err)
	}
	ekSHA := sha256.Sum256(ekDER)

	// Store session.
	sess := &session{
		id:        sessionID,
		scope:     req.Scope,
		subject:  req.Subject,
		secret:    secret,
		ekHash:    hex.EncodeToString(ekSHA[:]),
		token:     req.Token,
		expiresAt: time.Now().Add(sessionTTL),
	}

	v.mu.Lock()
	v.sessions[sessionID] = sess
	v.mu.Unlock()

	return &StartResponse{
		SessionID:           sessionID,
		EncryptedCredential: ec,
	}, nil
}

// CompleteRequest is the input for CompleteAttestation.
type CompleteRequest struct {
	SessionID       string
	ActivatedSecret []byte
}

// CompleteResult is returned on successful attestation.
type CompleteResult struct {
	Scope   string
	Subject string
	Token   string // original HMAC token for nonce consumption
	EKHash   string // for audit logging
}

// CompleteAttestation verifies the credential activation response.
// The session is marked as claimed (not deleted) so that it remains available
// for a subsequent POST /csr within the session TTL.
// The entire operation (lookup + crypto verify + mark claimed) is held under
// a single lock to prevent double-claim races.
func (v *Verifier) CompleteAttestation(req CompleteRequest) (*CompleteResult, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	sess, ok := v.sessions[req.SessionID]
	if !ok {
		return nil, errors.New("unknown or expired session")
	}
	if sess.claimed {
		return nil, errors.New("session already claimed")
	}
	if time.Now().After(sess.expiresAt) {
		delete(v.sessions, req.SessionID)
		return nil, errors.New("session expired")
	}

	// Verify credential activation (proves real TPM with this EK).
	if subtle.ConstantTimeCompare(sess.secret, req.ActivatedSecret) != 1 {
		delete(v.sessions, req.SessionID)
		return nil, errors.New("credential activation failed")
	}

	// Mark session as claimed only after successful crypto verification.
	sess.claimed = true
	sess.expiresAt = time.Now().Add(sessionTTL) // extend for /csr window

	return &CompleteResult{
		Scope:   sess.scope,
		Subject: sess.subject,
		Token:   sess.token,
		EKHash:  sess.ekHash,
	}, nil
}

// ConsumeForCSR looks up a claimed session and deletes it atomically.
// Returns the session data (scope, subject, EK hash) for CSR signing authorization.
// The session must have been previously completed via CompleteAttestation.
func (v *Verifier) ConsumeForCSR(sessionID string) (*CompleteResult, error) {
	v.mu.Lock()
	sess, ok := v.sessions[sessionID]
	if !ok {
		v.mu.Unlock()
		return nil, errors.New("unknown or expired session")
	}
	if !sess.claimed {
		v.mu.Unlock()
		return nil, errors.New("session not yet claimed")
	}
	if time.Now().After(sess.expiresAt) {
		delete(v.sessions, sessionID)
		v.mu.Unlock()
		return nil, errors.New("session expired")
	}
	delete(v.sessions, sessionID)
	v.mu.Unlock()

	return &CompleteResult{
		Scope:   sess.scope,
		Subject: sess.subject,
		Token:   sess.token,
		EKHash:  sess.ekHash,
	}, nil
}

// cleanupLoop removes expired sessions periodically.
func (v *Verifier) cleanupLoop() {
	ticker := time.NewTicker(cleanupPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-v.done:
			return
		case now := <-ticker.C:
			v.mu.Lock()
			for id, sess := range v.sessions {
				if now.After(sess.expiresAt) {
					delete(v.sessions, id)
				}
			}
			v.mu.Unlock()
		}
	}
}
