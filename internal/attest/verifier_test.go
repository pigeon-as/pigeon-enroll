package attest

import (
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

func TestVerifier_SessionExpiry(t *testing.T) {
	v := NewVerifier(nil)
	defer v.Close()

	// Create a session manually with an already-expired TTL.
	v.mu.Lock()
	v.sessions["expired"] = &session{
		id:        "expired",
		expiresAt: time.Now().Add(-1 * time.Second),
	}
	v.mu.Unlock()

	_, err := v.CompleteAttestation(CompleteRequest{SessionID: "expired"})
	must.Error(t, err)
}

func TestVerifier_UnknownSession(t *testing.T) {
	v := NewVerifier(nil)
	defer v.Close()

	_, err := v.CompleteAttestation(CompleteRequest{SessionID: "nonexistent"})
	must.Error(t, err)
}

func TestVerifier_SessionDeletedAfterLookup(t *testing.T) {
	v := NewVerifier(nil)
	defer v.Close()

	v.mu.Lock()
	v.sessions["once"] = &session{
		id:        "once",
		secret:    []byte("secret"),
		expiresAt: time.Now().Add(60 * time.Second),
	}
	v.mu.Unlock()

	// First call marks session as claimed (fails on secret check).
	v.CompleteAttestation(CompleteRequest{SessionID: "once"})

	// Second call should fail with "session already claimed".
	_, err := v.CompleteAttestation(CompleteRequest{SessionID: "once"})
	must.Error(t, err)
}

func TestVerifier_CompleteAttestationKeepsSession(t *testing.T) {
	v := NewVerifier(nil)
	defer v.Close()

	v.mu.Lock()
	v.sessions["s1"] = &session{
		id:        "s1",
		scope:     "worker",
		subject:   "node-1",
		secret:    []byte("secret"),
		token:     "tok",
		ekHash:    "abc",
		expiresAt: time.Now().Add(60 * time.Second),
	}
	v.mu.Unlock()

	result, err := v.CompleteAttestation(CompleteRequest{
		SessionID:       "s1",
		ActivatedSecret: []byte("secret"),
	})
	must.NoError(t, err)
	must.EqOp(t, "worker", result.Scope)
	must.EqOp(t, "node-1", result.Subject)

	// Session should still exist (claimed=true) for /csr.
	v.mu.RLock()
	sess, ok := v.sessions["s1"]
	v.mu.RUnlock()
	must.True(t, ok)
	must.True(t, sess.claimed)
}

func TestVerifier_ConsumeForCSR(t *testing.T) {
	v := NewVerifier(nil)
	defer v.Close()

	v.mu.Lock()
	v.sessions["s1"] = &session{
		id:        "s1",
		scope:     "worker",
		subject:   "node-1",
		secret:    []byte("secret"),
		token:     "tok",
		ekHash:    "abc",
		claimed:   true,
		expiresAt: time.Now().Add(60 * time.Second),
	}
	v.mu.Unlock()

	result, err := v.ConsumeForCSR("s1")
	must.NoError(t, err)
	must.EqOp(t, "worker", result.Scope)
	must.EqOp(t, "node-1", result.Subject)

	// Session should be deleted after consumption.
	_, err = v.ConsumeForCSR("s1")
	must.Error(t, err)
}

func TestVerifier_ConsumeForCSR_NotClaimed(t *testing.T) {
	v := NewVerifier(nil)
	defer v.Close()

	v.mu.Lock()
	v.sessions["s1"] = &session{
		id:        "s1",
		claimed:   false,
		expiresAt: time.Now().Add(60 * time.Second),
	}
	v.mu.Unlock()

	_, err := v.ConsumeForCSR("s1")
	must.Error(t, err)
}

func TestVerifier_ConsumeForCSR_Expired(t *testing.T) {
	v := NewVerifier(nil)
	defer v.Close()

	v.mu.Lock()
	v.sessions["s1"] = &session{
		id:        "s1",
		claimed:   true,
		expiresAt: time.Now().Add(-1 * time.Second),
	}
	v.mu.Unlock()

	_, err := v.ConsumeForCSR("s1")
	must.Error(t, err)
}
