package attest

import (
	"testing"
	"time"
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
	if err == nil {
		t.Fatal("expected error for expired session")
	}
}

func TestVerifier_UnknownSession(t *testing.T) {
	v := NewVerifier(nil)
	defer v.Close()

	_, err := v.CompleteAttestation(CompleteRequest{SessionID: "nonexistent"})
	if err == nil {
		t.Fatal("expected error for unknown session")
	}
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

	// First call removes the session (will fail on secret check but that's fine).
	v.CompleteAttestation(CompleteRequest{SessionID: "once"})

	// Second call should fail with "unknown session".
	_, err := v.CompleteAttestation(CompleteRequest{SessionID: "once"})
	if err == nil {
		t.Fatal("expected error: session should be consumed")
	}
}
