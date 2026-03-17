package token

import (
	"testing"
	"time"
)

var testKey = []byte("test-enrollment-key-32-bytes!!!!!")

func TestGenerateDeterministic(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	t1 := Generate(testKey, now, window, "")
	t2 := Generate(testKey, now, window, "")
	if t1 != t2 {
		t.Errorf("same inputs produced different tokens: %q vs %q", t1, t2)
	}
	if len(t1) != 64 { // SHA256 = 32 bytes = 64 hex chars
		t.Errorf("token length = %d, want 64", len(t1))
	}
}

func TestGenerateSameWindow(t *testing.T) {
	window := 30 * time.Minute
	t0 := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(15 * time.Minute) // same window

	tok0 := Generate(testKey, t0, window, "")
	tok1 := Generate(testKey, t1, window, "")
	if tok0 != tok1 {
		t.Error("tokens within same window should be identical")
	}
}

func TestGenerateDifferentWindow(t *testing.T) {
	window := 30 * time.Minute
	t0 := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(31 * time.Minute) // next window

	tok0 := Generate(testKey, t0, window, "")
	tok1 := Generate(testKey, t1, window, "")
	if tok0 == tok1 {
		t.Error("tokens in different windows should differ")
	}
}

func TestVerifyCurrentWindow(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 15, 0, 0, time.UTC)
	window := 30 * time.Minute
	tok := Generate(testKey, now, window, "")

	if !Verify(testKey, tok, now, window, "") {
		t.Error("token should verify in current window")
	}
}

func TestVerifyPreviousWindow(t *testing.T) {
	window := 30 * time.Minute
	// Token generated at 11:50 (window floor = 11:30)
	genTime := time.Date(2026, 3, 13, 11, 50, 0, 0, time.UTC)
	tok := Generate(testKey, genTime, window, "")

	// Verified at 12:05 (window floor = 12:00, previous = 11:30)
	verifyTime := time.Date(2026, 3, 13, 12, 5, 0, 0, time.UTC)
	if !Verify(testKey, tok, verifyTime, window, "") {
		t.Error("token from previous window should verify")
	}
}

func TestVerifyExpired(t *testing.T) {
	window := 30 * time.Minute
	// Token generated at 11:00 (window floor = 11:00)
	genTime := time.Date(2026, 3, 13, 11, 0, 0, 0, time.UTC)
	tok := Generate(testKey, genTime, window, "")

	// Verified at 12:05 — two windows later (current = 12:00, previous = 11:30)
	verifyTime := time.Date(2026, 3, 13, 12, 5, 0, 0, time.UTC)
	if Verify(testKey, tok, verifyTime, window, "") {
		t.Error("token from 2 windows ago should not verify")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute
	tok := Generate(testKey, now, window, "")

	otherKey := []byte("different-key-32-bytes-different!")
	if Verify(otherKey, tok, now, window, "") {
		t.Error("token should not verify with different key")
	}
}

func TestVerifyGarbageToken(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	if Verify(testKey, "not-a-valid-token", now, window, "") {
		t.Error("garbage token should not verify")
	}
}

func TestDifferentKeys(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	tok1 := Generate(testKey, now, window, "")
	tok2 := Generate([]byte("different-key-32-bytes-different!"), now, window, "")
	if tok1 == tok2 {
		t.Error("different keys should produce different tokens")
	}
}

func TestScopeBoundToken(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	// Tokens with different scopes must differ.
	tokWorker := Generate(testKey, now, window, "worker")
	tokServer := Generate(testKey, now, window, "server")
	tokEmpty := Generate(testKey, now, window, "")
	if tokWorker == tokServer {
		t.Error("different scopes should produce different tokens")
	}
	if tokWorker == tokEmpty {
		t.Error("scoped vs empty scope should produce different tokens")
	}

	// Token verifies only with matching scope.
	if !Verify(testKey, tokWorker, now, window, "worker") {
		t.Error("worker token should verify with worker scope")
	}
	if Verify(testKey, tokWorker, now, window, "server") {
		t.Error("worker token should NOT verify with server scope")
	}
	if Verify(testKey, tokWorker, now, window, "") {
		t.Error("worker token should NOT verify with empty scope")
	}

	// Empty-scope token only verifies with empty scope.
	if !Verify(testKey, tokEmpty, now, window, "") {
		t.Error("empty-scope token should verify with empty scope")
	}
	if Verify(testKey, tokEmpty, now, window, "worker") {
		t.Error("empty-scope token should NOT verify with worker scope")
	}
}
