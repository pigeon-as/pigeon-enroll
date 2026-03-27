package token

import (
	"testing"
	"time"
)

var testKey = []byte("test-enrollment-key-32-bytes!!!!")

func TestGenerateUnique(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	t1 := Generate(testKey, now, window, "")
	t2 := Generate(testKey, now, window, "")
	if t1 == t2 {
		t.Error("same inputs should produce different tokens (random nonce)")
	}
	if len(t1) != TokenLen {
		t.Errorf("token length = %d, want %d", len(t1), TokenLen)
	}
}

func TestGenerateVerifySameWindow(t *testing.T) {
	window := 30 * time.Minute
	t0 := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(15 * time.Minute) // same window

	tok := Generate(testKey, t0, window, "")
	if !Verify(testKey, tok, t1, window, "") {
		t.Error("token should verify within same window")
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

func TestVerifyWrongLength(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	// Old-format 64 hex char token should fail length check.
	if Verify(testKey, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", now, window, "") {
		t.Error("old-format (64 char) token should not verify")
	}
}

func TestDifferentKeys(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	tok1 := Generate(testKey, now, window, "")
	// Token generated with different key should not verify with testKey.
	if Verify([]byte("different-key-32-bytes-different!"), tok1, now, window, "") {
		t.Error("token should not verify with different key")
	}
}

func TestScopeBoundToken(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	tokWorker := Generate(testKey, now, window, "worker")
	tokServer := Generate(testKey, now, window, "server")
	tokEmpty := Generate(testKey, now, window, "")

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

	// Server token verifies only with server scope.
	if !Verify(testKey, tokServer, now, window, "server") {
		t.Error("server token should verify with server scope")
	}
	if Verify(testKey, tokServer, now, window, "worker") {
		t.Error("server token should NOT verify with worker scope")
	}

	// Empty-scope token only verifies with empty scope.
	if !Verify(testKey, tokEmpty, now, window, "") {
		t.Error("empty-scope token should verify with empty scope")
	}
	if Verify(testKey, tokEmpty, now, window, "worker") {
		t.Error("empty-scope token should NOT verify with worker scope")
	}
}
