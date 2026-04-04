package token

import (
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

var testKey = []byte("test-enrollment-key-32-bytes!!!!")

func TestGenerateUnique(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	t1 := Generate(testKey, now, window, "")
	t2 := Generate(testKey, now, window, "")
	must.NotEq(t, t1, t2, must.Sprint("same inputs should produce different tokens (random nonce)"))
	must.EqOp(t, TokenLen, len(t1))
}

func TestGenerateVerifySameWindow(t *testing.T) {
	window := 30 * time.Minute
	t0 := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	t1 := t0.Add(15 * time.Minute) // same window

	tok := Generate(testKey, t0, window, "")
	must.True(t, Verify(testKey, tok, t1, window, ""))
}

func TestVerifyCurrentWindow(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 15, 0, 0, time.UTC)
	window := 30 * time.Minute
	tok := Generate(testKey, now, window, "")

	must.True(t, Verify(testKey, tok, now, window, ""))
}

func TestVerifyPreviousWindow(t *testing.T) {
	window := 30 * time.Minute
	// Token generated at 11:50 (window floor = 11:30)
	genTime := time.Date(2026, 3, 13, 11, 50, 0, 0, time.UTC)
	tok := Generate(testKey, genTime, window, "")

	// Verified at 12:05 (window floor = 12:00, previous = 11:30)
	verifyTime := time.Date(2026, 3, 13, 12, 5, 0, 0, time.UTC)
	must.True(t, Verify(testKey, tok, verifyTime, window, ""))
}

func TestVerifyExpired(t *testing.T) {
	window := 30 * time.Minute
	// Token generated at 11:00 (window floor = 11:00)
	genTime := time.Date(2026, 3, 13, 11, 0, 0, 0, time.UTC)
	tok := Generate(testKey, genTime, window, "")

	// Verified at 12:05 — two windows later (current = 12:00, previous = 11:30)
	verifyTime := time.Date(2026, 3, 13, 12, 5, 0, 0, time.UTC)
	must.False(t, Verify(testKey, tok, verifyTime, window, ""))
}

func TestVerifyWrongKey(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute
	tok := Generate(testKey, now, window, "")

	otherKey := []byte("different-key-32-bytes-different!")
	must.False(t, Verify(otherKey, tok, now, window, ""))
}

func TestVerifyGarbageToken(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	must.False(t, Verify(testKey, "not-a-valid-token", now, window, ""))
}

func TestVerifyWrongLength(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	// Old-format 64 hex char token should fail length check.
	must.False(t, Verify(testKey, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", now, window, ""))
}

func TestDifferentKeys(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	tok1 := Generate(testKey, now, window, "")
	must.False(t, Verify([]byte("different-key-32-bytes-different!"), tok1, now, window, ""))
}

func TestScopeBoundToken(t *testing.T) {
	now := time.Date(2026, 3, 13, 12, 0, 0, 0, time.UTC)
	window := 30 * time.Minute

	tokWorker := Generate(testKey, now, window, "worker")
	tokServer := Generate(testKey, now, window, "server")
	tokEmpty := Generate(testKey, now, window, "")

	// Token verifies only with matching scope.
	must.True(t, Verify(testKey, tokWorker, now, window, "worker"))
	must.False(t, Verify(testKey, tokWorker, now, window, "server"))
	must.False(t, Verify(testKey, tokWorker, now, window, ""))

	// Server token verifies only with server scope.
	must.True(t, Verify(testKey, tokServer, now, window, "server"))
	must.False(t, Verify(testKey, tokServer, now, window, "worker"))

	// Empty-scope token only verifies with empty scope.
	must.True(t, Verify(testKey, tokEmpty, now, window, ""))
	must.False(t, Verify(testKey, tokEmpty, now, window, "worker"))
}
