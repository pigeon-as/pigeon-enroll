package nonce

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCheckRejectsReplay(t *testing.T) {
	s, err := New(time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Check("tok1") {
		t.Fatal("first check should accept")
	}
	if s.Check("tok1") {
		t.Fatal("replay should be rejected")
	}
}

func TestCheckAcceptsDifferentTokens(t *testing.T) {
	s, err := New(time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Check("tok1") {
		t.Fatal("tok1 should be accepted")
	}
	if !s.Check("tok2") {
		t.Fatal("tok2 should be accepted")
	}
}

func TestPersistSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonces")

	s1, err := New(time.Hour, path)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Check("tok1") {
		t.Fatal("first check should accept")
	}

	// Simulate restart: create new store from same file.
	s2, err := New(time.Hour, path)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Check("tok1") {
		t.Fatal("replayed token should be rejected after restart")
	}
	// New token should still work.
	if !s2.Check("tok2") {
		t.Fatal("new token should be accepted")
	}
}

func TestExpiredDroppedOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonces")

	// Use a tiny maxAge so the token expires quickly.
	s1, err := New(50*time.Millisecond, path)
	if err != nil {
		t.Fatal(err)
	}
	if !s1.Check("tok1") {
		t.Fatal("first check should accept")
	}

	// Wait for token to expire.
	time.Sleep(100 * time.Millisecond)

	// Reload: expired token should be dropped.
	s2, err := New(50*time.Millisecond, path)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Check("tok1") {
		t.Fatal("expired token should be accepted again after reload")
	}
}

func TestInMemoryNoPersistence(t *testing.T) {
	s, err := New(time.Hour, "")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Check("tok1") {
		t.Fatal("should accept")
	}
	if s.Check("tok1") {
		t.Fatal("replay should be rejected")
	}
}
