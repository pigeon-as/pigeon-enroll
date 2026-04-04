package nonce

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

func TestCheckRejectsReplay(t *testing.T) {
	s, err := New(time.Hour, "")
	must.NoError(t, err)

	ok, err := s.Check("tok1")
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("first check should accept"))

	ok, err = s.Check("tok1")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("replay should be rejected"))
}

func TestCheckAcceptsDifferentTokens(t *testing.T) {
	s, err := New(time.Hour, "")
	must.NoError(t, err)

	ok, err := s.Check("tok1")
	must.NoError(t, err)
	must.True(t, ok)

	ok, err = s.Check("tok2")
	must.NoError(t, err)
	must.True(t, ok)
}

func TestPersistSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces")

	s1, err := New(time.Hour, path)
	must.NoError(t, err)

	ok, err := s1.Check("tok1")
	must.NoError(t, err)
	must.True(t, ok)

	// Simulate restart: create new store from same file.
	s2, err := New(time.Hour, path)
	must.NoError(t, err)

	ok, err = s2.Check("tok1")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("replayed token should be rejected after restart"))

	ok, err = s2.Check("tok2")
	must.NoError(t, err)
	must.True(t, ok)
}

func TestExpiredDroppedOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonces")

	s1, err := New(50*time.Millisecond, path)
	must.NoError(t, err)

	ok, err := s1.Check("tok1")
	must.NoError(t, err)
	must.True(t, ok)

	time.Sleep(100 * time.Millisecond)

	// Reload: expired token should be dropped.
	s2, err := New(50*time.Millisecond, path)
	must.NoError(t, err)

	ok, err = s2.Check("tok1")
	must.NoError(t, err)
	must.True(t, ok, must.Sprint("expired token should be accepted again"))
}

func TestInMemoryNoPersistence(t *testing.T) {
	s, err := New(time.Hour, "")
	must.NoError(t, err)

	ok, err := s.Check("tok1")
	must.NoError(t, err)
	must.True(t, ok)

	ok, err = s.Check("tok1")
	must.NoError(t, err)
	must.False(t, ok, must.Sprint("replay should be rejected"))
}
