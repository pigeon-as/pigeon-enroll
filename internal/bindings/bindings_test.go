package bindings

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/shoenig/test/must"
)

func TestBindAndLookup(t *testing.T) {
	s, err := New("")
	must.NoError(t, err)

	_, ok := s.Lookup("ek1")
	must.False(t, ok)

	must.NoError(t, s.Bind("ek1", "control_plane"))

	r, ok := s.Lookup("ek1")
	must.True(t, ok)
	must.Eq(t, "control_plane", r.Identity)
	must.Eq(t, "ek1", r.EKHash)
	must.False(t, r.FirstSeen.IsZero())
}

func TestBindSameIdentityIsIdempotent(t *testing.T) {
	s, err := New("")
	must.NoError(t, err)

	must.NoError(t, s.Bind("ek1", "worker"))
	first, _ := s.Lookup("ek1")

	must.NoError(t, s.Bind("ek1", "worker"))
	second, _ := s.Lookup("ek1")

	must.Eq(t, first.FirstSeen, second.FirstSeen)
	must.True(t, !second.LastSeen.Before(first.LastSeen))
}

func TestBindDifferentIdentityRejected(t *testing.T) {
	s, err := New("")
	must.NoError(t, err)

	must.NoError(t, s.Bind("ek1", "worker"))

	err = s.Bind("ek1", "control_plane")
	must.True(t, errors.Is(err, ErrIdentityMismatch))
}

func TestTouchRequiresExistingBinding(t *testing.T) {
	s, err := New("")
	must.NoError(t, err)

	err = s.Touch("ek1", "worker")
	must.ErrorContains(t, err, "not bound")

	must.NoError(t, s.Bind("ek1", "worker"))
	must.NoError(t, s.Touch("ek1", "worker"))

	err = s.Touch("ek1", "control_plane")
	must.True(t, errors.Is(err, ErrIdentityMismatch))
}

func TestPersistSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings")

	s1, err := New(path)
	must.NoError(t, err)
	must.NoError(t, s1.Bind("ek1", "control_plane"))
	must.NoError(t, s1.Bind("ek2", "worker"))

	s2, err := New(path)
	must.NoError(t, err)

	r, ok := s2.Lookup("ek1")
	must.True(t, ok)
	must.Eq(t, "control_plane", r.Identity)

	r, ok = s2.Lookup("ek2")
	must.True(t, ok)
	must.Eq(t, "worker", r.Identity)

	// Rebind same identity should update last_seen.
	must.NoError(t, s2.Bind("ek1", "control_plane"))

	// Rebind different identity still rejected after reload.
	err = s2.Bind("ek1", "worker")
	must.True(t, errors.Is(err, ErrIdentityMismatch))
}

func TestRemoveClearsBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings")

	s1, err := New(path)
	must.NoError(t, err)
	must.NoError(t, s1.Bind("ek1", "worker"))
	must.NoError(t, s1.Remove("ek1"))

	_, ok := s1.Lookup("ek1")
	must.False(t, ok)

	// Survives restart (file rewritten).
	s2, err := New(path)
	must.NoError(t, err)
	_, ok = s2.Lookup("ek1")
	must.False(t, ok)
}

func TestList(t *testing.T) {
	s, err := New("")
	must.NoError(t, err)
	must.NoError(t, s.Bind("ek1", "worker"))
	must.NoError(t, s.Bind("ek2", "control_plane"))

	recs := s.List()
	must.Len(t, 2, recs)
}
