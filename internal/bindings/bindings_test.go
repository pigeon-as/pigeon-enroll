package bindings

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

var testIKM = []byte("0123456789abcdef0123456789abcdef")

func newStore(t *testing.T, path string) *Store {
	t.Helper()
	s, err := New(path, testIKM, nil)
	must.NoError(t, err)
	return s
}

func TestBindAndLookup(t *testing.T) {
	s := newStore(t, "")

	_, ok := s.Lookup("ek1")
	must.False(t, ok)

	must.NoError(t, s.Bind("ek1", "control_plane"))

	r, ok := s.Lookup("ek1")
	must.True(t, ok)
	must.Eq(t, "control_plane", r.Identity)
	must.Eq(t, "ek1", r.EKHash)
	must.False(t, r.FirstSeen.IsZero())
	must.NotEq(t, "", r.MAC)
}

func TestBindSameIdentityIsIdempotent(t *testing.T) {
	s := newStore(t, "")

	must.NoError(t, s.Bind("ek1", "worker"))
	first, _ := s.Lookup("ek1")

	must.NoError(t, s.Bind("ek1", "worker"))
	second, _ := s.Lookup("ek1")

	must.Eq(t, first.FirstSeen, second.FirstSeen)
	must.True(t, !second.LastSeen.Before(first.LastSeen))
}

func TestBindDifferentIdentityRejected(t *testing.T) {
	s := newStore(t, "")

	must.NoError(t, s.Bind("ek1", "worker"))

	err := s.Bind("ek1", "control_plane")
	must.True(t, errors.Is(err, ErrIdentityMismatch))
}

func TestTouchRequiresExistingBinding(t *testing.T) {
	s := newStore(t, "")

	err := s.Touch("ek1", "worker")
	must.ErrorContains(t, err, "not bound")

	must.NoError(t, s.Bind("ek1", "worker"))
	must.NoError(t, s.Touch("ek1", "worker"))

	err = s.Touch("ek1", "control_plane")
	must.True(t, errors.Is(err, ErrIdentityMismatch))
}

func TestPersistSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings")

	s1 := newStore(t, path)
	must.NoError(t, s1.Bind("ek1", "control_plane"))
	must.NoError(t, s1.Bind("ek2", "worker"))

	s2 := newStore(t, path)

	r, ok := s2.Lookup("ek1")
	must.True(t, ok)
	must.Eq(t, "control_plane", r.Identity)

	r, ok = s2.Lookup("ek2")
	must.True(t, ok)
	must.Eq(t, "worker", r.Identity)

	// Rebind same identity should update last_seen.
	must.NoError(t, s2.Bind("ek1", "control_plane"))

	// Rebind different identity still rejected after reload.
	err := s2.Bind("ek1", "worker")
	must.True(t, errors.Is(err, ErrIdentityMismatch))
}

func TestRemoveClearsBinding(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings")

	s1 := newStore(t, path)
	must.NoError(t, s1.Bind("ek1", "worker"))
	must.NoError(t, s1.Remove("ek1"))

	_, ok := s1.Lookup("ek1")
	must.False(t, ok)

	// Survives restart (file rewritten).
	s2 := newStore(t, path)
	_, ok = s2.Lookup("ek1")
	must.False(t, ok)
}

func TestList(t *testing.T) {
	s := newStore(t, "")
	must.NoError(t, s.Bind("ek1", "worker"))
	must.NoError(t, s.Bind("ek2", "control_plane"))

	recs := s.List()
	must.Len(t, 2, recs)
}

func TestLoadRejectsTamperedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings")

	// Seed a legitimate record via the store so the file has a valid line.
	s1 := newStore(t, path)
	must.NoError(t, s1.Bind("ek-good", "worker"))

	// Append a hand-crafted record whose MAC doesn't match the fields.
	tampered := Record{
		EKHash:    "ek-evil",
		Identity:  "control_plane",
		FirstSeen: time.Now().UTC(),
		LastSeen:  time.Now().UTC(),
		MAC:       "deadbeef",
	}
	b, err := json.Marshal(tampered)
	must.NoError(t, err)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	must.NoError(t, err)
	_, _ = f.Write(append(b, '\n'))
	must.NoError(t, f.Close())

	// Reload: good record survives, tampered one is dropped.
	s2 := newStore(t, path)
	_, ok := s2.Lookup("ek-good")
	must.True(t, ok)
	_, ok = s2.Lookup("ek-evil")
	must.False(t, ok)
}

func TestLoadRejectsDifferentIKMMAC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bindings")

	// Record written with testIKM.
	s1 := newStore(t, path)
	must.NoError(t, s1.Bind("ek1", "worker"))

	// Reload with a different IKM — the record's MAC can't verify.
	other := []byte("fedcba9876543210fedcba9876543210")
	s2, err := New(path, other, nil)
	must.NoError(t, err)
	_, ok := s2.Lookup("ek1")
	must.False(t, ok)
}
