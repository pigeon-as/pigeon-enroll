// Package bindings records the pairing between a TPM Endorsement Key and an
// identity the first time that TPM registers. On subsequent register calls
// from the same TPM the server can recognise the host and reissue its
// identity cert without requiring a fresh HMAC token — the SPIRE
// rebootstrap pattern: original NodeAttestor (TPM) re-runs, no operator
// token needed.
//
// The store is append-only JSON lines on disk; in-memory it is a map keyed
// by EK hash. Records are immutable once written: an EK cannot be re-bound
// to a different identity. This prevents identity-hopping even if an
// operator mints a token for the wrong identity.
package bindings

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
)

// ErrIdentityMismatch is returned when a TPM that is already bound to one
// identity attempts to register as a different identity.
var ErrIdentityMismatch = errors.New("ek already bound to a different identity")

// Record is one EK→identity binding.
type Record struct {
	EKHash    string    `json:"ek_hash"`
	Identity  string    `json:"identity"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// Store holds the EK→identity bindings. Safe for concurrent use.
type Store struct {
	mu   sync.Mutex
	recs map[string]Record
	path string // empty = in-memory only
}

// New loads (or creates) a bindings store at path. If path is empty the
// store is memory-only.
func New(path string) (*Store, error) {
	s := &Store{
		recs: make(map[string]Record),
		path: path,
	}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("create bindings directory: %w", err)
		}
		if err := s.loadFile(); err != nil {
			return nil, fmt.Errorf("load bindings: %w", err)
		}
	}
	return s, nil
}

// Lookup returns the current binding for ekHash, or ok=false if none.
func (s *Store) Lookup(ekHash string) (Record, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.recs[ekHash]
	return r, ok
}

// Bind records a first-time binding for ekHash → identity. It is an error
// to call Bind for an EK that already has a record; callers should Lookup
// first and use Touch for known-same-identity refresh.
func (s *Store) Bind(ekHash, identity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.recs[ekHash]; ok {
		if existing.Identity != identity {
			return fmt.Errorf("%w: bound to %q", ErrIdentityMismatch, existing.Identity)
		}
		return s.touchLocked(ekHash)
	}
	now := time.Now().UTC()
	rec := Record{
		EKHash:    ekHash,
		Identity:  identity,
		FirstSeen: now,
		LastSeen:  now,
	}
	s.recs[ekHash] = rec
	return s.appendLocked(rec)
}

// Touch refreshes the last_seen timestamp for an existing binding. Returns
// ErrIdentityMismatch if the stored identity does not match.
func (s *Store) Touch(ekHash, identity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[ekHash]
	if !ok {
		return fmt.Errorf("ek not bound")
	}
	if rec.Identity != identity {
		return fmt.Errorf("%w: bound to %q", ErrIdentityMismatch, rec.Identity)
	}
	return s.touchLocked(ekHash)
}

// Remove deletes the binding for ekHash. Used for operator-driven revocation.
func (s *Store) Remove(ekHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.recs[ekHash]; !ok {
		return nil
	}
	delete(s.recs, ekHash)
	return s.rewriteLocked()
}

// List returns a snapshot of all current bindings.
func (s *Store) List() []Record {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Record, 0, len(s.recs))
	for _, r := range s.recs {
		out = append(out, r)
	}
	return out
}

func (s *Store) touchLocked(ekHash string) error {
	rec := s.recs[ekHash]
	rec.LastSeen = time.Now().UTC()
	s.recs[ekHash] = rec
	return s.appendLocked(rec)
}

func (s *Store) loadFile() error {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		// Later entries overwrite earlier ones (append-only semantics).
		s.recs[rec.EKHash] = rec
	}
	return scanner.Err()
}

func (s *Store) appendLocked(rec Record) (err error) {
	if s.path == "" {
		return nil
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if _, err := f.Write(b); err != nil {
		return err
	}
	return f.Sync()
}

func (s *Store) rewriteLocked() error {
	if s.path == "" {
		return nil
	}
	var buf []byte
	for _, rec := range s.recs {
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		buf = append(buf, b...)
		buf = append(buf, '\n')
	}
	return atomicfile.Write(s.path, buf, 0o600)
}
