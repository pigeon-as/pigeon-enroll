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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
)

// HKDFInfoBindingsMAC namespaces the HMAC key that authenticates each
// binding record on disk. Versioned (v1) to allow future rotation.
const HKDFInfoBindingsMAC = "pigeon-enroll bindings hmac key v1"

// ErrIdentityMismatch is returned when a TPM that is already bound to one
// identity attempts to register as a different identity.
var ErrIdentityMismatch = errors.New("ek already bound to a different identity")

// Record is one EK→identity binding. Persisted as JSONL on disk.
type Record struct {
	EKHash    string    `json:"ek_hash"`
	Identity  string    `json:"identity"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	MAC       string    `json:"mac"` // hex HMAC-SHA256 over canonical PAE of the other fields
}

// Store holds the EK→identity bindings. Safe for concurrent use.
//
// Each record carries an HMAC-SHA256 keyed from the enrollment key IKM via
// HKDF (info = HKDFInfoBindingsMAC). Records that fail MAC verification on
// load are skipped with a WARN — this detects out-of-band tampering of the
// JSONL file by anyone who gains write access to /var/lib/pigeon. The MAC
// does not defend against an attacker who already holds the IKM.
type Store struct {
	mu     sync.Mutex
	recs   map[string]Record
	path   string // empty = in-memory only
	macKey []byte
	logger *slog.Logger
}

// New loads (or creates) a bindings store at path. ikm is the enrollment
// key; the per-record MAC key is HKDF-derived from it. If path is empty
// the store is memory-only. If logger is nil, slog.Default() is used.
func New(path string, ikm []byte, logger *slog.Logger) (*Store, error) {
	macKey, err := deriveMACKey(ikm)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Store{
		recs:   make(map[string]Record),
		path:   path,
		macKey: macKey,
		logger: logger,
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

func deriveMACKey(ikm []byte) ([]byte, error) {
	if len(ikm) != 32 {
		return nil, fmt.Errorf("enrollment key must be 32 bytes, got %d", len(ikm))
	}
	r := hkdf.New(sha256.New, ikm, nil, []byte(HKDFInfoBindingsMAC))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("derive bindings mac key: %w", err)
	}
	return key, nil
}

// macInput assembles the HMAC input using PAE-style length-prefixing (same
// pattern as internal/token) so no field can be manipulated via
// canonicalization. Fields are ordered ek_hash, identity, first_seen,
// last_seen; timestamps use RFC3339 nano for stability across round-trips.
func macInput(ekHash, identity string, firstSeen, lastSeen time.Time) []byte {
	parts := []string{
		ekHash,
		identity,
		firstSeen.UTC().Format(time.RFC3339Nano),
		lastSeen.UTC().Format(time.RFC3339Nano),
	}
	var buf []byte
	var count [4]byte
	binary.BigEndian.PutUint32(count[:], uint32(len(parts)))
	buf = append(buf, count[:]...)
	var lenBuf [4]byte
	for _, p := range parts {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(p)))
		buf = append(buf, lenBuf[:]...)
		buf = append(buf, []byte(p)...)
	}
	return buf
}

func (s *Store) computeMAC(r Record) string {
	m := hmac.New(sha256.New, s.macKey)
	m.Write(macInput(r.EKHash, r.Identity, r.FirstSeen, r.LastSeen))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Store) verifyMAC(r Record) bool {
	got, err := hex.DecodeString(r.MAC)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, s.macKey)
	m.Write(macInput(r.EKHash, r.Identity, r.FirstSeen, r.LastSeen))
	return hmac.Equal(got, m.Sum(nil))
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
//
// Persistence order is disk-first: the JSONL append is fsynced before the
// in-memory map is updated. A crash between append and mutation is safe
// (replay on restart reconstructs the map); a failed append leaves the
// map untouched, preserving binding immutability across transient IO errors.
func (s *Store) Bind(ekHash, identity string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.recs[ekHash]; ok {
		if existing.Identity != identity {
			return fmt.Errorf("%w %q", ErrIdentityMismatch, existing.Identity)
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
	rec.MAC = s.computeMAC(rec)
	if err := s.appendLocked(rec); err != nil {
		return err
	}
	s.recs[ekHash] = rec
	return nil
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
		return fmt.Errorf("%w %q", ErrIdentityMismatch, rec.Identity)
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
	rec.MAC = s.computeMAC(rec)
	if err := s.appendLocked(rec); err != nil {
		return err
	}
	s.recs[ekHash] = rec
	return nil
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
	// Bindings records are tiny but future-proof against large timestamps
	// and operator-appended comments by bumping the default 64KiB line cap.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var loaded, skippedMalformed, skippedMAC int
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			s.logger.Warn("bindings: skip malformed record", "error", err)
			skippedMalformed++
			continue
		}
		if !s.verifyMAC(rec) {
			s.logger.Warn("bindings: skip record with bad mac (tampering suspected)",
				"ek_hash", rec.EKHash)
			skippedMAC++
			continue
		}
		// Later entries overwrite earlier ones (last-write-wins replay).
		s.recs[rec.EKHash] = rec
		loaded++
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	// Aggregated summary: quick operator signal, especially after IKM
	// rotation (every prior record's MAC fails in one batch).
	if skippedMalformed+skippedMAC > 0 {
		s.logger.Warn("bindings: load summary",
			"loaded", loaded,
			"skipped_malformed", skippedMalformed,
			"skipped_bad_mac", skippedMAC)
	}
	return nil
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
