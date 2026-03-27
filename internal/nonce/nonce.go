// Package nonce tracks consumed HMAC tokens to enforce one-time use.
// Tokens are stored in memory and optionally persisted to disk so that
// replay protection survives restarts. Tokens are SHA-256 hashed before
// storage to prevent disk-level replay.
package nonce

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Store tracks consumed tokens. Safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	maxAge    time.Duration
	lastPurge time.Time
	path      string // empty = in-memory only
}

// New creates a nonce store. maxAge is the maximum lifetime of a token
// (typically 2x the HMAC window, since verify checks current + previous).
// If path is non-empty, nonces are persisted to disk and loaded on startup.
func New(maxAge time.Duration, path string) (*Store, error) {
	s := &Store{
		seen:   make(map[string]time.Time),
		maxAge: maxAge,
		path:   path,
	}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, fmt.Errorf("create nonce directory: %w", err)
		}
		if err := s.loadFile(); err != nil {
			return nil, fmt.Errorf("load nonces: %w", err)
		}
	}
	return s, nil
}

// Check returns true if the token has NOT been seen before (and marks it).
func (s *Store) Check(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Since(s.lastPurge) > s.maxAge/2 {
		s.purge()
		s.lastPurge = time.Now()
	}

	h := hashToken(token)
	if _, exists := s.seen[h]; exists {
		return false
	}
	now := time.Now()
	s.seen[h] = now

	if s.path != "" {
		// Best-effort append — failure here doesn't block the claim.
		// On restart, the token window will have expired anyway for
		// tokens that failed to persist.
		_ = s.appendEntry(h, now)
	}
	return true
}

// hashToken returns the hex-encoded SHA-256 of the token.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// loadFile reads persisted nonces, discarding expired entries.
func (s *Store) loadFile() error {
	f, err := os.Open(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()

	cutoff := time.Now().Add(-s.maxAge)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		parts := strings.SplitN(scanner.Text(), " ", 2)
		if len(parts) != 2 {
			continue
		}
		ts, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			continue
		}
		t := time.Unix(ts, 0)
		if t.Before(cutoff) {
			continue
		}
		s.seen[parts[0]] = t
	}
	return scanner.Err()
}

// appendEntry appends a single nonce entry to the file.
func (s *Store) appendEntry(hash string, t time.Time) error {
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %d\n", hash, t.Unix())
	return err
}

// purge removes expired entries from memory and rewrites the file.
func (s *Store) purge() {
	cutoff := time.Now().Add(-s.maxAge)
	for tok, t := range s.seen {
		if t.Before(cutoff) {
			delete(s.seen, tok)
		}
	}
	if s.path != "" {
		_ = s.rewriteFile()
	}
}

// rewriteFile atomically rewrites the nonce file with current entries.
func (s *Store) rewriteFile() error {
	f, err := os.CreateTemp(filepath.Dir(s.path), ".nonces-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	for hash, t := range s.seen {
		if _, err := fmt.Fprintf(f, "%s %d\n", hash, t.Unix()); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.path)
}
