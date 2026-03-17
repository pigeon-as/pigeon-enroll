// Package nonce tracks consumed HMAC tokens to enforce one-time use.
// Tokens are stored in memory and expire naturally when their time window passes.
package nonce

import (
	"sync"
	"time"
)

// Store tracks consumed tokens. Safe for concurrent use.
type Store struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	maxAge    time.Duration
	lastPurge time.Time
}

// New creates a nonce store. maxAge is the maximum lifetime of a token
// (typically 2x the HMAC window, since verify checks current + previous).
func New(maxAge time.Duration) *Store {
	return &Store{
		seen:   make(map[string]time.Time),
		maxAge: maxAge,
	}
}

// Check returns true if the token has NOT been seen before (and marks it).
func (s *Store) Check(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if time.Since(s.lastPurge) > s.maxAge/2 {
		s.purge()
		s.lastPurge = time.Now()
	}

	if _, exists := s.seen[token]; exists {
		return false
	}
	s.seen[token] = time.Now()
	return true
}

// purge removes expired entries. Called under lock.
func (s *Store) purge() {
	cutoff := time.Now().Add(-s.maxAge)
	for tok, t := range s.seen {
		if t.Before(cutoff) {
			delete(s.seen, tok)
		}
	}
}
