// Package token implements HMAC-based time-windowed tokens for enrollment.
//
// Tokens are HMAC-SHA256(key, counter) where counter = floor(now / window).
// Verification checks the current and previous window to tolerate clock skew
// and delivery latency (e.g. OVH server provisioning takes 5-15 minutes).
package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// Generate computes a time-windowed HMAC token. Empty scope is valid.
func Generate(key []byte, now time.Time, window time.Duration, scope string) string {
	counter := uint64(now.Unix()) / uint64(window.Seconds())
	return hex.EncodeToString(computeMAC(key, counter, scope))
}

// Verify checks a token against the current and previous time window.
// Hex-decodes first for constant-time comparison on raw bytes.
func Verify(key []byte, tok string, now time.Time, window time.Duration, scope string) bool {
	got, err := hex.DecodeString(tok)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	counter := uint64(now.Unix()) / uint64(window.Seconds())
	if hmac.Equal(got, computeMAC(key, counter, scope)) {
		return true
	}
	if counter > 0 {
		return hmac.Equal(got, computeMAC(key, counter-1, scope))
	}
	return false
}

// computeMAC produces raw HMAC-SHA256 bytes.
func computeMAC(key []byte, counter uint64, scope string) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha256.New, key)
	mac.Write(buf[:])
	mac.Write([]byte(scope))
	return mac.Sum(nil)
}
