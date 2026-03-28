// Package token implements HMAC-based time-windowed tokens for enrollment.
//
// Each token contains a random nonce for uniqueness (Vault pattern:
// random base + HMAC signature). Format: hex(nonce) || hex(HMAC).
// Verification checks the current and previous window to tolerate clock skew
// and delivery latency (e.g. OVH server provisioning takes 5-15 minutes).
package token

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"time"
)

const (
	// NonceSize is the number of random bytes per token.
	NonceSize = 16
	// nonceHex is the hex-encoded nonce length.
	nonceHex = NonceSize * 2
	// macHex is the hex-encoded HMAC-SHA256 length.
	macHex = sha256.Size * 2
	// TokenLen is the total hex-encoded token length.
	TokenLen = nonceHex + macHex
)

// Generate computes a unique time-windowed HMAC token. Each call produces
// a different token by including a random nonce in the HMAC input.
// Format: hex(nonce) || hex(HMAC-SHA256(key, counter || scope || nonce)).
func Generate(key []byte, now time.Time, window time.Duration, scope string) string {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		panic("crypto/rand: " + err.Error())
	}
	counter := uint64(now.Unix()) / uint64(window.Seconds())
	mac := computeMAC(key, counter, scope, nonce)
	return hex.EncodeToString(nonce) + hex.EncodeToString(mac)
}

// Verify checks a token against the current and previous time window.
// Extracts the nonce, recomputes the HMAC, and uses constant-time comparison.
func Verify(key []byte, tok string, now time.Time, window time.Duration, scope string) bool {
	if len(tok) != TokenLen {
		return false
	}
	nonce, err := hex.DecodeString(tok[:nonceHex])
	if err != nil {
		return false
	}
	got, err := hex.DecodeString(tok[nonceHex:])
	if err != nil || len(got) != sha256.Size {
		return false
	}
	counter := uint64(now.Unix()) / uint64(window.Seconds())
	if hmac.Equal(got, computeMAC(key, counter, scope, nonce)) {
		return true
	}
	if counter > 0 {
		return hmac.Equal(got, computeMAC(key, counter-1, scope, nonce))
	}
	return false
}

// computeMAC produces raw HMAC-SHA256 bytes.
func computeMAC(key []byte, counter uint64, scope string, nonce []byte) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha256.New, key)
	mac.Write(buf[:])
	mac.Write([]byte(scope))
	mac.Write(nonce)
	return mac.Sum(nil)
}
