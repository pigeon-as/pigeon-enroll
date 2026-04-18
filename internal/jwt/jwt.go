// Package jwt signs JWTs with HKDF-derived Ed25519 keys.
// Follows the Consul auto_config pattern: intro tokens are JWTs signed with
// a pre-shared key, presented during agent startup to authorize automatic
// cluster joining. Reference: https://developer.hashicorp.com/consul/docs/agent/config/config-files#auto_config
package jwt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// KeyID returns the deterministic key identifier for a JWT signing key. The
// `kid` is the first 16 base64url-nopad characters of SHA-256 over the
// public key bytes — small enough to fit in a header, stable across restarts
// (HKDF-derived keys are fixed under a fixed IKM), and a shape a future JWKS
// publisher can replay. Matches the SPIFFE JWT-SVID expectation that every
// signed token carries a `kid` that a verifier can key into a JWKS.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return base64.RawURLEncoding.EncodeToString(sum[:])[:16]
}

// Sign creates a signed JWT with the given claims. The header carries a
// `kid` derived from the public key so verifiers can select the right key
// from a JWKS without out-of-band coordination.
func Sign(key ed25519.PrivateKey, issuer, audience, subject string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := gojwt.RegisteredClaims{
		Issuer:    issuer,
		Audience:  gojwt.ClaimStrings{audience},
		Subject:   subject,
		IssuedAt:  gojwt.NewNumericDate(now),
		NotBefore: gojwt.NewNumericDate(now.Add(-5 * time.Minute)),
		ExpiresAt: gojwt.NewNumericDate(now.Add(ttl)),
	}
	token := gojwt.NewWithClaims(gojwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = KeyID(key.Public().(ed25519.PublicKey))
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}
