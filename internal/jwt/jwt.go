// Package jwt signs JWTs with HKDF-derived Ed25519 keys.
// Follows the Consul auto_config pattern: intro tokens are JWTs signed with
// a pre-shared key, presented during agent startup to authorize automatic
// cluster joining. Reference: https://developer.hashicorp.com/consul/docs/agent/config/config-files#auto_config
package jwt

import (
	"crypto/ed25519"
	"fmt"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

// Sign creates a signed JWT with the given claims.
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
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("sign JWT: %w", err)
	}
	return signed, nil
}
