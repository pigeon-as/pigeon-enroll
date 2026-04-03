package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
)

func TestSign_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signed, err := Sign(priv, "test-issuer", "test-audience", "host-01", 10*time.Minute)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	token, err := gojwt.Parse(signed, func(t *gojwt.Token) (any, error) {
		return pub, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !token.Valid {
		t.Fatal("token not valid")
	}

	iss, _ := token.Claims.GetIssuer()
	if iss != "test-issuer" {
		t.Errorf("issuer = %q, want test-issuer", iss)
	}

	aud, _ := token.Claims.GetAudience()
	if len(aud) != 1 || aud[0] != "test-audience" {
		t.Errorf("audience = %v, want [test-audience]", aud)
	}

	sub, _ := token.Claims.GetSubject()
	if sub != "host-01" {
		t.Errorf("subject = %q, want host-01", sub)
	}

	exp, _ := token.Claims.GetExpirationTime()
	if exp == nil {
		t.Fatal("no expiration")
	}
	// Should expire ~10 minutes from now.
	delta := time.Until(exp.Time)
	if delta < 9*time.Minute || delta > 11*time.Minute {
		t.Errorf("expiration delta = %v, want ~10m", delta)
	}
}

func TestSign_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	signed, err := Sign(priv, "iss", "aud", "sub", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	_, err = gojwt.Parse(signed, func(t *gojwt.Token) (any, error) {
		return otherPub, nil
	})
	if err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}
