package jwt

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	gojwt "github.com/golang-jwt/jwt/v5"
	"github.com/shoenig/test/must"
)

func TestSign_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(t, err)

	signed, err := Sign(priv, "test-issuer", "test-audience", "host-01", 10*time.Minute)
	must.NoError(t, err)

	token, err := gojwt.Parse(signed, func(t *gojwt.Token) (any, error) {
		return pub, nil
	})
	must.NoError(t, err)
	must.True(t, token.Valid)

	iss, _ := token.Claims.GetIssuer()
	must.EqOp(t, "test-issuer", iss)

	aud, _ := token.Claims.GetAudience()
	must.SliceLen(t, 1, aud)
	must.EqOp(t, "test-audience", aud[0])

	sub, _ := token.Claims.GetSubject()
	must.EqOp(t, "host-01", sub)

	exp, _ := token.Claims.GetExpirationTime()
	must.NotNil(t, exp)

	delta := time.Until(exp.Time)
	must.Between(t, 9*time.Minute, delta, 11*time.Minute)
}

func TestSign_KidHeaderIsDeterministic(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	must.NoError(t, err)

	signed, err := Sign(priv, "iss", "aud", "sub", time.Hour)
	must.NoError(t, err)

	token, _, err := gojwt.NewParser().ParseUnverified(signed, gojwt.MapClaims{})
	must.NoError(t, err)

	kid, ok := token.Header["kid"].(string)
	must.True(t, ok)
	must.EqOp(t, KeyID(pub), kid)
	must.EqOp(t, 16, len(kid))
}

func TestSign_WrongKey(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	signed, err := Sign(priv, "iss", "aud", "sub", time.Hour)
	must.NoError(t, err)

	_, err = gojwt.Parse(signed, func(t *gojwt.Token) (any, error) {
		return otherPub, nil
	})
	must.Error(t, err)
}
