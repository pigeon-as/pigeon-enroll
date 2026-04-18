// Package attestor implements SPIFFE-style node attestors for pigeon-enroll.
//
// An attestor validates a single piece of evidence (TPM credential activation,
// HMAC bootstrap token, bootstrap client cert) supplied by a node that is
// registering for an identity. An Identity references one or more attestors;
// all must pass for Register to succeed.
package attestor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	goattest "github.com/google/go-attestation/attest"
	attestpkg "github.com/pigeon-as/pigeon-enroll/internal/attest"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/nonce"
	"github.com/pigeon-as/pigeon-enroll/internal/token"
	enrollv1 "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
)

// Evidence is what the node supplies with its Register request plus context
// derived from the TLS connection. Individual attestors read only the fields
// they care about.
type Evidence struct {
	TPM           *enrollv1.TPMEvidence
	HMAC          *enrollv1.HMACEvidence
	BootstrapCert *enrollv1.BootstrapCertEvidence
	PeerCerts     []*x509.Certificate // client cert chain from TLS state
}

// Result is the attestor's opinion of the caller's identity. The `Subject`
// field is purely advisory (for audit logging, e.g. "EK:abc123…"); the
// identity cert's CN is the client-supplied subject from RegisterParams.
type Result struct {
	Subject string
}

// Challenger lets the TPM attestor round-trip a credential activation
// challenge through the gRPC Register stream. Non-TPM attestors ignore it.
type Challenger interface {
	Challenge(ctx context.Context, c *enrollv1.TPMChallenge) ([]byte, error)
}

// Attestor is the pluggable interface implemented by each attestor kind.
type Attestor interface {
	Kind() string
	Verify(ctx context.Context, ev Evidence, subject string, ch Challenger) (*Result, error)
}

// Build constructs attestors from config. `nonces` and `bootstrapCAs` may be
// nil if the corresponding attestors are not configured.
func Build(cfg *config.Config, nonces *nonce.Store, bootstrapCAs *x509.CertPool) (map[string]Attestor, error) {
	out := map[string]Attestor{}
	for kind, a := range cfg.Attestors {
		switch kind {
		case "tpm":
			at, err := newTPM(a)
			if err != nil {
				return nil, fmt.Errorf("attestor tpm: %w", err)
			}
			out[kind] = at
		case "hmac":
			if nonces == nil {
				return nil, errors.New("attestor hmac: nonce store required")
			}
			at, err := newHMAC(a, nonces)
			if err != nil {
				return nil, fmt.Errorf("attestor hmac: %w", err)
			}
			out[kind] = at
		case "bootstrap_cert":
			if bootstrapCAs == nil {
				return nil, errors.New("attestor bootstrap_cert: bootstrap CA pool required")
			}
			out[kind] = newBootstrapCert(bootstrapCAs)
		default:
			return nil, fmt.Errorf("unknown attestor kind %q", kind)
		}
	}
	return out, nil
}

// -----------------------------------------------------------------------------
// HMAC

type hmacAttestor struct {
	key    []byte
	window time.Duration
	nonces *nonce.Store
}

func newHMAC(cfg *config.Attestor, nonces *nonce.Store) (*hmacAttestor, error) {
	data, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	key := bytes.TrimRight(data, "\r\n")
	if len(key) == 0 {
		return nil, errors.New("key file is empty")
	}
	return &hmacAttestor{key: key, window: cfg.Window, nonces: nonces}, nil
}

func (h *hmacAttestor) Kind() string { return "hmac" }

func (h *hmacAttestor) Verify(_ context.Context, ev Evidence, subject string, _ Challenger) (*Result, error) {
	if ev.HMAC == nil || ev.HMAC.Token == "" {
		return nil, errors.New("hmac evidence missing")
	}
	if !token.Verify(h.key, ev.HMAC.Token, time.Now(), h.window, ev.HMAC.Scope) {
		return nil, errors.New("invalid hmac token")
	}
	ok, err := h.nonces.Check(ev.HMAC.Token)
	if err != nil {
		return nil, fmt.Errorf("nonce store: %w", err)
	}
	if !ok {
		return nil, errors.New("hmac token already consumed")
	}
	return &Result{Subject: "hmac:" + ev.HMAC.Scope}, nil
}

// -----------------------------------------------------------------------------
// bootstrap_cert

type bootstrapCertAttestor struct {
	pool *x509.CertPool
}

func newBootstrapCert(pool *x509.CertPool) *bootstrapCertAttestor {
	return &bootstrapCertAttestor{pool: pool}
}

func (b *bootstrapCertAttestor) Kind() string { return "bootstrap_cert" }

func (b *bootstrapCertAttestor) Verify(_ context.Context, ev Evidence, _ string, _ Challenger) (*Result, error) {
	if len(ev.PeerCerts) == 0 {
		return nil, errors.New("no peer certificate")
	}
	leaf := ev.PeerCerts[0]
	inters := x509.NewCertPool()
	for _, c := range ev.PeerCerts[1:] {
		inters.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         b.pool,
		Intermediates: inters,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("bootstrap cert verify: %w", err)
	}
	return &Result{Subject: "cert:" + leaf.Subject.CommonName}, nil
}

// -----------------------------------------------------------------------------
// TPM

type tpmAttestor struct {
	validator *attestpkg.EKValidator
}

func newTPM(cfg *config.Attestor) (*tpmAttestor, error) {
	if cfg.EKCAPath == "" && cfg.EKHashPath == "" {
		return nil, errors.New("tpm attestor requires ek_ca_path or ek_hash_path")
	}
	v, err := attestpkg.NewEKValidator(cfg.EKCAPath, cfg.EKHashPath)
	if err != nil {
		return nil, err
	}
	return &tpmAttestor{validator: v}, nil
}

func (t *tpmAttestor) Kind() string { return "tpm" }

func (t *tpmAttestor) Verify(ctx context.Context, ev Evidence, _ string, ch Challenger) (*Result, error) {
	if ev.TPM == nil {
		return nil, errors.New("tpm evidence missing")
	}
	ekPub, err := x509.ParsePKIXPublicKey(ev.TPM.EkPublic)
	if err != nil {
		return nil, fmt.Errorf("parse EK public: %w", err)
	}
	var ekCert *x509.Certificate
	if len(ev.TPM.EkCert) > 0 {
		ekCert, err = x509.ParseCertificate(ev.TPM.EkCert)
		if err != nil {
			return nil, fmt.Errorf("parse EK cert: %w", err)
		}
	}
	if err := t.validator.Validate(ekPub, ekCert); err != nil {
		return nil, err
	}
	ap := goattest.ActivationParameters{
		EK: ekPub,
		AK: goattest.AttestationParameters{
			Public:            ev.TPM.AkPublic,
			CreateData:        ev.TPM.AkCreateData,
			CreateAttestation: ev.TPM.AkCreateAttestation,
			CreateSignature:   ev.TPM.AkCreateSignature,
		},
	}
	secret, encCred, err := ap.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate credential activation: %w", err)
	}
	if ch == nil {
		return nil, errors.New("challenger required for tpm attestor")
	}
	activated, err := ch.Challenge(ctx, &enrollv1.TPMChallenge{
		Credential: encCred.Credential,
		Secret:     encCred.Secret,
	})
	if err != nil {
		return nil, fmt.Errorf("credential activation: %w", err)
	}
	if !hmac.Equal(secret, activated) {
		return nil, errors.New("credential activation mismatch")
	}
	ekHash, err := ekHashHex(ekPub)
	if err != nil {
		return nil, err
	}
	return &Result{Subject: "ek:" + ekHash}, nil
}

func ekHashHex(ekPub any) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(ekPub)
	if err != nil {
		return "", fmt.Errorf("marshal EK public key: %w", err)
	}
	return EKHash(der), nil
}

// EKHash returns the hex-encoded SHA-256 of a PKIX-DER-encoded EK public key.
// Used by the server to key the EK→identity binding store; stable across
// reboots since the EK is fixed in TPM hardware.
func EKHash(ekPubDER []byte) string {
	h := sha256.Sum256(ekPubDER)
	return hex.EncodeToString(h[:])
}
