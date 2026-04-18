package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/pigeon-as/pigeon-enroll/internal/tpm"
	enrollv1 "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
)

func ekCredentialFrom(ch *enrollv1.TPMChallenge) attest.EncryptedCredential {
	return attest.EncryptedCredential{Credential: ch.Credential, Secret: ch.Secret}
}

func cmdRegister(args []string) int {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	cf := registerClientFlags(fs)
	tlsBundle := fs.String("tls", "", "bootstrap client cert+key bundle (from ConfigDrive)")
	identityName := fs.String("identity", "", "identity name to register as")
	subject := fs.String("subject", "", "subject (e.g. hostname) for the identity cert")
	tokenIn := fs.String("token", "", "HMAC bootstrap token, or @file to read it from a file")
	skipTPM := fs.Bool("skip-tpm", false, "skip TPM attestation (for dev/testing only)")
	timeout := fs.Duration("timeout", 2*time.Minute, "register timeout")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *identityName == "" || *subject == "" {
		fmt.Fprintln(os.Stderr, "-identity and -subject are required")
		return 2
	}
	tokBytes, err := readValueOrFile(*tokenIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read token: %v\n", err)
		return 1
	}
	token := strings.TrimSpace(string(tokBytes))

	conn, err := dialServer(cf.addr, cf.ca, *tlsBundle)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		return 1
	}
	defer conn.Close()

	client := enrollv1.NewEnrollClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	stream, err := client.Register(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open stream: %v\n", err)
		return 1
	}

	params := &enrollv1.RegisterParams{
		Identity: *identityName,
		Subject:  *subject,
	}
	if token != "" {
		params.Hmac = &enrollv1.HMACEvidence{Token: token, Scope: *identityName}
	}
	if *tlsBundle != "" {
		params.BootstrapCert = &enrollv1.BootstrapCertEvidence{}
	}

	var tpmSess *tpm.Session
	if !*skipTPM && tpm.Available() {
		s, err := tpm.Open()
		if err != nil {
			fmt.Fprintf(os.Stderr, "open TPM: %v\n", err)
			return 1
		}
		defer s.Close()
		tpmSess = s

		akParams := s.AKParams()
		var ekCert []byte
		if ec := s.EKCertificate(); ec != nil {
			ekCert = ec.Raw
		}
		ekPub, err := x509.MarshalPKIXPublicKey(s.EKPublic())
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal EK public: %v\n", err)
			return 1
		}
		params.Tpm = &enrollv1.TPMEvidence{
			EkPublic:            ekPub,
			EkCert:              ekCert,
			AkPublic:            akParams.Public,
			AkCreateData:        akParams.CreateData,
			AkCreateAttestation: akParams.CreateAttestation,
			AkCreateSignature:   akParams.CreateSignature,
		}
	}

	// Client-generated keypair + CSR: the server signs the public key, we keep
	// the private key local.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate keypair: %v\n", err)
		return 1
	}
	_ = pub
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: *subject},
	}, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create csr: %v\n", err)
		return 1
	}
	params.CsrDer = csrDER

	if err := stream.Send(&enrollv1.RegisterRequest{
		Step: &enrollv1.RegisterRequest_Params{Params: params},
	}); err != nil {
		fmt.Fprintf(os.Stderr, "send params: %v\n", err)
		return 1
	}

	// Drive the Register stream until Result or EOF.
	var result *enrollv1.RegisterResult
	for {
		resp, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "recv: %v\n", err)
			return 1
		}
		switch s := resp.Step.(type) {
		case *enrollv1.RegisterResponse_Challenge:
			if tpmSess == nil {
				fmt.Fprintln(os.Stderr, "server issued TPM challenge but TPM session is not open")
				return 1
			}
			secret, err := tpmSess.ActivateCredential(ekCredentialFrom(s.Challenge))
			if err != nil {
				fmt.Fprintf(os.Stderr, "activate credential: %v\n", err)
				return 1
			}
			if err := stream.Send(&enrollv1.RegisterRequest{
				Step: &enrollv1.RegisterRequest_ChallengeResponse{ChallengeResponse: secret},
			}); err != nil {
				fmt.Fprintf(os.Stderr, "send challenge response: %v\n", err)
				return 1
			}
		case *enrollv1.RegisterResponse_Result:
			result = s.Result
			if err := stream.CloseSend(); err != nil {
				// best effort
				_ = err
			}
			// fall through; break out of recv loop
		default:
			fmt.Fprintf(os.Stderr, "unexpected response step %T\n", s)
			return 1
		}
		if result != nil {
			break
		}
	}
	if result == nil {
		fmt.Fprintln(os.Stderr, "register: no result received")
		return 1
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: mustMarshalPKCS8(priv),
	})

	if err := writeIdentityBundle(cf.identityDir, result.CertPem, keyPEM, result.CaBundlePem); err != nil {
		fmt.Fprintf(os.Stderr, "write identity: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "registered as %s (renew in %ds, expires in %ds)\n",
		*subject, result.RenewAfterSeconds, result.ExpiresInSeconds)
	return 0
}

func mustMarshalPKCS8(priv ed25519.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(err)
	}
	return der
}

// writeIdentityBundle writes the four identity files atomically. cert.pem is
// written last so downstream path watchers (pigeon-template-bootstrap.path)
// only fire once the full bundle is on disk.
func writeIdentityBundle(dir string, certPEM, keyPEM, caPEM []byte) error {
	if dir == "" {
		return errors.New("output dir is empty")
	}
	bundle := append(append([]byte{}, certPEM...), keyPEM...)
	files := []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{
		{identityKeyPath(dir), keyPEM, 0o600},
		{identityCAPath(dir), caPEM, 0o644},
		{identityBundlePath(dir), bundle, 0o600},
		{identityCertPath(dir), certPEM, 0o644},
	}
	for _, f := range files {
		if err := atomicfile.Write(f.path, f.content, f.mode); err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
	}
	return nil
}
