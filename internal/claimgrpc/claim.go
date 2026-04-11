// Package claimgrpc implements the client-side enrollment claim flow via gRPC.
// Follows the SPIRE node attestation pattern: bidirectional stream for
// TPM credential activation (params → challenge → response → result).
package claimgrpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/google/go-attestation/attest"
	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/pigeon-as/pigeon-enroll/internal/tpm"
	pb "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
	"google.golang.org/grpc"
)

// Response is the claim result written to disk as JSON.
type Response struct {
	Secrets map[string]string            `json:"secrets"`
	Vars    map[string]string            `json:"vars"`
	CA      map[string]map[string]string `json:"ca,omitempty"`
	Certs   map[string]map[string]string `json:"certs,omitempty"`
	JWTs    map[string]string            `json:"jwts,omitempty"`
	JWTKeys map[string]string            `json:"jwt_keys,omitempty"`
	Error   string                       `json:"error,omitempty"`
}

// Run performs the enrollment claim and writes secrets to outputPath.
// Set skipTPM to true for dev/testing only.
func Run(ctx context.Context, conn *grpc.ClientConn, token, scope, subject, outputPath string, skipTPM bool, logger *slog.Logger) (*Response, error) {
	client := pb.NewEnrollmentServiceClient(conn)

	stream, err := client.Claim(ctx)
	if err != nil {
		return nil, fmt.Errorf("open claim stream: %w", err)
	}

	if skipTPM {
		logger.Warn("WARNING: --skip-tpm set — TPM attestation disabled, do not use in production")
		return runTokenOnly(stream, token, scope, subject, outputPath)
	}
	return runTPM(stream, token, scope, subject, outputPath, logger)
}

// runTokenOnly sends a token-only claim (no TPM attestation).
func runTokenOnly(stream pb.EnrollmentService_ClaimClient, token, scope, subject, outputPath string) (*Response, error) {
	// Always generate a CSR — it's a public key vehicle for CSR-mode certs.
	// The server assigns CN from config or subject independently (SPIRE pattern).
	csrDER, csrKey, err := generateCSR(subject)
	if err != nil {
		return nil, err
	}

	if err := stream.Send(&pb.ClaimRequest{
		Step: &pb.ClaimRequest_Params{Params: &pb.ClaimParams{
			Token:   token,
			Scope:   scope,
			Subject: subject,
			CsrDer:  csrDER,
		}},
	}); err != nil {
		return nil, fmt.Errorf("send params: %w", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("receive result: %w", err)
	}
	result := resp.GetResult()
	if result == nil {
		return nil, fmt.Errorf("expected result, got challenge (server requires TPM?)")
	}
	return writeResult(result, outputPath, csrKey)
}

// runTPM performs the full TPM attestation claim flow on the stream.
func runTPM(stream pb.EnrollmentService_ClaimClient, token, scope, subject, outputPath string, logger *slog.Logger) (*Response, error) {
	// Open TPM and create ephemeral AK.
	sess, err := tpm.Open()
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}
	defer sess.Close()

	ekHash, _ := sess.EKHash()
	logger.Info("TPM session opened", "ek", ekHash)

	// Marshal EK public key.
	ekPub := sess.EKPublic()
	ekDER, err := x509.MarshalPKIXPublicKey(ekPub)
	if err != nil {
		return nil, fmt.Errorf("marshal EK public key: %w", err)
	}

	// Optional EK certificate.
	var ekCertDER []byte
	if cert := sess.EKCertificate(); cert != nil {
		ekCertDER = cert.Raw
	}

	akParams := sess.AKParams()

	// Always generate a CSR — it's a public key vehicle for CSR-mode certs.
	// The server assigns CN from config or subject independently (SPIRE pattern).
	csrDER, csrKey, csrErr := generateCSR(subject)
	if csrErr != nil {
		return nil, csrErr
	}

	// Send initial params with TPM data + CSR (SPIRE pattern: everything in first message).
	if err := stream.Send(&pb.ClaimRequest{
		Step: &pb.ClaimRequest_Params{Params: &pb.ClaimParams{
			Token:   token,
			Scope:   scope,
			Subject: subject,
			Tpm: &pb.TPMParams{
				EkPublic:            ekDER,
				EkCert:              ekCertDER,
				AkPublic:            akParams.Public,
				AkCreateData:        akParams.CreateData,
				AkCreateAttestation: akParams.CreateAttestation,
				AkCreateSignature:   akParams.CreateSignature,
			},
			CsrDer: csrDER,
		}},
	}); err != nil {
		return nil, fmt.Errorf("send params: %w", err)
	}

	// Receive challenge.
	resp, err := stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("receive challenge: %w", err)
	}
	challenge := resp.GetChallenge()
	if challenge == nil {
		// Server didn't challenge — maybe direct result (shouldn't happen with TPM params).
		if result := resp.GetResult(); result != nil {
			return writeResult(result, outputPath, csrKey)
		}
		return nil, fmt.Errorf("unexpected response from server")
	}

	logger.Info("TPM challenge received, activating credential")

	// Activate credential (proves AK is on same TPM as EK).
	activated, err := sess.ActivateCredential(attest.EncryptedCredential{
		Credential: challenge.Credential,
		Secret:     challenge.Secret,
	})
	if err != nil {
		return nil, fmt.Errorf("activate credential: %w", err)
	}

	logger.Info("TPM attestation complete, sending challenge response")

	// Send challenge response.
	if err := stream.Send(&pb.ClaimRequest{
		Step: &pb.ClaimRequest_ChallengeResponse{ChallengeResponse: activated},
	}); err != nil {
		return nil, fmt.Errorf("send challenge response: %w", err)
	}

	// Receive result.
	resp, err = stream.Recv()
	if err != nil {
		return nil, fmt.Errorf("receive result: %w", err)
	}
	result := resp.GetResult()
	if result == nil {
		return nil, fmt.Errorf("expected result after challenge response")
	}

	return writeResult(result, outputPath, csrKey)
}

// generateCSR creates an Ed25519 keypair and CSR. Returns the DER-encoded CSR
// and the private key (which stays local — only the public key is sent to the server).
func generateCSR(subject string) ([]byte, ed25519.PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}

	tmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: subject},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return csrDER, priv, nil
}

// writeResult converts the proto result to the on-disk JSON format and writes it.
// If csrKey is non-nil, it is attached to CSR-mode certs that have no server-supplied key.
func writeResult(result *pb.ClaimResult, outputPath string, csrKey ed25519.PrivateKey) (*Response, error) {
	resp := &Response{
		Secrets: result.Secrets,
		Vars:    result.Vars,
	}

	// Convert CA proto to JSON format.
	if len(result.Ca) > 0 {
		resp.CA = make(map[string]map[string]string, len(result.Ca))
		for name, ca := range result.Ca {
			entry := map[string]string{"cert_pem": ca.CertPem}
			if ca.PrivateKeyPem != "" {
				entry["private_key_pem"] = ca.PrivateKeyPem
			}
			resp.CA[name] = entry
		}
	}

	// Convert certs proto to JSON format. For CSR-mode certs, attach the local private key.
	if len(result.Certs) > 0 {
		resp.Certs = make(map[string]map[string]string, len(result.Certs))
		for name, cert := range result.Certs {
			entry := map[string]string{"cert_pem": cert.CertPem}
			if cert.KeyPem != "" {
				// Push-mode: server generated and sent the key.
				entry["key_pem"] = cert.KeyPem
			} else if csrKey != nil {
				// CSR-mode: server signed our public key, attach local private key.
				keyDER, err := x509.MarshalPKCS8PrivateKey(csrKey)
				if err != nil {
					return nil, fmt.Errorf("marshal CSR private key: %w", err)
				}
				entry["key_pem"] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
			}
			resp.Certs[name] = entry
		}
	}

	if len(result.Jwts) > 0 {
		resp.JWTs = result.Jwts
	}
	if len(result.JwtKeys) > 0 {
		resp.JWTKeys = result.JwtKeys
	}

	data, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal response: %w", err)
	}

	if err := atomicfile.Write(outputPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write secrets: %w", err)
	}

	return resp, nil
}
