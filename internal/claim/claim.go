// Package claim implements the client-side enrollment claim flow.
// Follows the SPIRE node attestation pattern: two-round TPM credential
// activation (POST /attest → POST /claim) proves the AK is resident on
// the same TPM as the EK.
// Reference: https://github.com/spiffe/spire/tree/main/pkg/agent/attestor/node
package claim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/go-attestation/attest"
	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/pigeon-as/pigeon-enroll/internal/tpm"
)

// Response is the JSON structure returned by POST /claim.
// Format: {"secrets":{...},"vars":{...}} with optional "ca", "certs", "jwts", and "jwt_keys" fields.
type Response struct {
	Secrets  map[string]string            `json:"secrets"`
	Vars     map[string]string            `json:"vars"`
	CA       map[string]map[string]string `json:"ca,omitempty"`
	Certs    map[string]map[string]string `json:"certs,omitempty"`
	CSRCerts []string                     `json:"csr_certs,omitempty"`
	JWTs     map[string]string            `json:"jwts,omitempty"`
	JWTKeys  map[string]string            `json:"jwt_keys,omitempty"`
	Error    string                       `json:"error,omitempty"`
}

// attestResponse is the JSON structure returned by POST /attest.
type attestResponse struct {
	SessionID  string                    `json:"session_id"`
	Credential attest.EncryptedCredential `json:"credential"`
}

// Run sends a claim request and writes secrets to outputPath.
// Always performs two-round TPM attestation (POST /attest → POST /claim).
// Set skipTPM to true for dev/testing only (logs WARNING, sends token-only claim).
// The url parameter can be either the base URL (e.g. https://host:8443) or
// the full claim URL (e.g. https://host:8443/claim) for backward compatibility.
func Run(client *http.Client, url, token, scope, subject, outputPath string, skipTPM bool, logger *slog.Logger) (*Response, error) {
	baseURL := strings.TrimSuffix(strings.TrimRight(url, "/"), "/claim")

	if skipTPM {
		logger.Warn("WARNING: --skip-tpm set — TPM attestation disabled, do not use in production")
		return runTokenOnly(client, baseURL, token, scope, subject, outputPath)
	}

	return runTPM(client, baseURL, token, scope, subject, outputPath, logger)
}

// runTokenOnly performs a token-only claim without TPM attestation.
// Only used when --skip-tpm is explicitly set (dev/testing).
func runTokenOnly(client *http.Client, baseURL, token, scope, subject, outputPath string) (*Response, error) {
	reqBody := map[string]string{
		"token": token,
	}
	if scope != "" {
		reqBody["scope"] = scope
	}
	if subject != "" {
		reqBody["subject"] = subject
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	result, data, err := doClaimRequest(client, baseURL+"/claim", body)
	if err != nil {
		return nil, err
	}

	if err := atomicfile.Write(outputPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write secrets: %w", err)
	}

	return result, nil
}

// runTPM performs the two-round TPM attestation claim.
func runTPM(client *http.Client, baseURL, token, scope, subject, outputPath string, logger *slog.Logger) (*Response, error) {
	// Step 1: Open TPM and create ephemeral AK.
	sess, err := tpm.Open()
	if err != nil {
		return nil, fmt.Errorf("open TPM: %w", err)
	}
	defer sess.Close()

	ekHash, _ := sess.EKHash()
	logger.Info("TPM session opened", "ek", ekHash)

	// Step 2: Marshal EK public key.
	ekPub := sess.EKPublic()
	ekDER, err := x509.MarshalPKIXPublicKey(ekPub)
	if err != nil {
		return nil, fmt.Errorf("marshal EK public key: %w", err)
	}

	// Step 3: Get optional EK certificate.
	var ekCertDER []byte
	if cert := sess.EKCertificate(); cert != nil {
		ekCertDER = cert.Raw
	}

	// Step 4: POST /attest with token + EK pub + EK cert + AK params.
	attestReq := struct {
		Token    string                       `json:"token"`
		Scope    string                       `json:"scope"`
		Subject  string                       `json:"subject,omitempty"`
		EKPub    []byte                       `json:"ek_pub"`
		EKCert   []byte                       `json:"ek_cert,omitempty"`
		AKParams attest.AttestationParameters `json:"ak_params"`
	}{
		Token:   token,
		Scope:   scope,
		Subject: subject,
		EKPub:    ekDER,
		EKCert:   ekCertDER,
		AKParams: sess.AKParams(),
	}
	attestBody, err := json.Marshal(attestReq)
	if err != nil {
		return nil, fmt.Errorf("marshal attest request: %w", err)
	}

	attestResp, err := client.Post(baseURL+"/attest", "application/json", bytes.NewReader(attestBody))
	if err != nil {
		return nil, fmt.Errorf("POST /attest: %w", err)
	}
	defer attestResp.Body.Close()

	attestData, err := io.ReadAll(io.LimitReader(attestResp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read /attest response: %w", err)
	}
	if attestResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attest failed (%d): %s", attestResp.StatusCode, extractError(attestData, attestResp.Status))
	}

	var ar attestResponse
	if err := json.Unmarshal(attestData, &ar); err != nil {
		return nil, fmt.Errorf("decode attest response: %w", err)
	}

	logger.Info("attestation challenge received", "session", ar.SessionID)

	// Step 5: Activate credential (proves AK is on same TPM as EK).
	activated, err := sess.ActivateCredential(ar.Credential)
	if err != nil {
		return nil, fmt.Errorf("activate credential: %w", err)
	}

	logger.Info("TPM attestation complete, claiming secrets")

	// Step 6: POST /claim with session_id + activated_secret.
	claimReq := struct {
		SessionID       string `json:"session_id"`
		ActivatedSecret []byte `json:"activated_secret"`
	}{
		SessionID:       ar.SessionID,
		ActivatedSecret: activated,
	}
	claimBody, err := json.Marshal(claimReq)
	if err != nil {
		return nil, fmt.Errorf("marshal claim request: %w", err)
	}

	result, data, err := doClaimRequest(client, baseURL+"/claim", claimBody)
	if err != nil {
		return nil, err
	}

	// Step 7: If the server indicates CSR-mode certs, generate keypair and submit CSR.
	if len(result.CSRCerts) > 0 {
		logger.Info("submitting CSR for certs", "certs", result.CSRCerts)
		csrCerts, csrKeyPEMs, err := submitCSR(client, baseURL, ar.SessionID, subject)
		if err != nil {
			return nil, fmt.Errorf("CSR: %w", err)
		}
		// Merge CSR certs into claim response (cert_pem from server, key_pem from local keypair).
		if result.Certs == nil {
			result.Certs = make(map[string]map[string]string)
		}
		for name, certPEM := range csrCerts {
			result.Certs[name] = map[string]string{
				"cert_pem": certPEM,
				"key_pem":  csrKeyPEMs[name],
			}
		}
		// Re-encode the merged response for the on-disk file.
		data, err = json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("re-encode response: %w", err)
		}
	}

	// Write the final response to disk.
	if err := atomicfile.Write(outputPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write secrets: %w", err)
	}

	return result, nil
}

// doClaimRequest sends a POST to the claim endpoint and returns the parsed response and raw JSON.
func doClaimRequest(client *http.Client, url string, body []byte) (*Response, []byte, error) {
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("claim failed (%d): %s", resp.StatusCode, extractError(data, resp.Status))
	}

	var result Response
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, nil, fmt.Errorf("decode response: %w", err)
	}

	return &result, data, nil
}

// csrResponse is the JSON structure returned by POST /csr.
type csrResponse struct {
	Certs map[string]struct {
		CertPEM string `json:"cert_pem"`
	} `json:"certs"`
	Error string `json:"error,omitempty"`
}

// submitCSR generates an Ed25519 keypair, builds a CSR, and submits it to POST /csr.
// Returns maps of cert name → cert PEM (from server) and cert name → key PEM (local).
func submitCSR(client *http.Client, baseURL, sessionID, subject string) (certPEMs, keyPEMs map[string]string, err error) {
	// Generate ephemeral Ed25519 keypair (never leaves this machine).
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}

	// Build CSR with subject as CN. Server ignores all CSR fields except the public key
	// (SPIRE pattern), but we include a valid subject for protocol correctness.
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: subject},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	// POST /csr with session_id + CSR PEM.
	reqBody := struct {
		SessionID string `json:"session_id"`
		CSRPEM    string `json:"csr_pem"`
	}{
		SessionID: sessionID,
		CSRPEM:    string(csrPEM),
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CSR request: %w", err)
	}

	resp, err := client.Post(baseURL+"/csr", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("POST /csr: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("read /csr response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("CSR failed (%d): %s", resp.StatusCode, extractError(data, resp.Status))
	}

	var csrResp csrResponse
	if err := json.Unmarshal(data, &csrResp); err != nil {
		return nil, nil, fmt.Errorf("decode CSR response: %w", err)
	}

	// Encode local private key as PEM.
	keyDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}
	localKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))

	certPEMs = make(map[string]string, len(csrResp.Certs))
	keyPEMs = make(map[string]string, len(csrResp.Certs))
	for name, entry := range csrResp.Certs {
		certPEMs[name] = entry.CertPEM
		keyPEMs[name] = localKeyPEM // same keypair for all CSR certs
	}

	return certPEMs, keyPEMs, nil
}

// extractError attempts to parse an error message from a JSON error response.
func extractError(data []byte, status string) string {
	var errResp struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &errResp); err == nil && errResp.Error != "" {
		return errResp.Error
	}
	msg := string(bytes.TrimSpace(data))
	if msg == "" {
		return status
	}
	return msg
}


