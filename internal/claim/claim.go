// Package claim implements the client-side enrollment claim flow.
package claim

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
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
	Secrets map[string]string            `json:"secrets"`
	Vars    map[string]string            `json:"vars"`
	CA      map[string]map[string]string `json:"ca,omitempty"`
	Certs   map[string]map[string]string `json:"certs,omitempty"`
	JWTs    map[string]string            `json:"jwts,omitempty"`
	JWTKeys map[string]string            `json:"jwt_keys,omitempty"`
	Error   string                       `json:"error,omitempty"`
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

	return doClaimRequest(client, baseURL+"/claim", body, outputPath)
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

	return doClaimRequest(client, baseURL+"/claim", claimBody, outputPath)
}

// doClaimRequest sends a POST to the claim endpoint and writes the response.
func doClaimRequest(client *http.Client, url string, body []byte, outputPath string) (*Response, error) {
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", url, err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("claim failed (%d): %s", resp.StatusCode, extractError(data, resp.Status))
	}

	var result Response
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	// Write the raw server response ("ca" field present only when CAs are configured).
	if err := atomicfile.Write(outputPath, data, 0600); err != nil {
		return nil, fmt.Errorf("write secrets: %w", err)
	}

	return &result, nil
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


