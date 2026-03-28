// Package claim implements the client-side enrollment claim flow.
package claim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
)

// Response is the JSON structure returned by POST /claim.
// Format: {"secrets":{...},"vars":{...}} with an optional "ca" field when CAs are configured.
type Response struct {
	Secrets map[string]string            `json:"secrets"`
	Vars    map[string]string            `json:"vars"`
	CA      map[string]map[string]string `json:"ca,omitempty"`
	Error   string                       `json:"error,omitempty"`
}

// Run sends a claim request and writes secrets to outputPath.
func Run(client *http.Client, url, token, scope, outputPath string) (*Response, error) {
	reqBody := map[string]string{
		"token": token,
	}
	if scope != "" {
		reqBody["scope"] = scope
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

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
		var errResp Response
		if err := json.Unmarshal(data, &errResp); err == nil && errResp.Error != "" {
			return nil, fmt.Errorf("claim failed (%d): %s", resp.StatusCode, errResp.Error)
		}
		msg := string(bytes.TrimSpace(data))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("claim failed (%d): %s", resp.StatusCode, msg)
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


