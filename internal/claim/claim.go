// Package claim implements the client-side enrollment claim flow.
package claim

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Response is the JSON structure returned by POST /claim.
type Response struct {
	Secrets map[string]string `json:"secrets"`
	Vars    map[string]string `json:"vars"`
	Error   string            `json:"error,omitempty"`
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

	var result Response
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		msg := result.Error
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("claim failed (%d): %s", resp.StatusCode, msg)
	}

	output := map[string]map[string]string{
		"secrets": result.Secrets,
		"vars":    result.Vars,
	}
	flat, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("marshal output: %w", err)
	}

	if err := writeAtomic(outputPath, flat); err != nil {
		return nil, fmt.Errorf("write secrets: %w", err)
	}

	return &result, nil
}

func writeAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secrets-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
