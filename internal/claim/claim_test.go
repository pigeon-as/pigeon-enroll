package claim

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func TestRun_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		if req["token"] != "abc123" {
			t.Fatalf("expected token abc123, got %s", req["token"])
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Response{
			Secrets: map[string]string{"gossip_key": "secret1", "wg_psk": "secret2"},
			Vars:    map[string]string{"datacenter": "dc1"},
		})
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "secrets.json")
	resp, err := Run(srv.Client(), srv.URL, "abc123", "", out, true, testLogger)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Secrets) != 2 {
		t.Fatalf("expected 2 secrets, got %d", len(resp.Secrets))
	}
	if resp.Secrets["gossip_key"] != "secret1" {
		t.Fatalf("expected gossip_key=secret1, got %s", resp.Secrets["gossip_key"])
	}

	// Verify file preserves structure.
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var fromDisk map[string]map[string]string
	json.Unmarshal(data, &fromDisk)
	if fromDisk["secrets"]["wg_psk"] != "secret2" {
		t.Fatalf("disk: expected secrets.wg_psk=secret2, got %s", fromDisk["secrets"]["wg_psk"])
	}
	if fromDisk["vars"]["datacenter"] != "dc1" {
		t.Fatalf("disk: expected vars.datacenter=dc1, got %s", fromDisk["vars"]["datacenter"])
	}
}

func TestRun_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired token"})
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "secrets.json")
	_, err := Run(srv.Client(), srv.URL, "bad", "", out, true, testLogger)
	if err == nil {
		t.Fatal("expected error for 403")
	}

	// File should not exist.
	if _, statErr := os.Stat(out); statErr == nil {
		t.Fatal("file should not exist on failure")
	}
}

func TestRun_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "secrets.json")
	_, err := Run(srv.Client(), srv.URL, "tok", "", out, true, testLogger)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestRun_ConnectionRefused(t *testing.T) {
	out := filepath.Join(t.TempDir(), "secrets.json")
	_, err := Run(&http.Client{}, "http://127.0.0.1:1", "tok", "", out, true, testLogger)
	if err == nil {
		t.Fatal("expected connection error")
	}
}

func TestRun_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permissions not supported on Windows")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Response{Secrets: map[string]string{"key": "val"}})
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "sub", "secrets.json")
	_, err := Run(srv.Client(), srv.URL, "tok", "", out, true, testLogger)
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}
