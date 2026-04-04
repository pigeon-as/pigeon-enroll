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

	"github.com/shoenig/test/must"
)

var testLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

func TestRun_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		must.EqOp(t, http.MethodPost, r.Method)
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		must.EqOp(t, "abc123", req["token"])
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Response{
			Secrets: map[string]string{"gossip_key": "secret1", "wg_psk": "secret2"},
			Vars:    map[string]string{"datacenter": "dc1"},
		})
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "secrets.json")
	resp, err := Run(srv.Client(), srv.URL, "abc123", "", "", out, true, testLogger)
	must.NoError(t, err)
	must.MapLen(t, 2, resp.Secrets)
	must.EqOp(t, "secret1", resp.Secrets["gossip_key"])

	// Verify file preserves structure.
	data, err := os.ReadFile(out)
	must.NoError(t, err)
	var fromDisk map[string]map[string]string
	json.Unmarshal(data, &fromDisk)
	must.EqOp(t, "secret2", fromDisk["secrets"]["wg_psk"])
	must.EqOp(t, "dc1", fromDisk["vars"]["datacenter"])
}

func TestRun_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired token"})
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "secrets.json")
	_, err := Run(srv.Client(), srv.URL, "bad", "", "", out, true, testLogger)
	must.Error(t, err)

	// File should not exist.
	_, statErr := os.Stat(out)
	must.Error(t, statErr)
}

func TestRun_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "secrets.json")
	_, err := Run(srv.Client(), srv.URL, "tok", "", "", out, true, testLogger)
	must.Error(t, err)
}

func TestRun_ConnectionRefused(t *testing.T) {
	out := filepath.Join(t.TempDir(), "secrets.json")
	_, err := Run(&http.Client{}, "http://127.0.0.1:1", "tok", "", "", out, true, testLogger)
	must.Error(t, err)
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
	_, err := Run(srv.Client(), srv.URL, "tok", "", "", out, true, testLogger)
	must.NoError(t, err)

	info, err := os.Stat(out)
	must.NoError(t, err)
	must.EqOp(t, os.FileMode(0600), info.Mode().Perm())
}
