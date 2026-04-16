package action

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/shoenig/test/must"
)

func TestConsulACL_TokenAlreadyExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/acl/token/self" && r.Method == http.MethodGet {
			// Token exists — return 200.
			json.NewEncoder(w).Encode(map[string]string{"SecretID": "agent-token-value"})
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	defer srv.Close()

	cfgJSON, _ := json.Marshal(map[string]any{
		"addr":             srv.URL,
		"management_token": "consul_bootstrap_token",
		"agent_token":      "consul_agent_token",
	})

	a, err := newConsulACL(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	secrets := map[string]string{
		"consul_bootstrap_token": "mgmt-token-value",
		"consul_agent_token":     "agent-token-value",
	}
	must.NoError(t, a.Run(context.Background(), slog.Default(), secrets))
}

func TestConsulACL_CreatesPolicyAndToken(t *testing.T) {
	var policyCreated, tokenCreated atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/acl/token/self" && r.Method == http.MethodGet:
			// Token doesn't exist.
			w.WriteHeader(http.StatusForbidden)

		case r.URL.Path == "/v1/acl/policy/name/nomad-agent" && r.Method == http.MethodGet:
			// Policy doesn't exist.
			w.WriteHeader(http.StatusNotFound)

		case r.URL.Path == "/v1/acl/policy" && r.Method == http.MethodPut:
			// Verify management token is used.
			must.Eq(t, "mgmt-token-value", r.Header.Get("X-Consul-Token"))

			var body map[string]string
			must.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			must.Eq(t, "nomad-agent", body["Name"])

			policyCreated.Store(true)
			json.NewEncoder(w).Encode(map[string]string{"ID": "policy-id-123"})

		case r.URL.Path == "/v1/acl/token" && r.Method == http.MethodPut:
			must.Eq(t, "mgmt-token-value", r.Header.Get("X-Consul-Token"))

			var body map[string]any
			must.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			must.Eq(t, "agent-token-value", body["SecretID"])

			policies := body["Policies"].([]any)
			p := policies[0].(map[string]any)
			must.Eq(t, "policy-id-123", p["ID"])

			tokenCreated.Store(true)
			json.NewEncoder(w).Encode(map[string]string{"SecretID": "agent-token-value"})

		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cfgJSON, _ := json.Marshal(map[string]any{
		"addr":             srv.URL,
		"management_token": "consul_bootstrap_token",
		"agent_token":      "consul_agent_token",
	})

	a, err := newConsulACL(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	secrets := map[string]string{
		"consul_bootstrap_token": "mgmt-token-value",
		"consul_agent_token":     "agent-token-value",
	}
	must.NoError(t, a.Run(context.Background(), slog.Default(), secrets))

	must.True(t, policyCreated.Load())
	must.True(t, tokenCreated.Load())
}

func TestConsulACL_PolicyAlreadyExists(t *testing.T) {
	var tokenCreated atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/acl/token/self" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusForbidden)

		case r.URL.Path == "/v1/acl/policy/name/nomad-agent" && r.Method == http.MethodGet:
			// Policy already exists.
			json.NewEncoder(w).Encode(map[string]string{"ID": "existing-policy-id"})

		case r.URL.Path == "/v1/acl/token" && r.Method == http.MethodPut:
			var body map[string]any
			must.NoError(t, json.NewDecoder(r.Body).Decode(&body))

			policies := body["Policies"].([]any)
			p := policies[0].(map[string]any)
			must.Eq(t, "existing-policy-id", p["ID"])

			tokenCreated.Store(true)
			json.NewEncoder(w).Encode(map[string]string{"SecretID": "agent-token-value"})

		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cfgJSON, _ := json.Marshal(map[string]any{
		"addr":             srv.URL,
		"management_token": "consul_bootstrap_token",
		"agent_token":      "consul_agent_token",
	})

	a, err := newConsulACL(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	secrets := map[string]string{
		"consul_bootstrap_token": "mgmt-token-value",
		"consul_agent_token":     "agent-token-value",
	}
	must.NoError(t, a.Run(context.Background(), slog.Default(), secrets))
	must.True(t, tokenCreated.Load())
}

func TestConsulACL_MissingSecrets(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]any{
		"addr":             "http://localhost:8500",
		"management_token": "consul_bootstrap_token",
		"agent_token":      "consul_agent_token",
	})

	a, err := newConsulACL(jsonToBody(t, cfgJSON))
	must.NoError(t, err)

	// Missing management token.
	err = a.Run(context.Background(), slog.Default(), map[string]string{})
	must.Error(t, err)
	must.StrContains(t, err.Error(), "management_token")
}

func TestConsulACL_SecretNames(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]any{
		"addr":             "http://localhost:8500",
		"management_token": "consul_bootstrap_token",
		"agent_token":      "consul_agent_token",
	})

	a, err := newConsulACL(jsonToBody(t, cfgJSON))
	must.NoError(t, err)
	must.SliceContains(t, a.SecretNames(), "consul_bootstrap_token")
	must.SliceContains(t, a.SecretNames(), "consul_agent_token")
}

func TestConsulACL_RequiresManagementToken(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]any{
		"addr":        "http://localhost:8500",
		"agent_token": "consul_agent_token",
	})

	_, err := newConsulACL(jsonToBody(t, cfgJSON))
	must.Error(t, err)
	must.StrContains(t, err.Error(), "management_token is required")
}

func TestConsulACL_RequiresAgentToken(t *testing.T) {
	cfgJSON, _ := json.Marshal(map[string]any{
		"addr":             "http://localhost:8500",
		"management_token": "consul_bootstrap_token",
	})

	_, err := newConsulACL(jsonToBody(t, cfgJSON))
	must.Error(t, err)
	must.StrContains(t, err.Error(), "agent_token is required")
}
