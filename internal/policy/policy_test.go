package policy

import (
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
)

func mkEngine(t *testing.T, policies map[string]*config.Policy) *Engine {
	t.Helper()
	e, err := New(policies)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return e
}

func TestMatchExact(t *testing.T) {
	cases := []struct {
		pattern, path string
		want          bool
	}{
		{"ca/mesh/cert", "ca/mesh/cert", true},
		{"ca/mesh/cert", "ca/mesh/bundle", false},
		{"var/*", "var/domain", true},
		{"var/*", "var/nested/thing", true}, // trailing * is greedy
		{"pki/*/issue", "pki/worker/issue", true},
		{"pki/*/issue", "pki/worker/sign", false},
		{"pki/*/issue", "pki/worker", false},
		{"ca/*", "ca/mesh/cert", true},
	}
	for _, tc := range cases {
		got := match(tc.pattern, tc.path)
		if got != tc.want {
			t.Errorf("match(%q, %q) = %v, want %v", tc.pattern, tc.path, got, tc.want)
		}
	}
}

func TestAllows(t *testing.T) {
	pol := map[string]*config.Policy{
		"worker": {
			Name: "worker",
			Paths: []config.PathRule{
				{Pattern: "ca/bootstrap", Capabilities: []string{"read"}},
				{Pattern: "secret/gossip_key", Capabilities: []string{"read"}},
				{Pattern: "var/*", Capabilities: []string{"read"}},
				{Pattern: "pki/mesh_worker", Capabilities: []string{"write"}},
			},
		},
	}
	e := mkEngine(t, pol)

	mustAllow := func(path string, c Capability) {
		t.Helper()
		if !e.Allows("worker", path, c) {
			t.Errorf("worker should allow %s on %q", c, path)
		}
	}
	mustDeny := func(path string, c Capability) {
		t.Helper()
		if e.Allows("worker", path, c) {
			t.Errorf("worker should DENY %s on %q", c, path)
		}
	}

	mustAllow("ca/bootstrap", Read)
	mustAllow("var/domain", Read)
	mustAllow("pki/mesh_worker", Write)
	mustDeny("pki/mesh_worker", Read)
	mustDeny("ca/mesh", Read)
	mustDeny("unknown/path", Read)
}

func TestInherits(t *testing.T) {
	pol := map[string]*config.Policy{
		"base": {
			Name: "base",
			Paths: []config.PathRule{
				{Pattern: "var/*", Capabilities: []string{"read"}},
			},
		},
		"server": {
			Name:     "server",
			Inherits: []string{"base"},
			Paths: []config.PathRule{
				{Pattern: "secret/root_token", Capabilities: []string{"read"}},
			},
		},
	}
	e := mkEngine(t, pol)

	if !e.Allows("server", "var/domain", Read) {
		t.Error("server should inherit var/* from base")
	}
	if !e.Allows("server", "secret/root_token", Read) {
		t.Error("server should allow its own rule")
	}
	if e.Allows("base", "secret/root_token", Read) {
		t.Error("base should not see server rules")
	}
}

func TestCycleDetection(t *testing.T) {
	pol := map[string]*config.Policy{
		"a": {Name: "a", Inherits: []string{"b"}},
		"b": {Name: "b", Inherits: []string{"a"}},
	}
	_, err := New(pol)
	if err == nil {
		t.Fatal("expected cycle error")
	}
}

func TestUnknownPolicy(t *testing.T) {
	e := mkEngine(t, map[string]*config.Policy{})
	if e.Allows("nope", "any/path", Read) {
		t.Error("unknown policy must deny")
	}
}
