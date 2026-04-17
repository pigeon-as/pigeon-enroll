package policy

import (
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/shoenig/test/must"
)

func mkEngine(t *testing.T, policies map[string]*config.Policy) *Engine {
	t.Helper()
	e, err := New(policies)
	must.NoError(t, err)
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
		must.EqOp(t, tc.want, match(tc.pattern, tc.path))
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

	must.True(t, e.Allows("worker", "ca/bootstrap", Read))
	must.True(t, e.Allows("worker", "var/domain", Read))
	must.True(t, e.Allows("worker", "pki/mesh_worker", Write))
	must.False(t, e.Allows("worker", "pki/mesh_worker", Read))
	must.False(t, e.Allows("worker", "ca/mesh", Read))
	must.False(t, e.Allows("worker", "unknown/path", Read))
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

	must.True(t, e.Allows("server", "var/domain", Read))
	must.True(t, e.Allows("server", "secret/root_token", Read))
	must.False(t, e.Allows("base", "secret/root_token", Read))
}

func TestCycleDetection(t *testing.T) {
	pol := map[string]*config.Policy{
		"a": {Name: "a", Inherits: []string{"b"}},
		"b": {Name: "b", Inherits: []string{"a"}},
	}
	_, err := New(pol)
	must.Error(t, err)
}

func TestUnknownPolicy(t *testing.T) {
	e := mkEngine(t, map[string]*config.Policy{})
	must.False(t, e.Allows("nope", "any/path", Read))
}
