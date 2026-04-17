package identity

import (
	"context"
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/attestor"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/policy"
	"github.com/shoenig/test/must"
)

type stubAttestor struct{ kind string }

func (s *stubAttestor) Kind() string { return s.kind }
func (s *stubAttestor) Verify(_ context.Context, _ attestor.Evidence, _ string, _ attestor.Challenger) (*attestor.Result, error) {
	return &attestor.Result{Subject: s.kind}, nil
}

func baseFixture(t *testing.T) (*config.Config, *policy.Engine, map[string]attestor.Attestor) {
	t.Helper()
	pki := &config.PKI{Name: "worker", CARef: "identity"}
	cfg := &config.Config{
		PKIs: map[string]*config.PKI{"worker": pki},
		Policies: map[string]*config.Policy{
			"worker": {Name: "worker"},
		},
		Identities: map[string]*config.Identity{
			"worker": {
				Name:      "worker",
				Attestors: []string{"hmac"},
				PKIRef:    "worker",
				PolicyRef: "worker",
			},
		},
	}
	eng, err := policy.New(cfg.Policies)
	must.NoError(t, err)
	return cfg, eng, map[string]attestor.Attestor{"hmac": &stubAttestor{kind: "hmac"}}
}

func TestNewRegistryValid(t *testing.T) {
	cfg, eng, ats := baseFixture(t)
	r, err := New(cfg, eng, ats)
	must.NoError(t, err)
	id, err := r.Lookup("worker")
	must.NoError(t, err)
	must.Eq(t, "worker", id.Name)
	must.Eq(t, "worker", id.Policy)
	must.Eq(t, "worker", id.PKI.Name)
	must.SliceLen(t, 1, id.Attestors)
	must.Eq(t, "hmac", id.Attestors[0].Kind())
}

func TestLookupUnknown(t *testing.T) {
	cfg, eng, ats := baseFixture(t)
	r, err := New(cfg, eng, ats)
	must.NoError(t, err)
	_, err = r.Lookup("ghost")
	must.Error(t, err)
}

func TestMissingReferences(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*config.Config, map[string]attestor.Attestor)
		want   string
	}{
		{
			"unknown pki",
			func(c *config.Config, _ map[string]attestor.Attestor) {
				c.Identities["worker"].PKIRef = "missing"
			},
			"pki",
		},
		{
			"unknown policy",
			func(c *config.Config, _ map[string]attestor.Attestor) {
				c.Identities["worker"].PolicyRef = "missing"
			},
			"policy",
		},
		{
			"unknown attestor",
			func(c *config.Config, _ map[string]attestor.Attestor) {
				c.Identities["worker"].Attestors = []string{"missing"}
			},
			"attestor",
		},
		{
			"no attestors",
			func(c *config.Config, _ map[string]attestor.Attestor) {
				c.Identities["worker"].Attestors = nil
			},
			"no attestors",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, eng, ats := baseFixture(t)
			tc.mutate(cfg, ats)
			_, err := New(cfg, eng, ats)
			must.ErrorContains(t, err, tc.want)
		})
	}
}
