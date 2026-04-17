package identity

import (
	"context"
	"strings"
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/attestor"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/policy"
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
	if err != nil {
		t.Fatal(err)
	}
	return cfg, eng, map[string]attestor.Attestor{"hmac": &stubAttestor{kind: "hmac"}}
}

func TestNewRegistryValid(t *testing.T) {
	cfg, eng, ats := baseFixture(t)
	r, err := New(cfg, eng, ats)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	id, err := r.Lookup("worker")
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if id.Name != "worker" || id.Policy != "worker" || id.PKI.Name != "worker" {
		t.Fatalf("unexpected identity: %+v", id)
	}
	if len(id.Attestors) != 1 || id.Attestors[0].Kind() != "hmac" {
		t.Fatalf("unexpected attestors: %+v", id.Attestors)
	}
}

func TestLookupUnknown(t *testing.T) {
	cfg, eng, ats := baseFixture(t)
	r, err := New(cfg, eng, ats)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup("ghost"); err == nil {
		t.Fatal("expected error")
	}
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
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}
