// Package identity binds attestors, a PKI role, and a policy into a single
// named identity. The Registry resolves identity references at server
// startup so that the hot path (Register/Renew/Fetch) is a simple map lookup.
package identity

import (
	"fmt"

	"github.com/pigeon-as/pigeon-enroll/internal/attestor"
	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/policy"
)

// Identity is a resolved identity: attestors are live objects, PKI is the
// decoded config block, Policy is the name (resolved via the Engine).
type Identity struct {
	Name      string
	Attestors []attestor.Attestor
	PKI       *config.PKI
	Policy    string
}

// Registry is an immutable map of identity name → resolved Identity.
type Registry struct {
	byName map[string]*Identity
}

// New builds the registry from decoded config plus the attestor map and
// policy engine. Every reference must resolve or New returns an error.
func New(cfg *config.Config, engine *policy.Engine, attestors map[string]attestor.Attestor) (*Registry, error) {
	if cfg == nil {
		return nil, fmt.Errorf("nil config")
	}
	if engine == nil {
		return nil, fmt.Errorf("nil policy engine")
	}
	r := &Registry{byName: make(map[string]*Identity, len(cfg.Identities))}
	for name, id := range cfg.Identities {
		pki, ok := cfg.PKIs[id.PKIRef]
		if !ok {
			return nil, fmt.Errorf("identity %q: pki %q not found", name, id.PKIRef)
		}
		if !engine.Has(id.PolicyRef) {
			return nil, fmt.Errorf("identity %q: policy %q not found", name, id.PolicyRef)
		}
		if len(id.Attestors) == 0 {
			return nil, fmt.Errorf("identity %q: no attestors", name)
		}
		ats := make([]attestor.Attestor, 0, len(id.Attestors))
		for _, kind := range id.Attestors {
			a, ok := attestors[kind]
			if !ok {
				return nil, fmt.Errorf("identity %q: attestor %q not found", name, kind)
			}
			ats = append(ats, a)
		}
		r.byName[name] = &Identity{
			Name:      name,
			Attestors: ats,
			PKI:       pki,
			Policy:    id.PolicyRef,
		}
	}
	return r, nil
}

// Lookup returns the identity with the given name, or an error if unknown.
func (r *Registry) Lookup(name string) (*Identity, error) {
	id, ok := r.byName[name]
	if !ok {
		return nil, fmt.Errorf("identity %q not found", name)
	}
	return id, nil
}

// Names returns all registered identity names. Order is unspecified.
func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.byName))
	for n := range r.byName {
		out = append(out, n)
	}
	return out
}
