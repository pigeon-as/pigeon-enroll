// Package policy implements Vault-style path/capability authorization.
//
// A policy is a named set of (path pattern, capabilities) rules. Policies can
// inherit from other policies (union of rules). Authorization is deny-by-default:
// a request for path P with capability C is allowed iff some rule's pattern
// matches P and includes C.
//
// Path glob: Vault-style. '*' matches a single path segment (bounded by '/');
// '**' (or a trailing '*') matches any number of segments. For v1 we support
// '*' as a single-segment wildcard and '*' as a greedy tail wildcard when it
// appears as the last segment (matches "foo/*" → any subtree).
package policy

import (
	"fmt"
	"strings"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
)

// Capability is a Vault-style permission verb. pigeon-enroll has exactly
// two: read (for Read paths) and write (for Write paths).
type Capability string

const (
	Read  Capability = "read"
	Write Capability = "write"
)

// Engine resolves and evaluates policies loaded from config.
type Engine struct {
	policies map[string]*config.Policy
	resolved map[string][]rule
}

type rule struct {
	pattern string
	caps    map[Capability]struct{}
}

// New builds an engine from config policies. Inheritance is flattened once
// at construction time; cycles are detected.
func New(policies map[string]*config.Policy) (*Engine, error) {
	e := &Engine{policies: policies, resolved: map[string][]rule{}}
	for name := range policies {
		if _, err := e.resolve(name, nil); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// Allows reports whether `policy` grants `cap` on `path`.
func (e *Engine) Allows(policyName, path string, cap Capability) bool {
	rules, ok := e.resolved[policyName]
	if !ok {
		return false
	}
	for _, r := range rules {
		if _, hasCap := r.caps[cap]; !hasCap {
			continue
		}
		if match(r.pattern, path) {
			return true
		}
	}
	return false
}

// Has reports whether the engine knows a policy by that name.
func (e *Engine) Has(policyName string) bool {
	_, ok := e.resolved[policyName]
	return ok
}

func (e *Engine) resolve(name string, visiting []string) ([]rule, error) {
	if existing, ok := e.resolved[name]; ok {
		return existing, nil
	}
	p, ok := e.policies[name]
	if !ok {
		return nil, fmt.Errorf("policy %q not defined", name)
	}
	for _, v := range visiting {
		if v == name {
			return nil, fmt.Errorf("policy inheritance cycle through %q", name)
		}
	}
	visiting = append(visiting, name)

	rules := make([]rule, 0, len(p.Paths))
	for _, inh := range p.Inherits {
		inhRules, err := e.resolve(inh, visiting)
		if err != nil {
			return nil, err
		}
		rules = append(rules, inhRules...)
	}
	for _, pr := range p.Paths {
		caps := make(map[Capability]struct{}, len(pr.Capabilities))
		for _, c := range pr.Capabilities {
			caps[Capability(c)] = struct{}{}
		}
		rules = append(rules, rule{pattern: pr.Pattern, caps: caps})
	}
	e.resolved[name] = rules
	return rules, nil
}

// match reports whether path matches the Vault-style glob pattern.
//
//	"ca/mesh/cert"      — exact
//	"var/*"             — one segment in that position (greedy when last)
//	"pki/*/issue"       — single-segment wildcard in middle
//
// A trailing '*' segment matches one or more remaining segments (subtree).
// A non-trailing '*' matches exactly one segment.
func match(pattern, path string) bool {
	pp := strings.Split(pattern, "/")
	sp := strings.Split(path, "/")
	for i, seg := range pp {
		if seg == "*" {
			if i == len(pp)-1 {
				// trailing wildcard: must be at least one remaining segment
				return len(sp) > i
			}
			if i >= len(sp) {
				return false
			}
			continue
		}
		if i >= len(sp) || sp[i] != seg {
			return false
		}
	}
	return len(sp) == len(pp)
}
