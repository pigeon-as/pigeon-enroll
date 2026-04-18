// Package policy implements Vault-style path/capability authorization.
//
// A policy is a named set of (path pattern, capabilities) rules. Policies can
// inherit from other policies (union of rules). Authorization is deny-by-default:
// a request for path P with capability C is allowed iff some rule's pattern
// matches P and includes C.
//
// Path glob syntax (Vault-compatible subset):
//
//   - exact: "ca/mesh" matches only that path.
//   - '*' inside a segment is a glob (Go path.Match semantics; no '/' crossing):
//     "pki/mesh_*" matches "pki/mesh_worker", not "pki/other".
//   - '+' as a whole segment is a single-segment wildcard: "pki/+/issue" matches
//     "pki/mesh/issue" but not "pki/a/b/issue".
//   - trailing "/*" is a subtree match: "secret/*" matches "secret", "secret/a",
//     "secret/a/b/c", etc.
//   - '**' is rejected at construction — use trailing "/*" for subtrees.
package policy

import (
	"fmt"
	"path"
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
// at construction time; cycles are detected. Pattern syntax is validated:
// '**' is rejected (use trailing '/*' for subtree match) and malformed globs
// fail fast.
func New(policies map[string]*config.Policy) (*Engine, error) {
	for name, p := range policies {
		for _, pr := range p.Paths {
			if err := validatePattern(pr.Pattern); err != nil {
				return nil, fmt.Errorf("policy %q path %q: %w", name, pr.Pattern, err)
			}
		}
	}
	e := &Engine{policies: policies, resolved: map[string][]rule{}}
	for name := range policies {
		if _, err := e.resolve(name, nil); err != nil {
			return nil, err
		}
	}
	return e, nil
}

func validatePattern(pattern string) error {
	if strings.Contains(pattern, "**") {
		return fmt.Errorf(`"**" not supported; use trailing "/*" for subtree match`)
	}
	for _, seg := range strings.Split(pattern, "/") {
		// Feed the pattern itself as the name so path.Match has to parse
		// every token — path.Match returns ErrBadPattern early on mismatch
		// with a short name, which would hide malformed tails like "foo[".
		if _, err := path.Match(seg, seg); err != nil {
			return fmt.Errorf("malformed glob %q: %w", seg, err)
		}
	}
	return nil
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

// match reports whether reqPath matches the Vault-style glob pattern.
// Segment rules:
//
//   - trailing "/*" is a subtree wildcard (matches zero or more remaining
//     segments of any content).
//   - '+' as a whole segment matches exactly one segment of any content.
//   - otherwise the pattern segment is Go path.Match'd against the request
//     segment — '*' inside a segment is a character glob that does not cross '/'.
func match(pattern, reqPath string) bool {
	pp := strings.Split(pattern, "/")
	sp := strings.Split(reqPath, "/")

	// Trailing "/*" is a subtree match: the leading segments must match
	// exactly, and everything after is accepted.
	if n := len(pp); n > 0 && pp[n-1] == "*" {
		if len(sp) < n-1 {
			return false
		}
		for i := 0; i < n-1; i++ {
			if !segMatch(pp[i], sp[i]) {
				return false
			}
		}
		return true
	}

	if len(pp) != len(sp) {
		return false
	}
	for i, pseg := range pp {
		if !segMatch(pseg, sp[i]) {
			return false
		}
	}
	return true
}

func segMatch(pattern, seg string) bool {
	if pattern == "+" {
		return seg != ""
	}
	ok, err := path.Match(pattern, seg)
	return err == nil && ok
}
