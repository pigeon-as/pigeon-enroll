// Package config loads the pigeon-enroll server configuration (Decision 65).
//
// The HCL schema is Vault-shaped: five primitive resource kinds
// (ca/secret/var/jwt_key/pki) plus templates/attestors/policies/identities.
// References between blocks (e.g. pki.ca = ca.mesh, identity.pki = pki.X) are
// native HCL expressions, validated against declared block names at load time.
package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

// Config is the top-level pigeon-enroll server config.
type Config struct {
	TrustDomain   string
	Listen        string
	IdentityTTL   time.Duration
	RenewFraction float64

	Attestors  map[string]*Attestor
	CAs        map[string]*CA
	Secrets    map[string]*Secret
	Vars       map[string]*Var
	JWTKeys    map[string]*JWTKey
	PKIs       map[string]*PKI
	Templates  map[string]*Template
	Policies   map[string]*Policy
	Identities map[string]*Identity
}

// Attestor is a pluggable NodeAttestor (SPIRE pattern).
// Kind is the single HCL label ("tpm", "hmac", "bootstrap_cert").
type Attestor struct {
	Kind string

	// TPM
	EKCAPath   string
	EKHashPath string

	// HMAC
	KeyPath string
	Window  time.Duration
}

// CA is an HKDF-derived certificate authority (deterministic, never rotates).
type CA struct {
	Name     string
	CN       string
	Validity time.Duration
}

// Secret is an HKDF-derived secret value.
type Secret struct {
	Name     string
	Length   int
	Encoding string // "hex", "base64", "base64url", "raw"
}

// Var is a plaintext literal value exposed as a resource.
type Var struct {
	Name  string
	Value string
}

// JWTKey is a named JWT signing key derived from the enrollment key.
type JWTKey struct {
	Name     string
	Alg      string // "EdDSA"
	Issuer   string
	Audience string
	TTL      time.Duration
}

// PKI is a Vault-style PKI role: issues ephemeral leaves from a declared CA.
type PKI struct {
	Name        string
	CARef       string // resolved from ca = ca.<name>
	TTL         time.Duration
	ExtKeyUsage []string
	// SAN/CN expressions are evaluated at issue time with `subject` in scope.
	DNSSANsExpr hcl.Expression
	IPSANsExpr  hcl.Expression
	CNExpr      hcl.Expression
}

// Resolve evaluates the PKI role's CN, DNS SANs, and IP SANs with the given
// subject bound as `${subject}`. Any field may be nil (not set in config).
func (p *PKI) Resolve(subject string) (cn string, dnsSANs, ipSANs []string, err error) {
	ectx := &hcl.EvalContext{
		Variables: map[string]cty.Value{"subject": cty.StringVal(subject)},
	}
	cn = subject
	if p.CNExpr != nil && !exprIsNil(p.CNExpr) {
		v, diags := p.CNExpr.Value(ectx)
		if diags.HasErrors() {
			return "", nil, nil, fmt.Errorf("pki %q cn: %s", p.Name, diags.Error())
		}
		if v.Type() == cty.String {
			cn = v.AsString()
		}
	}
	dnsSANs, err = evalStringList(p.DNSSANsExpr, ectx, fmt.Sprintf("pki %q dns_sans", p.Name))
	if err != nil {
		return "", nil, nil, err
	}
	ipSANs, err = evalStringList(p.IPSANsExpr, ectx, fmt.Sprintf("pki %q ip_sans", p.Name))
	if err != nil {
		return "", nil, nil, err
	}
	return cn, dnsSANs, ipSANs, nil
}

func exprIsNil(e hcl.Expression) bool {
	if e == nil {
		return true
	}
	// gohcl with `,optional` leaves the field as an empty literal expression
	// that yields cty.NilVal / zero-length. We treat that as "not set".
	r := e.Range()
	return r.Start == r.End
}

func evalStringList(expr hcl.Expression, ectx *hcl.EvalContext, label string) ([]string, error) {
	if expr == nil || exprIsNil(expr) {
		return nil, nil
	}
	v, diags := expr.Value(ectx)
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s: %s", label, diags.Error())
	}
	if v.IsNull() {
		return nil, nil
	}
	if !v.Type().IsTupleType() && !v.Type().IsListType() {
		return nil, fmt.Errorf("%s: expected list, got %s", label, v.Type().FriendlyName())
	}
	out := make([]string, 0, v.LengthInt())
	it := v.ElementIterator()
	for it.Next() {
		_, ev := it.Element()
		if ev.Type() != cty.String {
			return nil, fmt.Errorf("%s: list element must be string", label)
		}
		out = append(out, ev.AsString())
	}
	return out, nil
}

// Template is a server-rendered HCL native template. Body is the raw template
// text; resources referenced via ${kind.name} are resolved per-Fetch.
type Template struct {
	Name   string
	Source string
}

// Policy is a Vault path/capability set.
type Policy struct {
	Name     string
	Paths    []PathRule
	Inherits []string
}

// PathRule is one `path "<glob>" { capabilities = [...] }` entry.
type PathRule struct {
	Pattern      string
	Capabilities []string
}

// Identity binds attestors, a PKI role, and a policy.
type Identity struct {
	Name      string
	Attestors []string // attestor kinds in order
	PKIRef    string   // pki.<name>
	PolicyRef string   // policy.<name>
}

// Load reads and validates an HCL config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return Parse(data, path)
}

// Parse parses HCL source bytes. `filename` is used only for diagnostics.
func Parse(data []byte, filename string) (*Config, error) {
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(data, filename)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse %s: %s", filename, diags.Error())
	}

	// First pass: decode raw shape (references remain as hcl.Expression).
	var raw rawConfig
	if diags := gohcl.DecodeBody(file.Body, nil, &raw); diags.HasErrors() {
		return nil, fmt.Errorf("decode %s: %s", filename, diags.Error())
	}

	cfg := &Config{
		TrustDomain:   raw.TrustDomain,
		Listen:        raw.Listen,
		RenewFraction: raw.RenewFraction,
		Attestors:     map[string]*Attestor{},
		CAs:           map[string]*CA{},
		Secrets:       map[string]*Secret{},
		Vars:          map[string]*Var{},
		JWTKeys:       map[string]*JWTKey{},
		PKIs:          map[string]*PKI{},
		Templates:     map[string]*Template{},
		Policies:      map[string]*Policy{},
		Identities:    map[string]*Identity{},
	}

	if raw.Listen == "" {
		cfg.Listen = ":8443"
	}
	if raw.IdentityTTL != "" {
		d, err := time.ParseDuration(raw.IdentityTTL)
		if err != nil {
			return nil, fmt.Errorf("identity_ttl: %w", err)
		}
		cfg.IdentityTTL = d
	} else {
		cfg.IdentityTTL = 720 * time.Hour
	}
	if cfg.RenewFraction == 0 {
		cfg.RenewFraction = 0.5
	}

	// Attestors
	for _, a := range raw.Attestors {
		if _, dup := cfg.Attestors[a.Kind]; dup {
			return nil, fmt.Errorf("duplicate attestor %q", a.Kind)
		}
		at, err := decodeAttestor(a)
		if err != nil {
			return nil, err
		}
		cfg.Attestors[a.Kind] = at
	}

	// CAs
	for _, c := range raw.CAs {
		if _, dup := cfg.CAs[c.Name]; dup {
			return nil, fmt.Errorf("duplicate ca %q", c.Name)
		}
		validity, err := parseDuration(c.Validity, "10y")
		if err != nil {
			return nil, fmt.Errorf("ca %q validity: %w", c.Name, err)
		}
		cfg.CAs[c.Name] = &CA{Name: c.Name, CN: c.CN, Validity: validity}
	}

	// Secrets
	for _, s := range raw.Secrets {
		if _, dup := cfg.Secrets[s.Name]; dup {
			return nil, fmt.Errorf("duplicate secret %q", s.Name)
		}
		enc := s.Encoding
		if enc == "" {
			enc = "base64"
		}
		switch enc {
		case "hex", "base64", "base64url", "raw":
		default:
			return nil, fmt.Errorf("secret %q: unknown encoding %q", s.Name, enc)
		}
		length := s.Length
		if length == 0 {
			length = 32
		}
		cfg.Secrets[s.Name] = &Secret{Name: s.Name, Length: length, Encoding: enc}
	}

	// Vars
	for _, v := range raw.Vars {
		if _, dup := cfg.Vars[v.Name]; dup {
			return nil, fmt.Errorf("duplicate var %q", v.Name)
		}
		cfg.Vars[v.Name] = &Var{Name: v.Name, Value: v.Value}
	}

	// JWT keys
	for _, j := range raw.JWTKeys {
		if _, dup := cfg.JWTKeys[j.Name]; dup {
			return nil, fmt.Errorf("duplicate jwt_key %q", j.Name)
		}
		alg := j.Alg
		if alg == "" {
			alg = "EdDSA"
		}
		if alg != "EdDSA" {
			return nil, fmt.Errorf("jwt_key %q: only EdDSA supported, got %q", j.Name, alg)
		}
		ttl, err := parseDuration(j.TTL, "24h")
		if err != nil {
			return nil, fmt.Errorf("jwt_key %q ttl: %w", j.Name, err)
		}
		cfg.JWTKeys[j.Name] = &JWTKey{
			Name:     j.Name,
			Alg:      alg,
			Issuer:   j.Issuer,
			Audience: j.Audience,
			TTL:      ttl,
		}
	}

	// Templates
	for _, t := range raw.Templates {
		if _, dup := cfg.Templates[t.Name]; dup {
			return nil, fmt.Errorf("duplicate template %q", t.Name)
		}
		if t.Source == "" {
			return nil, fmt.Errorf("template %q: source is required", t.Name)
		}
		cfg.Templates[t.Name] = &Template{Name: t.Name, Source: t.Source}
	}

	// Policies
	for _, p := range raw.Policies {
		if _, dup := cfg.Policies[p.Name]; dup {
			return nil, fmt.Errorf("duplicate policy %q", p.Name)
		}
		pol := &Policy{Name: p.Name, Inherits: p.Inherits}
		for _, pr := range p.Paths {
			if len(pr.Capabilities) == 0 {
				return nil, fmt.Errorf("policy %q path %q: capabilities is required", p.Name, pr.Pattern)
			}
			for _, c := range pr.Capabilities {
				switch c {
				case "read", "write":
				default:
					return nil, fmt.Errorf("policy %q path %q: unknown capability %q", p.Name, pr.Pattern, c)
				}
			}
			pol.Paths = append(pol.Paths, PathRule{Pattern: pr.Pattern, Capabilities: pr.Capabilities})
		}
		cfg.Policies[p.Name] = pol
	}

	// Second pass: resolve references in PKI and Identity using EvalContext.
	ectx := buildEvalContext(cfg)

	// PKIs (ca = ca.X)
	for _, p := range raw.PKIs {
		if _, dup := cfg.PKIs[p.Name]; dup {
			return nil, fmt.Errorf("duplicate pki %q", p.Name)
		}
		caRef, err := evalRef(p.CA, "ca", ectx)
		if err != nil {
			return nil, fmt.Errorf("pki %q ca: %w", p.Name, err)
		}
		if _, ok := cfg.CAs[caRef]; !ok {
			return nil, fmt.Errorf("pki %q: ca.%s not defined", p.Name, caRef)
		}
		ttl, err := parseDuration(p.TTL, "168h")
		if err != nil {
			return nil, fmt.Errorf("pki %q ttl: %w", p.Name, err)
		}
		eku := p.ExtKeyUsage
		if len(eku) == 0 {
			eku = []string{"client_auth"}
		}
		cfg.PKIs[p.Name] = &PKI{
			Name:        p.Name,
			CARef:       caRef,
			TTL:         ttl,
			ExtKeyUsage: eku,
			DNSSANsExpr: p.DNSSANs,
			IPSANsExpr:  p.IPSANs,
			CNExpr:      p.CN,
		}
	}

	// Rebuild EvalContext now that pki names are known.
	ectx = buildEvalContext(cfg)

	// Identities
	for _, id := range raw.Identities {
		if _, dup := cfg.Identities[id.Name]; dup {
			return nil, fmt.Errorf("duplicate identity %q", id.Name)
		}
		attRefs, err := evalRefList(id.Attestors, "attestor", ectx)
		if err != nil {
			return nil, fmt.Errorf("identity %q attestors: %w", id.Name, err)
		}
		for _, k := range attRefs {
			if _, ok := cfg.Attestors[k]; !ok {
				return nil, fmt.Errorf("identity %q: attestor.%s not defined", id.Name, k)
			}
		}
		pkiRef, err := evalRef(id.PKI, "pki", ectx)
		if err != nil {
			return nil, fmt.Errorf("identity %q pki: %w", id.Name, err)
		}
		if _, ok := cfg.PKIs[pkiRef]; !ok {
			return nil, fmt.Errorf("identity %q: pki.%s not defined", id.Name, pkiRef)
		}
		polRef, err := evalRef(id.Policy, "policy", ectx)
		if err != nil {
			return nil, fmt.Errorf("identity %q policy: %w", id.Name, err)
		}
		if _, ok := cfg.Policies[polRef]; !ok {
			return nil, fmt.Errorf("identity %q: policy.%s not defined", id.Name, polRef)
		}
		cfg.Identities[id.Name] = &Identity{
			Name:      id.Name,
			Attestors: attRefs,
			PKIRef:    pkiRef,
			PolicyRef: polRef,
		}
	}

	// Validate policy inheritance.
	for _, p := range cfg.Policies {
		for _, inh := range p.Inherits {
			if _, ok := cfg.Policies[inh]; !ok {
				return nil, fmt.Errorf("policy %q: inherits unknown policy %q", p.Name, inh)
			}
		}
	}

	if cfg.TrustDomain == "" {
		return nil, fmt.Errorf("trust_domain is required")
	}

	return cfg, nil
}

func decodeAttestor(r rawAttestor) (*Attestor, error) {
	a := &Attestor{Kind: r.Kind}
	switch r.Kind {
	case "tpm":
		var body tpmAttestorBody
		if diags := gohcl.DecodeBody(r.Body, nil, &body); diags.HasErrors() {
			return nil, fmt.Errorf("attestor tpm: %s", diags.Error())
		}
		a.EKCAPath = body.EKCAPath
		a.EKHashPath = body.EKHashPath
	case "hmac":
		var body hmacAttestorBody
		if diags := gohcl.DecodeBody(r.Body, nil, &body); diags.HasErrors() {
			return nil, fmt.Errorf("attestor hmac: %s", diags.Error())
		}
		if body.KeyPath == "" {
			return nil, fmt.Errorf("attestor hmac: key_path is required")
		}
		a.KeyPath = body.KeyPath
		win, err := parseDuration(body.Window, "30m")
		if err != nil {
			return nil, fmt.Errorf("attestor hmac window: %w", err)
		}
		a.Window = win
	case "bootstrap_cert":
		// No body fields.
	default:
		return nil, fmt.Errorf("unknown attestor kind %q", r.Kind)
	}
	return a, nil
}

func parseDuration(s, def string) (time.Duration, error) {
	if s == "" {
		s = def
	}
	// Accept "10y" shorthand (not supported by time.ParseDuration).
	if strings.HasSuffix(s, "y") {
		years, err := time.ParseDuration(strings.TrimSuffix(s, "y") + "h")
		if err != nil {
			return 0, err
		}
		return years * 24 * 365, nil
	}
	if strings.HasSuffix(s, "d") {
		days, err := time.ParseDuration(strings.TrimSuffix(s, "d") + "h")
		if err != nil {
			return 0, err
		}
		return days * 24, nil
	}
	return time.ParseDuration(s)
}

// buildEvalContext exposes declared block names as cty string values, so that
// references like `ca = ca.mesh` evaluate to the string "mesh".
func buildEvalContext(cfg *Config) *hcl.EvalContext {
	return &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"attestor": refObject(cfg.Attestors),
			"ca":       refObject(cfg.CAs),
			"pki":      refObject(cfg.PKIs),
			"policy":   refObject(cfg.Policies),
		},
	}
}

// refObject builds an HCL reference object from a map keyed by block name.
// Empty map becomes cty.EmptyObjectVal so `kind.missing` produces a clean
// "unsupported attribute" error instead of "unknown variable".
func refObject[V any](m map[string]V) cty.Value {
	if len(m) == 0 {
		return cty.EmptyObjectVal
	}
	obj := make(map[string]cty.Value, len(m))
	for k := range m {
		obj[k] = cty.StringVal(k)
	}
	return cty.ObjectVal(obj)
}

// evalRef evaluates a single-reference expression to the referenced name.
// Accepts bare strings too (for programmatic use).
func evalRef(expr hcl.Expression, expectedRoot string, ectx *hcl.EvalContext) (string, error) {
	if expr == nil {
		return "", fmt.Errorf("reference is required")
	}
	v, diags := expr.Value(ectx)
	if diags.HasErrors() {
		return "", fmt.Errorf("%s", diags.Error())
	}
	if v.Type() != cty.String {
		return "", fmt.Errorf("expected %s.<name>, got %s", expectedRoot, v.Type().FriendlyName())
	}
	return v.AsString(), nil
}

func evalRefList(expr hcl.Expression, expectedRoot string, ectx *hcl.EvalContext) ([]string, error) {
	if expr == nil {
		return nil, fmt.Errorf("reference list is required")
	}
	v, diags := expr.Value(ectx)
	if diags.HasErrors() {
		return nil, fmt.Errorf("%s", diags.Error())
	}
	if !v.Type().IsTupleType() && !v.Type().IsListType() {
		return nil, fmt.Errorf("expected list of %s.<name>, got %s", expectedRoot, v.Type().FriendlyName())
	}
	out := make([]string, 0, v.LengthInt())
	it := v.ElementIterator()
	for it.Next() {
		_, ev := it.Element()
		if ev.Type() != cty.String {
			return nil, fmt.Errorf("list element must be %s.<name> reference", expectedRoot)
		}
		out = append(out, ev.AsString())
	}
	return out, nil
}
