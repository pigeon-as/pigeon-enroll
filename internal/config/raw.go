package config

import (
	"github.com/hashicorp/hcl/v2"
)

// rawConfig is the direct HCL representation; references remain as hcl.Expression.
type rawConfig struct {
	TrustDomain   string  `hcl:"trust_domain,optional"`
	Listen        string  `hcl:"listen,optional"`
	RenewFraction float64 `hcl:"renew_fraction,optional"`

	Attestors  []rawAttestor  `hcl:"attestor,block"`
	CAs        []rawCA        `hcl:"ca,block"`
	Secrets    []rawSecret    `hcl:"secret,block"`
	Vars       []rawVar       `hcl:"var,block"`
	JWTKeys    []rawJWTKey    `hcl:"jwt_key,block"`
	PKIs       []rawPKI       `hcl:"pki,block"`
	Templates  []rawTemplate  `hcl:"template,block"`
	Policies   []rawPolicy    `hcl:"policy,block"`
	Identities []rawIdentity  `hcl:"identity,block"`
}

type rawAttestor struct {
	Kind string   `hcl:"kind,label"`
	Body hcl.Body `hcl:",remain"`
}

type tpmAttestorBody struct {
	EKCAPath   string `hcl:"ek_ca_path,optional"`
	EKHashPath string `hcl:"ek_hash_path,optional"`
}

type hmacAttestorBody struct {
	Window string `hcl:"window,optional"`
}

type rawCA struct {
	Name     string `hcl:"name,label"`
	CN       string `hcl:"cn,optional"`
	Validity string `hcl:"validity,optional"`
}

type rawSecret struct {
	Name     string `hcl:"name,label"`
	Length   int    `hcl:"length,optional"`
	Encoding string `hcl:"encoding,optional"`
}

type rawVar struct {
	Name  string `hcl:"name,label"`
	Value string `hcl:"value"`
}

type rawJWTKey struct {
	Name     string `hcl:"name,label"`
	Alg      string `hcl:"alg,optional"`
	Issuer   string `hcl:"issuer,optional"`
	Audience string `hcl:"audience,optional"`
	TTL      string `hcl:"ttl,optional"`
}

type rawPKI struct {
	Name        string         `hcl:"name,label"`
	CA          hcl.Expression `hcl:"ca"`
	TTL         string         `hcl:"ttl,optional"`
	ExtKeyUsage []string       `hcl:"ext_key_usage,optional"`
	DNSSANs     hcl.Expression `hcl:"dns_sans,optional"`
	IPSANs      hcl.Expression `hcl:"ip_sans,optional"`
	CN          hcl.Expression `hcl:"cn,optional"`
}

type rawTemplate struct {
	Name   string `hcl:"name,label"`
	Source string `hcl:"source"`
}

type rawPolicy struct {
	Name     string       `hcl:"name,label"`
	Inherits []string     `hcl:"inherits,optional"`
	Paths    []rawPathRule `hcl:"path,block"`
}

type rawPathRule struct {
	Pattern      string   `hcl:"pattern,label"`
	Capabilities []string `hcl:"capabilities"`
}

type rawIdentity struct {
	Name      string         `hcl:"name,label"`
	Attestors hcl.Expression `hcl:"attestors"`
	PKI       hcl.Expression `hcl:"pki"`
	Policy    hcl.Expression `hcl:"policy"`
}
