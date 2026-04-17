// Package resource resolves resource paths on behalf of Read and Write.
//
// Paths (Vault Logical API shape, scalar responses only):
//
//   Read (idempotent):
//     var/<n>         literal string
//     secret/<n>      HKDF-derived bytes, encoded per spec
//     ca/<n>          CA certificate PEM
//     jwt_key/<n>     JWT signing public key PEM
//
//   Write (mutating / entropy-consuming):
//     pki/<role>      leaf certificate PEM (data["csr"] required, DER PKCS#10)
//     jwt/<n>         signed JWT
//
// Capabilities: read (Read) and write (Write). Every call starts with a
// policy check against the caller's named policy.
package resource

import (
"crypto/ed25519"
"crypto/sha256"
"crypto/x509"
"encoding/base64"
"encoding/hex"
"encoding/pem"
"fmt"
"io"
"net"
"strings"

"github.com/pigeon-as/pigeon-enroll/internal/config"
"github.com/pigeon-as/pigeon-enroll/internal/jwt"
"github.com/pigeon-as/pigeon-enroll/internal/pki"
"github.com/pigeon-as/pigeon-enroll/internal/policy"
"golang.org/x/crypto/hkdf"
)

// Caller carries the per-request context used for policy checks and
// certificate subject substitution.
type Caller struct {
Identity string
Policy   string
Subject  string
}

// Response is what Read and Write return.
type Response struct {
Content     []byte
ContentType string
TTLSeconds  uint32
}

// Resolver dispatches path lookups to the appropriate backend.
type Resolver struct {
cfg    *config.Config
engine *policy.Engine
ikm    []byte
}

// New constructs a resolver. ikm must be 32 bytes of uniformly random
// keying material (the enrollment key).
func New(cfg *config.Config, engine *policy.Engine, ikm []byte) (*Resolver, error) {
if cfg == nil {
return nil, fmt.Errorf("nil config")
}
if engine == nil {
return nil, fmt.Errorf("nil policy engine")
}
if len(ikm) == 0 {
return nil, fmt.Errorf("empty ikm")
}
return &Resolver{cfg: cfg, engine: engine, ikm: ikm}, nil
}

// Read resolves an idempotent scalar path.
func (r *Resolver) Read(caller *Caller, path string) (*Response, error) {
if caller == nil {
return nil, fmt.Errorf("nil caller")
}
kind, name, err := splitPath(path)
if err != nil {
return nil, err
}
if err := r.check(caller, path, policy.Read); err != nil {
return nil, err
}
switch kind {
case "var":
return r.readVar(name)
case "secret":
return r.readSecret(name)
case "ca":
return r.readCA(name)
case "jwt_key":
return r.readJWTKey(name)
default:
return nil, fmt.Errorf("unknown resource kind %q for read", kind)
}
}

// Write resolves a mutating path. data carries path-specific inputs
// (e.g. pki/<role> requires data["csr"] = DER PKCS#10).
func (r *Resolver) Write(caller *Caller, path string, data map[string][]byte) (*Response, error) {
if caller == nil {
return nil, fmt.Errorf("nil caller")
}
kind, name, err := splitPath(path)
if err != nil {
return nil, err
}
if err := r.check(caller, path, policy.Write); err != nil {
return nil, err
}
switch kind {
case "pki":
return r.writePKI(caller, name, data)
case "jwt":
return r.writeJWT(caller, name)
default:
return nil, fmt.Errorf("unknown resource kind %q for write", kind)
}
}

// -----------------------------------------------------------------------------
// Read handlers

func (r *Resolver) readVar(name string) (*Response, error) {
v, ok := r.cfg.Vars[name]
if !ok {
return nil, fmt.Errorf("var %q not found", name)
}
return &Response{Content: []byte(v.Value), ContentType: "text/plain"}, nil
}

func (r *Resolver) readSecret(name string) (*Response, error) {
spec, ok := r.cfg.Secrets[name]
if !ok {
return nil, fmt.Errorf("secret %q not found", name)
}
raw := make([]byte, spec.Length)
info := "pigeon-enroll derive " + name
rd := hkdf.New(sha256.New, r.ikm, nil, []byte(info))
if _, err := io.ReadFull(rd, raw); err != nil {
return nil, fmt.Errorf("derive secret %q: %w", name, err)
}
encoded, err := encodeBytes(raw, spec.Encoding)
if err != nil {
return nil, fmt.Errorf("secret %q: %w", name, err)
}
return &Response{Content: encoded, ContentType: "text/plain"}, nil
}

func (r *Resolver) readCA(name string) (*Response, error) {
if _, ok := r.cfg.CAs[name]; !ok {
return nil, fmt.Errorf("ca %q not found", name)
}
ca, err := pki.DeriveNamedCA(r.ikm, name)
if err != nil {
return nil, err
}
return &Response{Content: ca.CertPEM, ContentType: "application/x-pem-file"}, nil
}

func (r *Resolver) readJWTKey(name string) (*Response, error) {
if _, ok := r.cfg.JWTKeys[name]; !ok {
return nil, fmt.Errorf("jwt_key %q not found", name)
}
pub, _, err := pki.DeriveJWTKey(r.ikm, name)
if err != nil {
return nil, err
}
der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(pub))
if err != nil {
return nil, fmt.Errorf("marshal jwt pubkey: %w", err)
}
p := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
return &Response{Content: p, ContentType: "application/x-pem-file"}, nil
}

// -----------------------------------------------------------------------------
// Write handlers

func (r *Resolver) writePKI(caller *Caller, role string, data map[string][]byte) (*Response, error) {
spec, ok := r.cfg.PKIs[role]
if !ok {
return nil, fmt.Errorf("pki %q not found", role)
}
if _, ok := r.cfg.CAs[spec.CARef]; !ok {
return nil, fmt.Errorf("pki %q references unknown ca %q", role, spec.CARef)
}
csrDER, ok := data["csr"]
if !ok || len(csrDER) == 0 {
return nil, fmt.Errorf("pki %q requires data[\"csr\"] (DER PKCS#10)", role)
}
csr, err := x509.ParseCertificateRequest(csrDER)
if err != nil {
return nil, fmt.Errorf("parse csr: %w", err)
}
if err := csr.CheckSignature(); err != nil {
return nil, fmt.Errorf("csr signature: %w", err)
}
cn, dnsSANs, ipSANsRaw, err := spec.Resolve(caller.Subject)
if err != nil {
return nil, err
}
ipSANs, err := parseIPs(ipSANsRaw)
if err != nil {
return nil, fmt.Errorf("pki %q ip_sans: %w", role, err)
}
eku, err := pki.ParseExtKeyUsage(spec.ExtKeyUsage)
if err != nil {
return nil, fmt.Errorf("pki %q ext_key_usage: %w", role, err)
}
ca, err := pki.DeriveCAByName(r.ikm, spec.CARef)
if err != nil {
return nil, err
}
certPEM, err := pki.SignCSR(ca, csr.PublicKey, cn, dnsSANs, ipSANs, spec.TTL, eku)
if err != nil {
return nil, fmt.Errorf("sign csr: %w", err)
}
return &Response{
Content:     certPEM,
ContentType: "application/x-pem-file",
TTLSeconds:  uint32(spec.TTL.Seconds()),
}, nil
}

func (r *Resolver) writeJWT(caller *Caller, name string) (*Response, error) {
spec, ok := r.cfg.JWTKeys[name]
if !ok {
return nil, fmt.Errorf("jwt %q not found", name)
}
_, priv, err := pki.DeriveJWTKey(r.ikm, name)
if err != nil {
return nil, err
}
tok, err := jwt.Sign(priv, spec.Issuer, spec.Audience, caller.Subject, spec.TTL)
if err != nil {
return nil, fmt.Errorf("sign jwt: %w", err)
}
return &Response{
Content:     []byte(tok),
ContentType: "application/jwt",
TTLSeconds:  uint32(spec.TTL.Seconds()),
}, nil
}

// -----------------------------------------------------------------------------
// helpers

func splitPath(path string) (kind, name string, err error) {
parts := strings.SplitN(path, "/", 2)
if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
return "", "", fmt.Errorf("invalid path %q; expected <kind>/<name>", path)
}
return parts[0], parts[1], nil
}

func (r *Resolver) check(caller *Caller, path string, cap policy.Capability) error {
if !r.engine.Allows(caller.Policy, path, cap) {
return fmt.Errorf("permission denied: %s on %s (policy %q)", cap, path, caller.Policy)
}
return nil
}

func encodeBytes(b []byte, encoding string) ([]byte, error) {
switch encoding {
case "", "raw":
return b, nil
case "hex":
return []byte(hex.EncodeToString(b)), nil
case "base64":
return []byte(base64.StdEncoding.EncodeToString(b)), nil
case "base64url":
return []byte(base64.RawURLEncoding.EncodeToString(b)), nil
default:
return nil, fmt.Errorf("unknown encoding %q", encoding)
}
}

func parseIPs(raw []string) ([]net.IP, error) {
if len(raw) == 0 {
return nil, nil
}
out := make([]net.IP, 0, len(raw))
for _, s := range raw {
ip := net.ParseIP(s)
if ip == nil {
return nil, fmt.Errorf("invalid IP %q", s)
}
out = append(out, ip)
}
return out, nil
}