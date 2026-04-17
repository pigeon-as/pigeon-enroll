# pigeon-enroll

Stage-0 bootstrap server. Hosts attest with a token, receive an identity
mTLS cert, then read or write resources by path.

All cryptographic material is HKDF-derived from a single static enrollment
key. Every server with the same key produces the same outputs.

## RPCs

| RPC | Auth | Purpose |
|-----|------|---------|
| `Register` | attestor token | First contact. Issue identity mTLS cert. |
| `Renew` | identity cert | Rotate identity cert. |
| `Read` | identity cert | Read a scalar resource by path. |
| `Write` | identity cert | Write against a mutating resource (pki, jwt). |

## Paths

Every path returns one scalar. `Request` carries `path` and an optional
`data` map; `Response` carries `content`, `content_type`, and `ttl_seconds`.

| Path | Verb | Capability | Returns |
|------|------|------------|---------|
| `var/<name>` | read | `read` | literal string |
| `secret/<name>` | read | `read` | HKDF-derived bytes |
| `ca/<name>` | read | `read` | CA certificate PEM |
| `jwt_key/<name>` | read | `read` | JWT signing public key PEM |
| `template/<name>` | read | `read` | rendered template |
| `pki/<role>` | write | `write` | signed certificate PEM (CSR required) |
| `jwt/<name>` | write | `write` | signed JWT |

Capabilities are `read` and `write` (exact Vault match). `pki/<role>`
**requires** `data["csr"]` (DER PKCS#10) — the server signs the caller's CSR
and the private key never leaves the caller. This matches SPIFFE X509-SVID,
ACME, and step-ca.

## CLI

Env vars override defaults (Vault convention):

```
ENROLL_ADDR             server address (host:port)
ENROLL_CACERT           path to server CA PEM
ENROLL_IDENTITY_DIR     directory with identity cert/key/ca (default /etc/pigeon/identity)
```

```bash
# Run the server
pigeon-enroll server -config=/etc/pigeon/enroll-server.hcl

# First contact
pigeon-enroll register \
  -identity=worker -subject=worker-01 \
  -token=@/run/pigeon/enroll.token \
  -tls=/run/pigeon/bootstrap.pem

# Rotate identity cert
pigeon-enroll renew

# Read a scalar
pigeon-enroll read var/datacenter
pigeon-enroll read ca/mesh > mesh-ca.pem
pigeon-enroll read template/setup-worker | sh

# Sign a CSR (client owns the key — SPIFFE/ACME pattern)
pigeon-enroll write pki/mesh_worker csr=@csr.der > cert.pem

# Convenience: generate keypair locally, build CSR, write pki/<role>, save both
pigeon-enroll issue pki/mesh_worker \
  -out-cert=/etc/pigeon/mesh/cert.pem \
  -out-key=/etc/pigeon/mesh/key.pem

# Mint a JWT
pigeon-enroll write jwt/consul_auto_config > token.jwt

# Utilities
pigeon-enroll ek-hash    # SHA-256 of local TPM EK public key
pigeon-enroll version
```

## Config

```hcl
trust_domain   = "pigeon.as"
listen         = ":8443"
identity_ttl   = "720h"
renew_fraction = 0.5
key_path       = "/etc/pigeon/enrollment-key"

attestor "hmac" {
  key_path = "/etc/pigeon/enrollment-key"
  window   = "30m"
}

attestor "tpm" {
  ek_ca_path   = "/etc/pigeon/ek-ca"
  ek_hash_path = "/etc/pigeon/ek-hashes"
}

ca "identity" { cn = "pigeon identity CA" }
ca "mesh"     { cn = "pigeon mesh CA" }

secret "gossip_key" { length = 32, encoding = "base64" }

var "datacenter" { value = "eu-west-gra" }

pki "identity_worker" {
  ca            = ca.identity
  ttl           = "720h"
  ext_key_usage = ["client_auth"]
}

pki "mesh_worker" {
  ca            = ca.mesh
  ttl           = "720h"
  ext_key_usage = ["client_auth", "server_auth"]
  dns_sans      = ["${subject}"]
}

jwt_key "consul_auto_config" {
  issuer   = "pigeon-enroll"
  audience = "consul-auto-config"
  ttl      = "24h"
}

template "setup-worker" {
  source = "/etc/pigeon/templates/setup-worker.sh.tpl"
}

policy "worker" {
  path "var/datacenter"     { capabilities = ["read"] }
  path "secret/gossip_key"  { capabilities = ["read"] }
  path "ca/mesh"            { capabilities = ["read"] }
  path "pki/mesh_worker"    { capabilities = ["write"] }
  path "jwt/consul_auto_config" { capabilities = ["write"] }
  path "jwt_key/consul_auto_config" { capabilities = ["read"] }
  path "template/setup-worker"  { capabilities = ["read"] }
}

identity "worker" {
  attestors = [attestor.hmac, attestor.tpm]
  pki       = pki.identity_worker
  policy    = policy.worker
}
```

## mTLS

All cert material is HKDF-derived. The `identity` CA signs both the server's
own TLS cert and every identity cert issued to clients. Server certs
auto-rotate at 50% of their TTL. Clients verify the server using the derived
CA; the server verifies clients on Renew/Read/Write using the same CA.

## Attestors

- `hmac` — time-windowed token `hex(nonce) || hex(HMAC(k, counter || scope || nonce))`.
  Dedicated HKDF-derived signing key, persistent nonce store, current +
  previous window coverage. One-time use.
- `tpm` — TPM 2.0 credential activation. EK identity validated against a CA
  chain or hash allowlist (SPIRE pattern).
- `bootstrap_cert` — mTLS with a caller cert signed by a trusted bootstrap CA.

## Build & Test

```bash
make build    # Build binary -> build/pigeon-enroll
make test     # Run unit tests
make vet      # Run go vet
make e2e      # Run e2e tests (requires Linux)
```