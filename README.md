# pigeon-enroll

**Experimental** bootstrap enrollment server and client that derives bootstrap secrets from a shared enrollment key (HKDF) and distributes them to clients via mTLS, TPM attestation, and one-time HMAC tokens. Pluggable post-claim actions.

**Not a secrets manager:** covers the minimum secrets needed before Vault is available. The enrollment key is static; all servers with the same key independently derive identical secrets. A separate HMAC signing key is derived from it for token operations.

**Stage-0 bootstrap:** [pigeon-enroll](https://github.com/pigeon-as/pigeon-enroll) is a dumb pipe (token in, secrets out), [pigeon-template](https://github.com/pigeon-as/pigeon-template) is a dumb renderer (data in, config files out). Neither knows about the other. Neither forces a workflow.

## Usage

```bash
# Server (reads /etc/pigeon/enroll-server.hcl by default)
pigeon-enroll server

# Generate a claim token
pigeon-enroll generate-token [-scope=worker]

# Generate a TLS certificate bundle
pigeon-enroll generate-cert -bundle /tmp/enroll-cert.pem

# Claim (worker side, with mTLS + TPM attestation)
pigeon-enroll claim -url enroll:8443 \
  -token <hmac> -tls /tmp/enroll-cert.pem \
  -scope worker \
  -output /encrypted/pigeon/enroll.json

# Claim (dev/testing only, no TPM)
pigeon-enroll claim -url enroll:8443 \
  -token <hmac> -tls /tmp/enroll-cert.pem \
  -skip-tpm \
  -output /encrypted/pigeon/enroll.json

# Render templates (worker side, one-shot after claim)
pigeon-enroll render \
  -config /etc/pigeon/render.hcl \
  -vars /encrypted/pigeon/enroll.json

# Run all actions
pigeon-enroll run-actions

# Run a specific action
pigeon-enroll run-actions -type=vault-init
```

## TLS

mTLS is enabled by default — the CA is derived deterministically from the enrollment key via HKDF. Every server with the same key produces the same Ed25519 CA, no coordination needed. Server certs (`server_cert_ttl` default 30d) auto-rotate at 50% lifetime.

`generate-cert` outputs are explicit: `-bundle FILE` writes a PEM bundle (cert+key+ca), `-cert`/`-key`/`-ca` write individual files. `-bundle -` writes to stdout. EKU is inferred from SANs: `-dns`/`-ip` present → ServerAuth + ClientAuth, no SANs → ClientAuth only. `-ttl` sets validity (default 24h). `-base64` base64-encodes bundle output.

Use `-insecure` for testing without TLS verification.

## TPM Attestation

Claim performs TPM attestation via a bidirectional gRPC stream (SPIRE community plugin pattern):

1. Client opens TPM, reads EK, creates ephemeral AK
2. Client opens gRPC Claim stream and sends ClaimRequest with HMAC token + EK pub + EK cert (optional) + AK params
3. Server validates EK identity, returns credential activation challenge
4. Client activates credential (proves AK is on the same TPM as EK)
5. Client sends ClaimRequest with activated secret → server verifies and returns secrets

EK identity is validated via `ek_ca_path` (manufacturer CA cert chain) and/or `ek_hash_path` (SHA-256 pubkey hash allowlist). At least one must be configured when `require_tpm = true`.

Use `pigeon-enroll ek-hash` to print the EK public key hash for populating the allowlist. Use `-skip-tpm` on the client for dev/testing only.

## Config

```hcl
listen       = ":8443"
key_path     = "/encrypted/pigeon/enrollment-key"
token_window = "30m"
server_cert_ttl = "720h"
audit_path   = "/var/log/pigeon-enroll/audit.jsonl"
require_tpm  = true

# EK identity validation (SPIRE community TPM plugin pattern).
# At least one required when require_tpm = true.
ek_ca_path   = "/etc/pigeon/ek-ca"      # directory of manufacturer CA certs (PEM/DER)
ek_hash_path = "/etc/pigeon/ek-hashes"   # file with one SHA-256 EK pubkey hash per line

secret "secret_a" {
  length   = 32
  encoding = "base64"
}

secret "secret_b" {
  length   = 16
  encoding = "hex"
  scope    = "server"
}

secrets_path = "/encrypted/pigeon/enroll.json"

vars = {
  datacenter = "eu-west-gra"
  seeds      = "10.0.0.1,10.0.0.2"
}

action "vault-init" {
  addr             = "https://127.0.0.1:8200"
  secret_shares    = 1
  secret_threshold = 1
  output           = "/encrypted/vault/init.json"

  token {
    id          = "secret_a"
    policies    = ["root"]
    revoke_root = true
  }
}
```

`secrets` are derived via HKDF-SHA256; `vars` are static key-value pairs. Both are returned in the claim response under separate keys. `secrets_path` persists derived secrets on first start and loads from disk on restart.

## API

gRPC service defined in `internal/proto/enroll/v1/enroll.proto`.

### `EnrollService.Claim` (bidirectional stream)

Bidirectional gRPC stream for TPM attestation and secret distribution. The client sends `ClaimRequest` messages and receives `ClaimResponse` messages:

1. Client sends `ClaimRequest` with `token`, `scope`, `subject`, `ek_pub`, `ek_cert` (optional), `ak_params`, and optionally `csr_der`
2. Server validates token and EK identity, returns `ClaimResponse` with `credential_activation_challenge`
3. Client sends `ClaimRequest` with `activated_secret`
4. Server verifies activation, returns `ClaimResponse` with `secrets`, `vars`, `jwts`, `jwt_keys`, and optionally `signed_cert_der`

Without TPM (`-skip-tpm`, dev/testing): single-round — client sends token-only request, server returns secrets immediately.

### Health

Standard gRPC health check via `grpc.health.v1.Health`.

## Actions

Pluggable post-claim lifecycle actions. Run via `run-actions` (all) or `run-actions -type=<type>` (specific).

### vault-init

Initializes Vault and creates a management token with a known HKDF-derived ID, so other tools can independently derive the same token without coordination. Idempotent — skips gracefully if Vault is already initialized.

1. Polls Vault until reachable
2. Initializes (Shamir or auto-unseal depending on config)
3. Creates management token with `token.id` (HKDF-derived)
4. Optionally revokes root token and redacts it from output

```hcl
action "vault-init" {
  addr             = "https://127.0.0.1:8200"
  secret_shares    = 1
  secret_threshold = 1
  output           = "/encrypted/vault/init.json"

  token {
    id          = "vault_management_token"
    policies    = ["root"]
    revoke_root = true
  }
}
```

For auto-unseal, also set `recovery_shares` and `recovery_threshold`.

### luks-recovery

Adds a recovery passphrase to a LUKS2 keyslot for disaster recovery. Uses the volume key from an already unlocked dm-crypt device to authenticate. Fails if the keyslot is already occupied.

```hcl
action "luks-recovery" {
  device      = "/dev/md1"
  mapped_name = "encrypted"
  key_slot    = 1
  secret      = "luks_recovery"
}
```

## Render

One-shot HCL template rendering using `hclsyntax.ParseTemplate()` — Terraform's `templatefile()` engine. Template syntax: `${var}` for interpolation, `{{ }}` passes through as literal text.

```hcl
template {
  source      = "/etc/pigeon/templates/consul.hcl.tpl"
  destination = "/encrypted/consul/consul.hcl"
  perms       = "0640"
}
```

Variables come from the `-vars` JSON file, passed as-is to templates. Like Terraform's `templatefile(path, vars)`, the vars object can contain nested maps — templates navigate the structure directly (e.g. `${secrets.gossip_key}`, `${vars.datacenter}`).

## Build

```bash
make build    # Build binary → build/pigeon-enroll
make test     # Run unit tests
make vet      # Run go vet
```