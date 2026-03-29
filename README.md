# pigeon-enroll

**Experimental** bootstrap enrollment server and client that derives bootstrap secrets from a shared enrollment key (HKDF) and distributes them to clients via mTLS and one-time, time-windowed HMAC tokens. Pluggable post-claim actions.

**Not a secrets manager:** covers the minimum secrets needed before Vault is available. The enrollment key is static; all servers with the same key independently derive identical secrets. A separate HMAC signing key is derived from it for token operations.

**Stage-0 bootstrap:** [pigeon-enroll](https://github.com/pigeon-as/pigeon-enroll) is a dumb pipe (token in, secrets out), [pigeon-template](https://github.com/pigeon-as/pigeon-template) is a dumb renderer (data in, config files out). Neither knows about the other. Neither forces a workflow.

## Usage

```bash
# Server (reads /etc/pigeon/enroll.hcl by default)
pigeon-enroll server

# Generate a claim token
pigeon-enroll generate-token [-scope=worker]

# Generate a client TLS certificate bundle
pigeon-enroll generate-cert -bundle /tmp/enroll-cert.pem

# Claim (worker side, with mTLS)
pigeon-enroll claim -url https://enroll:8443/claim \
  -token <hmac> -tls /tmp/enroll-cert.pem \
  -scope worker \
  -output /encrypted/pigeon/secrets.json

# Render templates (worker side, one-shot after claim)
pigeon-enroll render \
  -config /etc/pigeon/render.hcl \
  -vars /encrypted/pigeon/secrets.json

# Run all actions
pigeon-enroll run-actions

# Run a specific action
pigeon-enroll run-actions -type=vault-init
```

## TLS

mTLS is enabled by default — the CA is derived deterministically from the enrollment key via HKDF. Every server with the same key produces the same Ed25519 CA, no coordination needed. Server certs (P-256, `server_cert_ttl` default 30d) auto-rotate at 50% lifetime.

`generate-cert` outputs are explicit: `-bundle FILE` writes a PEM bundle (cert+key+ca), `-cert`/`-key`/`-ca` write individual files. `-bundle -` writes to stdout. EKU is inferred from SANs: `-dns`/`-ip` present → ServerAuth + ClientAuth, no SANs → ClientAuth only. `-ttl` sets validity (default 24h). `-base64` base64-encodes bundle output.

Use `-skip-tls` for testing without TLS.

## Config

```hcl
listen       = ":8443"
key_path     = "/encrypted/pigeon/enrollment-key"
token_window = "30m"
client_cert_ttl = "1h"
server_cert_ttl = "720h"
audit_path   = "/var/log/pigeon-enroll/audit.jsonl"
trusted_proxies = ["10.0.0.0/8"]

secret "secret_a" {
  length   = 32
  encoding = "base64"
}

secret "secret_b" {
  length   = 16
  encoding = "hex"
  scope    = "server"
}

secrets_path = "/encrypted/pigeon/secrets.json"

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

`trusted_proxies` is a list of CIDRs. When a request comes from a trusted proxy, the client IP is read from `X-Forwarded-For` instead of `RemoteAddr`.

## API

### `POST /claim`

```json
{"token": "<hmac>", "scope": "worker"}
```

Returns filtered secrets + vars:

```json
{"secrets": {"secret_a": "..."}, "vars": {"datacenter": "eu-west-gra"}}
```

### `GET /health`

Returns `{"status": "ok"}`.

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

### vault-cert-auth

Configures Vault's `auth/cert` method with a role that trusts the enrollment CA. This bridges stage 0 (enrollment) to stage 1 (Vault PKI) — nodes with enrollment-CA-signed client certs can authenticate to Vault via vault-agent. Idempotent — skips if auth/cert is already enabled, upserts the role.

Reads the enrollment CA public cert from disk (`ca_cert_file`) and authenticates to Vault using the management token from the secrets map (`token_secret`).

```hcl
action "vault-cert-auth" {
  addr          = "https://127.0.0.1:8200"
  tls_skip_verify = true
  ca_cert_file  = "/encrypted/tls/node.ca.crt"
  token_secret  = "vault_management_token"
  role          = "node"
  policies      = ["node-pki"]
  token_ttl     = "1h"
}
```

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