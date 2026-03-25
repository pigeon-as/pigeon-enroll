# pigeon-enroll

**Experimental** bootstrap enrollment server and client that derives bootstrap secrets from a shared enrollment key (HKDF) and distributes them to clients via one-time, time-windowed HMAC tokens. Pluggable request verification and post-claim actions.

**Not a secrets manager:** covers the minimum secrets needed before Vault is available. The enrollment key is static; all servers with the same key independently derive identical secrets. A separate HMAC signing key is derived from it for token operations.

**Stage-0 bootstrap:** [pigeon-enroll](https://github.com/pigeon-as/pigeon-enroll) is a dumb pipe (token in, secrets out), [pigeon-template](https://github.com/pigeon-as/pigeon-template) is a dumb renderer (data in, config files out). Neither knows about the other. Neither forces a workflow.

## Usage

```bash
# Server (reads /etc/pigeon/enroll.json by default)
pigeon-enroll server

# Generate a claim token
pigeon-enroll generate-token [-scope=worker]

# Generate a client TLS certificate bundle (PEM to stdout)
pigeon-enroll generate-cert

# Generate a client TLS certificate bundle (PEM to file)
pigeon-enroll generate-cert -output /tmp/client.pem

# Claim (worker side, with mTLS)
pigeon-enroll claim -url https://enroll:8443/claim \
  -token <hmac> -tls /tmp/enroll-cert.pem \
  -scope worker \
  -output /encrypted/pigeon/secrets.json

# Run all actions
pigeon-enroll run-actions

# Run a specific action
pigeon-enroll run-actions -type=vault-init
```

## TLS

mTLS is enabled by default — the CA is derived deterministically from the enrollment key via HKDF. Every server with the same key produces the same Ed25519 CA, no coordination needed. Server certs (P-256, 30d validity) and client certs (P-256, 1h validity) are signed by this CA.

`generate-cert` outputs a standard PEM bundle (client cert + EC private key + CA cert) to stdout, or to a file with `-output <path>` (0600 perms). The autoscaler pipes through `base64 -w0` for ConfigDrive embedding.

Use `-skip-tls` for testing without TLS.

## Config

```json
{
  "listen": ":8443",
  "key_path": "/encrypted/pigeon/enrollment-key",
  "token_window": "30m",
  "audit_path": "/var/log/pigeon-enroll/audit.jsonl",
  "trusted_proxies": ["10.0.0.0/8"],
  "verifiers": [
    {"type": "cidr", "config": {"allow": ["0.0.0.0/0", "::/0"]}}
  ],
  "secrets": [
    {"name": "secret_a", "length": 32, "encoding": "base64"},
    {"name": "secret_b", "length": 16, "encoding": "hex", "scope": "server"}
  ],
  "secrets_path": "/encrypted/pigeon/secrets.json",
  "vars": {
    "datacenter": "eu-west-gra",
    "seeds": "10.0.0.1,10.0.0.2"
  },
  "actions": [
    {
      "type": "vault-init",
      "config": {
        "addr": "https://127.0.0.1:8200",
        "secret_shares": 1,
        "secret_threshold": 1,
        "output": "/encrypted/vault/init.json",
        "token": {
          "id": "secret_a",
          "policies": ["root"],
          "revoke_root": true
        }
      }
    }
  ]
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

Initializes Vault and creates a management token with a known HKDF-derived ID, so other tools can independently derive the same token without coordination. Fails if Vault is already initialized.

1. Polls Vault until reachable
2. Initializes (Shamir or auto-unseal depending on config)
3. Creates management token with `token.id` (HKDF-derived)
4. Optionally revokes root token and redacts it from output

```json
{
  "type": "vault-init",
  "config": {
    "addr": "https://127.0.0.1:8200",
    "secret_shares": 1,
    "secret_threshold": 1,
    "output": "/encrypted/vault/init.json",
    "token": {
      "id": "vault_management_token",
      "policies": ["root"],
      "revoke_root": true
    }
  }
}
```

For auto-unseal, also set `recovery_shares` and `recovery_threshold`.

### luks-recovery

Adds a recovery passphrase to a LUKS2 keyslot for disaster recovery. Uses the volume key from an already unlocked dm-crypt device to authenticate. Fails if the keyslot is already occupied.

```json
{
  "type": "luks-recovery",
  "config": {
    "device": "/dev/md1",
    "mapped_name": "encrypted",
    "key_slot": 1,
    "secret": "luks_recovery"
  }
}
```

## Verifiers

Pluggable claim verification. Multiple verifiers run as a chain. All verifiers are fatal by default — set `"fatal": false` to log and continue instead.

| Type | Description |
|------|-------------|
| `cidr` | Allow claims from specific CIDRs |
| `ovh` | Verify client IP is an OVH-owned server |

## Build

```bash
make build    # Build binary → build/pigeon-enroll
make test     # Run unit tests
make vet      # Run go vet
```