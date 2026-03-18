# pigeon-enroll

**Experimental** bootstrap enrollment server and client that derives bootstrap secrets from a shared enrollment key (HKDF) and distributes them to clients via one-time, time-windowed HMAC tokens. Optional request verification and Vault initialization support.

Not a secrets manager — covers the minimum secrets needed before Vault is available. The enrollment key is static; all servers with the same key independently derive identical secrets. A separate HMAC signing key is derived from it for token operations.

> **Stage-0 bootstrap:** pigeon-enroll is a dumb pipe (token in, secrets out), pigeon-template is a dumb renderer (data in, config files out). Neither knows about the other. Neither forces a workflow.

## Usage

```bash
# Server
pigeon-enroll --config=/etc/pigeon/enroll.json

# Generate a claim token
pigeon-enroll --generate-token --config=/etc/pigeon/enroll.json [--scope=worker]

# Claim (worker side)
pigeon-enroll --claim --url https://enroll:8443/claim \
  --token <hmac> --scope worker \
  --output /encrypted/pigeon/secrets.json

# Run all actions
pigeon-enroll --run-actions --config=/etc/pigeon/enroll.json

# Run a specific action
pigeon-enroll --run-actions=vault-init --config=/etc/pigeon/enroll.json
```

## Config

```json
{
  "listen": ":8443",
  "key_path": "/encrypted/pigeon/enrollment-key",
  "tls_cert": "/path/to/cert.pem",
  "tls_key": "/path/to/key.pem",
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

Pluggable post-claim lifecycle actions. Run via `--run-actions` (all) or `--run-actions=<type>` (specific).

### vault-init

Initializes Vault and creates a management token with a known HKDF-derived ID, so other tools can independently derive the same token without coordination.

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

## Verifiers

Pluggable claim verification. Multiple verifiers run as a chain. Each has a `fatal` flag — fatal verifiers reject the claim, non-fatal log and continue.

| Type | Description | Default fatal |
|------|-------------|---------------|
| `cidr` | Allow claims from specific CIDRs | no |
| `ovh` | Verify client IP is an OVH-owned server | yes |

## Build

```bash
make build    # Build binary → build/pigeon-enroll
make test     # Run unit tests
make vet      # Run go vet
```