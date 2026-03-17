# pigeon-enroll

**Experimental** bootstrap enrollment server for pigeon infrastructure. Derives and distributes the minimum secrets needed before Vault is available. Not a secrets manager. Workers present a one-time HMAC token to receive bootstrap secrets.

The enrollment key is static — all servers with the same key independently derive identical secrets via HKDF-SHA256. A separate HMAC signing key is derived from it for token operations.

## Usage

```bash
# Server
pigeon-enroll --config=/etc/pigeon/enroll.json

# Generate a claim token
pigeon-enroll --generate-token --config=/etc/pigeon/enroll.json [--generate-scope=worker]

# Claim (worker side)
pigeon-enroll --claim --url https://enroll:8443/claim \
  --token <hmac> --scope worker \
  --output /encrypted/pigeon/secrets.json

# Initialize Vault
pigeon-enroll --vault-init --config=/etc/pigeon/enroll.json \
  --vault-output=/encrypted/vault/init.json
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

## Vault Init

Initializes Vault and creates a management token with a known HKDF-derived ID. Both pigeon-enroll and Terraform independently derive the same token ID from the enrollment key.

1. Polls Vault until reachable
2. Initializes (Shamir or auto-unseal depending on config)
3. Creates management token with `vault.token.id` (HKDF-derived)
4. Optionally revokes root token and redacts it from output

```json
{
  "vault": {
    "addr": "https://127.0.0.1:8200",
    "secret_shares": 1,
    "secret_threshold": 1,
    "token": {
      "id": "vault_management_token",
      "policies": ["root"],
      "revoke_root": true
    }
  }
}
```

For auto-unseal, also set `recovery_shares` and `recovery_threshold`.

## Build

```bash
make build    # Build binary → build/pigeon-enroll
make test     # Run unit tests
make vet      # Run go vet
```