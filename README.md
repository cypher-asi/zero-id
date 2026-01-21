# zero-auth

A cryptographic identity and authentication service with client-controlled roots.

## Overview

zero-auth is a modular authentication system built on the principle that cryptographic root material should never leave client devices. The server operates in a zero-trust model where it cannot decrypt, sign, or impersonate users without their active participation.

### Core Principles

1. **Client-Controlled Cryptography**: The root secret (Neural Key) is generated and stored exclusively on client devices
2. **Hierarchical Key Derivation**: All keys are deterministically derived from the Neural Key using HKDF-SHA256
3. **Per-Device Operations**: Daily authentication uses Machine Keys, not root material
4. **Threshold Recovery**: Account recovery via 3-of-5 Neural Shards using Shamir Secret Sharing
5. **Protocol Agnostic**: Multiple authentication methods (cryptographic, email, OAuth, wallet)

## How the System Works

### The Neural Key

The Neural Key is a 32-byte (256-bit) cryptographically random value that serves as the root secret for an identity. It has the following properties:

- Generated client-side using a cryptographically secure random number generator
- Never transmitted over the network or stored on the server
- The private key is never stored on a hard drive
- All other keys are derived from it deterministically
- Protected via Shamir Secret Sharing for disaster recovery
- Zeroized from memory immediately after use

When creating an identity, the client:

1. Generates a Neural Key locally
2. Derives an Identity Signing Key from the Neural Key
3. Derives a Machine Key for the current device
4. Sends only the public keys to the server
5. Splits the Neural Key into 5 Neural Shards for recovery

### Key Hierarchy

All keys in the system are derived from the Neural Key using HKDF-SHA256 with domain separation:

```
Neural Key (32 bytes, client-only)
    |
    +-- Identity Signing Key (Ed25519)
    |   Domain: "cypher:auth:identity:v1" || identity_id
    |   Purpose: Signs machine enrollments, key rotations, recovery operations
    |
    +-- Machine Key [per device, per epoch]
        Domain: "cypher:shared:machine:v1" || identity_id || machine_id || epoch
        |
        +-- Signing Key (Ed25519)
        |   Domain: "cypher:shared:machine:sign:v1" || machine_id
        |   Purpose: Signs authentication challenges and messages
        |
        +-- Encryption Key (X25519)
            Domain: "cypher:shared:machine:encrypt:v1" || machine_id
            Purpose: Diffie-Hellman key exchange, encrypting data
```

Domain separation ensures that even if two derivations use the same input, they produce different outputs if their purposes differ.

### Machine Keys

Machine Keys are the primary credentials used for day-to-day authentication. Each device enrolled with an identity has its own Machine Key with the following characteristics:

- **Derived, not random**: Computed deterministically from the Neural Key, identity ID, machine ID, and epoch
- **Dual-purpose**: Contains both an Ed25519 signing key and an X25519 encryption key
- **Capability-based**: Each Machine Key has a set of capabilities controlling what operations it can perform
- **Revocable**: Can be revoked independently without affecting other devices
- **Epoched**: Key material rotates with epoch changes during key rotation ceremonies

Machine Key capabilities include:

| Capability | Description |
|------------|-------------|
| AUTHENTICATE | Can authenticate to zero-auth |
| SIGN | Can sign challenges and messages |
| ENCRYPT | Can encrypt/decrypt data |
| SVK_UNWRAP | Can unwrap vault keys (for zero-vault integration) |
| MLS_MESSAGING | Can participate in MLS messaging groups |
| VAULT_OPERATIONS | Can access vault operations |

### Identity Lifecycle

1. **Creation**: Client generates Neural Key, derives keys, sends public keys to server
2. **Enrollment**: Additional devices are enrolled by deriving new Machine Keys
3. **Authentication**: Machine Keys prove identity via challenge-response
4. **Key Rotation**: Neural Key can be rotated with approval from multiple devices
5. **Recovery**: If Neural Key is lost, reconstruct from 3 of 5 recovery shards
6. **Revocation**: Individual devices or entire identity can be revoked

### Challenge-Response Authentication

Machine Key authentication uses a challenge-response protocol:

1. Client requests a challenge from the server
2. Server generates a random 32-byte nonce with a 60-second expiry
3. Client signs the challenge using their Machine Key (Ed25519)
4. Server verifies the signature against the registered public key
5. On success, server issues JWT access token and refresh token

The challenge includes canonical encoding to prevent malleability attacks:

```
Challenge = EntityType || identity_id || machine_id || operation || nonce || expiry
```

### Session and Token Management

Upon successful authentication, the server issues:

- **Access Token (JWT)**: Short-lived (15 minutes), signed with Ed25519 (EdDSA), contains identity and machine claims
- **Refresh Token**: Long-lived (30 days), opaque string, enables obtaining new access tokens

Token security features:

- JWT signing keys derived from a server-side master key with epoch rotation
- Refresh token rotation on each use (old tokens become invalid)
- Reuse detection: if a revoked refresh token is used, all tokens in that family are revoked
- Public keys published at `/.well-known/jwks.json` for external validation

### Recovery via Shamir Secret Sharing

The Neural Key is split into 5 shares using 3-of-5 Shamir Secret Sharing:

- Any 3 shares can reconstruct the original Neural Key
- Fewer than 3 shares reveal absolutely no information about the key
- Shares should be distributed to trusted custodians or stored in separate secure locations

Recovery process:

1. Collect 3 or more recovery shards
2. Reconstruct the Neural Key
3. Derive a new Identity Signing Key
4. Register new Machine Keys for current devices
5. Invalidate all previous sessions

## Authentication Methods

zero-auth supports multiple authentication methods:

| Method | Description | Use Case |
|--------|-------------|----------|
| Machine Key | Ed25519 challenge-response | Primary authentication for enrolled devices |
| Email + Password | Argon2id password hashing | Fallback authentication, account linking |
| OAuth | Google, X/Twitter, Epic Games | Social login, account linking |
| Wallet | EVM signatures (EIP-191, SECP256k1) | Blockchain-based authentication |
| MFA | TOTP with backup codes | Additional security for sensitive operations |

All methods can be combined with MFA for high-security operations.

## Architecture

The system is composed of modular crates:

| Crate | Purpose |
|-------|---------|
| `zero-auth-crypto` | Cryptographic primitives (Ed25519, X25519, XChaCha20-Poly1305, HKDF, Argon2id) |
| `zero-auth-storage` | RocksDB abstraction layer with column families |
| `zero-auth-policy` | Policy engine for authorization and rate limiting |
| `zero-auth-identity-core` | Identity and Machine Key management |
| `zero-auth-methods` | Authentication methods (Machine Key, Email, OAuth, Wallet, MFA) |
| `zero-auth-sessions` | Session and JWT token management |
| `zero-auth-integrations` | Event streaming (SSE) and webhooks |
| `zero-auth-server` | HTTP API server (Axum) |
| `zero-auth-client` | Official CLI client |

## Getting Started

### Prerequisites

- Rust 1.75.0 or later
- OpenSSL development libraries

### Building

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace
```

### Running the Server

The server requires a service master key for JWT signing and encryption operations:

```bash
# Generate a random service master key (64 hex characters = 32 bytes)

# On Unix/Linux/macOS:
export SERVICE_MASTER_KEY=$(openssl rand -hex 32)

# On Windows PowerShell:
$env:SERVICE_MASTER_KEY = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })

# Run the server
cargo run -p zero-auth-server
```

The server starts on `http://127.0.0.1:8080` by default.

### Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SERVICE_MASTER_KEY` | Yes | - | 64-character hex string (32 bytes) for cryptographic operations |
| `BIND_ADDRESS` | No | `127.0.0.1:8080` | Server bind address |
| `DATABASE_PATH` | No | `./data/zero-auth.db` | Path to RocksDB database |
| `JWT_ISSUER` | No | `https://zero-auth.cypher.io` | JWT issuer claim |
| `JWT_AUDIENCE` | No | `zero-vault` | JWT audience claim |
| `ACCESS_TOKEN_EXPIRY_SECONDS` | No | `900` (15 min) | Access token lifetime |
| `REFRESH_TOKEN_EXPIRY_SECONDS` | No | `2592000` (30 days) | Refresh token lifetime |

### Using the CLI Client

```bash
# Create an identity with client-side cryptography
cargo run -p zero-auth-client -- create-identity --device-name "My Laptop"

# Authenticate with machine key challenge-response
cargo run -p zero-auth-client -- login

# View your credentials (Neural Key, identity, machine info)
cargo run -p zero-auth-client -- show-credentials

# Enroll another device
cargo run -p zero-auth-client -- enroll-machine --device-name "My Phone"

# List all enrolled machines
cargo run -p zero-auth-client -- list-machines

# Refresh expired access token
cargo run -p zero-auth-client -- refresh-token
```

See `crates/zero-auth-client/README.md` for complete client documentation.

### Testing

```bash
# Run all unit tests
cargo test --workspace

# Run integration tests
cargo test --workspace --test '*' -- --ignored

# Run with output
cargo test --test identity_creation -- --ignored --nocapture
```

## API Reference

### Health and Status

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/ready` | GET | Readiness check |

### Identity Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/identity` | POST | Create new identity |
| `/v1/identity/:id` | GET | Get identity details |
| `/v1/identity/freeze` | POST | Freeze identity |
| `/v1/identity/unfreeze` | POST | Unfreeze identity |
| `/v1/identity/recovery` | POST | Perform recovery ceremony |
| `/v1/identity/rotation` | POST | Rotate Neural Key |

### Machine Key Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/machines/enroll` | POST | Enroll new device |
| `/v1/machines` | GET | List enrolled devices |
| `/v1/machines/:id` | DELETE | Revoke device access |

### Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/challenge` | GET | Get authentication challenge |
| `/v1/auth/login/machine` | POST | Login with machine key |
| `/v1/auth/login/email` | POST | Login with email/password |
| `/v1/auth/login/wallet` | POST | Login with crypto wallet |
| `/v1/auth/oauth/:provider` | GET | Initiate OAuth flow |
| `/v1/auth/oauth/:provider/callback` | POST | Complete OAuth flow |

### Session Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/auth/refresh` | POST | Refresh access token |
| `/v1/auth/introspect` | POST | Validate and inspect token |
| `/v1/session/revoke` | POST | Revoke current session |
| `/v1/session/revoke-all` | POST | Revoke all sessions |
| `/.well-known/jwks.json` | GET | JWT public keys (JWKS) |

### Multi-Factor Authentication

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/mfa/setup` | POST | Setup TOTP MFA |
| `/v1/mfa` | DELETE | Disable MFA |

### Integrations

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/integrations/register` | POST | Register external service |
| `/v1/events/stream` | GET | Server-Sent Events stream |

## Cryptographic Standards

| Operation | Algorithm | Standard |
|-----------|-----------|----------|
| Signatures | Ed25519 | RFC 8032 |
| Key Exchange | X25519 | RFC 7748 |
| Encryption | XChaCha20-Poly1305 | RFC 8439 |
| Key Derivation | HKDF-SHA256 | RFC 5869 |
| Password Hashing | Argon2id (64MB, 3 iterations) | RFC 9106 |
| Non-password Hashing | BLAKE3 | - |
| MFA | TOTP (SHA-1, 6 digits, 30s) | RFC 6238 |

## Security Properties

- **Client-Controlled Keys**: Neural Key never leaves client devices
- **Deterministic Derivation**: All keys derived reproducibly from Neural Key
- **Zeroization**: Sensitive material erased from memory after use
- **No Unsafe Code**: Entire codebase uses `#![forbid(unsafe_code)]`
- **Domain Separation**: Unique domain strings prevent key reuse across purposes
- **Canonical Encoding**: Signed messages use deterministic binary format
- **Rate Limiting**: Built-in rate limiting per identity and operation
- **Token Security**: EdDSA-signed JWTs with short expiry and refresh rotation
- **Comprehensive Revocation**: Per-session, per-identity, and epoch-level revocation

## Integrating with Your Application

### Token Introspection

The simplest integration method - validate tokens by calling the introspection endpoint:

```rust
let response = client
    .post("http://127.0.0.1:8080/v1/auth/introspect")
    .json(&json!({ "token": token, "operation_type": "protected" }))
    .send()
    .await?;

let info: IntrospectResponse = response.json().await?;
if info.active {
    // Token is valid, info.identity_id contains the user
}
```

### JWKS Validation

For better performance, validate JWTs locally using the public keys from `/.well-known/jwks.json`:

1. Fetch JWKS once at startup (and periodically refresh)
2. Decode JWT and extract `kid` (key ID) from header
3. Find matching key in JWKS
4. Verify signature and claims locally

This eliminates a network round-trip for each request.

## Project Status

**Current Version**: 0.1.0 (Alpha)

The system is feature-complete with all major subsystems implemented:

- Identity creation and lifecycle management
- Multi-device enrollment and revocation
- Multiple authentication methods
- JWT token issuance and validation
- Session management with refresh rotation
- Rate limiting and policy enforcement
- Event streaming and webhooks

## Contributing

```bash
# Format code
cargo fmt --all

# Check lints
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test --workspace
```

## License

MIT License
