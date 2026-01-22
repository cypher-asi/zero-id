# zero-id

A cryptographic identity and authentication service with client-controlled roots.

## Table of Contents

- [Quantum-Resistant Cryptography](#quantum-resistant-cryptography)
- [Overview](#overview)
  - [Core Principles](#core-principles)
  - [Open Source & Self-Hosting](#open-source--self-hosting)
- [How the System Works](#how-the-system-works)
  - [The Neural Key](#the-neural-key)
  - [Key Hierarchy](#key-hierarchy)
  - [Machine Keys](#machine-keys)
  - [Identity Lifecycle](#identity-lifecycle)
  - [Namespaces](#namespaces)
  - [Policy Engine](#policy-engine)
  - [Challenge-Response Authentication](#challenge-response-authentication)
  - [Session and Token Management](#session-and-token-management)
  - [Recovery via Shamir Secret Sharing](#recovery-via-shamir-secret-sharing)
- [Authentication Methods](#authentication-methods)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building](#building)
  - [Running the Server](#running-the-server)
  - [Configuration](#configuration)
  - [Using the CLI Client](#using-the-cli-client)
  - [Machine Management](#machine-management)
  - [Neural Key Recovery](#neural-key-recovery)
  - [Testing](#testing)
  - [Test Coverage](#test-coverage)
- [API Reference](#api-reference)
- [Cryptographic Standards](#cryptographic-standards)
- [Security Properties](#security-properties)
- [Security Auditing](#security-auditing)
- [Integrating with Your Application](#integrating-with-your-application)
- [Project Status](#project-status)
- [Contributing](#contributing)
- [License](#license)

## Quantum-Resistant Cryptography

zero-id supports **post-quantum cryptography** via PQ-Hybrid key derivation, protecting against future quantum computing threats while maintaining backward compatibility.

### Key Schemes

| Scheme | Keys Derived | Use Case |
|--------|-------------|----------|
| **Classical** | Ed25519 + X25519 | Default, OpenMLS compatible, smaller keys |
| **PQ-Hybrid** | Classical + ML-DSA-65 + ML-KEM-768 | Post-quantum protection with backward compatibility |

### Keys Derivable from Neural Key

All keys are deterministically derived from a single 32-byte Neural Key using HKDF-SHA256 with domain separation:

```
Neural Key (32 bytes, client-only)
│
├── Identity Signing Key (Ed25519)
│   Purpose: Signs machine enrollments, key rotations, recovery operations
│
├── MFA Key Encryption Key (XChaCha20-Poly1305)
│   Purpose: Encrypts TOTP secrets
│
└── Machine Key [per device, per epoch]
    │
    ├── Classical Keys (always present)
    │   ├── Signing Key (Ed25519, 32 B)
    │   └── Encryption Key (X25519, 32 B)
    │
    └── Post-Quantum Keys (PQ-Hybrid mode)
        ├── PQ Signing Key (ML-DSA-65, 1,952 B) — FIPS 204
        └── PQ Encryption Key (ML-KEM-768, 1,184 B) — FIPS 203
```

### Post-Quantum Algorithm Sizes

| Algorithm | Standard | Public Key | Signature/Ciphertext |
|-----------|----------|------------|---------------------|
| Ed25519 | RFC 8032 | 32 B | 64 B |
| X25519 | RFC 7748 | 32 B | 32 B |
| ML-DSA-65 | FIPS 204 | 1,952 B | 3,309 B |
| ML-KEM-768 | FIPS 203 | 1,184 B | 1,088 B |

See [Quantum Considerations](docs/encryption/quantum.md) for threat analysis and migration strategy.

---

## Documentation

| Document | Description |
|----------|-------------|
| [Specification v0.1](docs/spec/v0.1/README.md) | Comprehensive system specification with architecture diagrams |
| [API Documentation](docs/api/README.md) | REST API overview, authentication, and quick start |
| [API v1 Reference](docs/api/v1-reference.md) | Complete endpoint documentation |
| [API Errors](docs/api/errors.md) | Error codes and troubleshooting |
| [CLI Client Reference](crates/zero-id-client/REFERENCE.md) | Complete CLI command reference |
| [Encryption Comparison](docs/encryption/comparison.md) | Cryptographic algorithm comparison |
| [Quantum Considerations](docs/encryption/quantum.md) | Post-quantum cryptography notes |

### Specification Deep Dives

For detailed technical specifications of each component:

| Spec | Crate | Description |
|------|-------|-------------|
| [Crypto Primitives](docs/spec/v0.1/01-crypto.md) | `zero-id-crypto` | Key derivation, encryption, signatures, Shamir |
| [Storage](docs/spec/v0.1/02-storage.md) | `zero-id-storage` | Storage abstraction and column families |
| [Policy Engine](docs/spec/v0.1/03-policy.md) | `zero-id-policy` | Rate limiting, reputation, authorization |
| [Identity Core](docs/spec/v0.1/04-identity-core.md) | `zero-id-identity-core` | Identities, machines, namespaces |
| [Integrations](docs/spec/v0.1/05-integrations.md) | `zero-id-integrations` | mTLS auth, SSE streaming, webhooks |
| [Sessions](docs/spec/v0.1/06-sessions.md) | `zero-id-sessions` | JWT issuance, refresh tokens |
| [Auth Methods](docs/spec/v0.1/07-methods.md) | `zero-id-methods` | Machine, email, OAuth, wallet, MFA |
| [Server](docs/spec/v0.1/08-server.md) | `zero-id-server` | HTTP API endpoints and middleware |
| [Client](docs/spec/v0.1/09-client.md) | `zero-id-client` | CLI commands and workflows |
| [System Overview](docs/spec/v0.1/10-system-overview.md) | — | Architecture and data flows |
| [Crypto Primitives Deep Dive](docs/spec/v0.1/11-crypto-primitives.md) | — | Algorithms and binary formats |

## Overview

zero-id is a modular authentication system built on the principle that cryptographic root material should never leave client devices. The server operates in a zero-trust model where it cannot decrypt, sign, or impersonate users without their active participation.

### Core Principles

1. **Client-Controlled Cryptography**: The root secret (Neural Key) is generated and stored exclusively on client devices
2. **Hierarchical Key Derivation**: All keys are deterministically derived from the Neural Key using HKDF-SHA256
3. **Per-Device Operations**: Daily authentication uses Machine Keys, not root material
4. **Threshold Recovery**: Account recovery via 3-of-5 Neural Shards using Shamir Secret Sharing
5. **Protocol Agnostic**: Multiple authentication methods (cryptographic, email, OAuth, blockchain wallets)

### Open Source & Self-Hosting

zero-id is fully open source. Cypher operates the main authentication server at **https://auth.zero.tech** for public use, but anyone can run their own zero-id server. The system is designed to be self-hosted with no vendor lock-in—your cryptographic keys remain under your control regardless of which server you use.

## How the System Works

### The Neural Key

The Neural Key is a 32-byte (256-bit) high entropy cryptographic value that serves as the root secret for an identity. It has the following properties:

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
    |   Domain: "cypher:id:identity:v1" || identity_id
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

**Notation:**

| Term | Description |
|------|-------------|
| `Domain` | The `info` parameter passed to HKDF, which determines the derived key's uniqueness |
| `\|\|` | Byte concatenation |
| `identity_id` | UUID assigned to the identity at creation time |
| `machine_id` | UUID assigned to each enrolled device |
| `epoch` | Integer that increments during key rotation ceremonies, producing new key material |

**Domain separation** ensures that even though all keys are derived from the same Neural Key, each derivation produces a completely different output because the HKDF `info` parameter includes a unique domain string (e.g., `"cypher:id:identity:v1"` vs `"cypher:id:mfa-kek:v1"`). This prevents accidentally deriving the same key for different purposes, which would be a security vulnerability. The contextual identifiers (identity_id, machine_id, epoch) further ensure uniqueness within each key type.

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
| AUTHENTICATE | Can authenticate to zero-id |
| SIGN | Can sign challenges and messages |
| ENCRYPT | Can encrypt/decrypt data |
| SVK_UNWRAP | Can unwrap vault keys (for zero-vault integration) |
| MLS_MESSAGING | Can participate in MLS messaging groups |
| VAULT_OPERATIONS | Can access vault operations |

### Identity Lifecycle

1. **Creation**: Client generates Neural Key, derives keys, sends public keys to server
2. **Enrollment**: Additional devices are enrolled by deriving new Machine Keys
3. **Authentication**: Machine Keys prove identity via challenge-response
4. **Key Rotation**: Neural Key can be replaced, requiring a signature from the current Identity Signing Key, MFA verification, and approval from 2+ enrolled devices
5. **Recovery**: If Neural Key is lost, reconstruct from 3 of 5 recovery shards
6. **Revocation**: Individual devices or entire identity can be revoked

### Namespaces

Namespaces provide multi-tenant isolation and organizational boundaries within zero-id. Every identity operates within at least one namespace, and all sessions and tokens are scoped to a specific namespace context.

#### Namespace Structure

```
Namespace
├── namespace_id: UUID
├── name: String
├── owner_identity_id: UUID
├── created_at: Timestamp
└── active: Boolean
```

When an identity is created, a default namespace is automatically created with the identity as its owner:

```
Identity Creation
    │
    ├── Creates Identity
    ├── Creates Namespace (owned by identity)
    └── Creates IdentityNamespaceMembership (role: Owner)
```

#### Namespace Roles

Identities can belong to multiple namespaces with different permission levels:

| Role | Value | Description |
|------|-------|-------------|
| Owner | 0x01 | Full control over namespace, can manage members and settings |
| Admin | 0x02 | Can manage members and perform administrative operations |
| Member | 0x03 | Basic access within the namespace |

#### Namespace Membership

The relationship between identities and namespaces is tracked via membership records:

```
IdentityNamespaceMembership
├── identity_id: UUID
├── namespace_id: UUID
├── role: NamespaceRole
└── joined_at: Timestamp
```

#### How Namespaces Affect Sessions

Every session is bound to a specific namespace. When a user authenticates, the resulting session and tokens include the namespace context:

```
Session
├── session_id
├── identity_id
├── machine_id
├── namespace_id  ← Scoped to namespace
└── ...

JWT Access Token Claims
├── sub: identity_id
├── machine_id
├── namespace_id  ← Included in token
├── session_id
└── ...
```

This enables:

- **Tenant isolation**: Users in different namespaces cannot access each other's resources
- **Context switching**: A single identity can operate in multiple namespaces with different roles
- **Audit trails**: All operations are traceable to a specific namespace context

#### Example: Multi-Organization Access

Consider a user who belongs to two organizations:

```
Alice's Identity
    │
    ├── Namespace: "Acme Corp" (role: Admin)
    │   └── Can manage team members, access admin features
    │
    └── Namespace: "Side Project" (role: Owner)
        └── Full control, billing, settings
```

When Alice logs in, she authenticates to a specific namespace. Her JWT tokens will contain that namespace's ID, and backend services can enforce namespace-scoped permissions accordingly.

### Policy Engine

The Policy Engine provides authorization and rate limiting for all operations. Every authentication attempt and sensitive operation is evaluated against configurable policies before being allowed to proceed.

#### Policy Context

Each policy evaluation receives a context containing:

```
PolicyContext
├── identity_id: UUID
├── machine_id: Option<UUID>
├── namespace_id: UUID
├── auth_method: AuthMethod
├── mfa_verified: bool
├── operation: Operation
├── resource: Option<Resource>
├── ip_address: String
├── user_agent: String
├── timestamp: u64
├── reputation_score: i32
└── recent_failed_attempts: u32
```

#### Policy Verdicts

The engine returns one of five verdicts:

| Verdict | Description |
|---------|-------------|
| Allow | Operation permitted |
| Deny | Operation blocked |
| RequireAdditionalAuth | MFA or additional factor required |
| RequireApproval | Multi-device approval needed |
| RateLimited | Too many attempts, try later |

#### Operation Risk Levels

Operations are classified by risk level, which determines security requirements:

**High-Risk Operations** (require MFA when enabled):
- Disable Identity
- Freeze Identity
- Rotate Neural Key
- Disable MFA
- Change Password
- Revoke All Sessions

**Operations Requiring Multi-Device Approval**:
- Rotate Neural Key → 2 device approvals
- Unfreeze Identity → 2 device approvals

#### Rate Limiting

The policy engine enforces rate limits at multiple levels:

| Level | Window | Limit | Purpose |
|-------|--------|-------|---------|
| IP Address | 1 minute | 100 requests | Prevent brute force from single source |
| Identity | 1 hour | 1000 requests | Prevent account abuse |
| Failed Attempts | 15 minutes | 5 failures | Lock out after repeated failures |

Rate limit information is returned in response headers:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705320060
```

#### Reputation System

Each identity maintains a reputation score (0-100) that influences policy decisions:

- **Starting score**: 50 (neutral)
- **Successful operations**: Increase score
- **Failed operations**: Decrease score
- **Score below threshold**: Automatic denial

The reputation system helps identify potentially compromised accounts or malicious actors without requiring manual intervention.

#### Policy Evaluation Flow

```
Request
    │
    ├── 1. IP Rate Limit Check (middleware)
    │
    ├── 2. Authentication
    │
    └── 3. Policy Evaluation
            │
            ├── Identity status (frozen?)
            ├── Machine status (revoked?)
            ├── Namespace status (active?)
            ├── Operation risk level
            ├── MFA requirements
            ├── Reputation score
            ├── Failed attempt count
            └── Approval requirements
                    │
                    └── Verdict (Allow/Deny/RequireAuth/...)
```

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

- JWT signing keys are derived from a server-side master key using HKDF-SHA256 with epoch rotation
- The master key is designed to be stored in a Trusted Execution Environment (TEE); even if compromised, it cannot access or derive user keys since Neural Keys never leave client devices
- Refresh token rotation on each use (old tokens become invalid)
- Reuse detection: if a revoked refresh token is used, all tokens in that family are revoked
- Public keys published at `/.well-known/jwks.json` for external validation

### Recovery via Shamir Secret Sharing

The Neural Key is split into 5 Neural Shards using 3-of-5 Shamir Secret Sharing:

- Any 3 shards can reconstruct the original Neural Key
- Fewer than 3 shards reveal absolutely no information about the key
- Shards should be distributed to trusted custodians or stored in separate secure locations

**Local shard encryption:** Two Neural Shards are stored encrypted on the client device using a password-derived key. The encryption key is derived from the user's password using Argon2id (64MB memory, 3 iterations), and the shards are encrypted with XChaCha20-Poly1305 AEAD. This allows users to recover locally if they remember their password, while the remaining 3 shards can be distributed to trusted custodians for disaster recovery.

Recovery process:

1. Collect 3 or more recovery shards
2. Reconstruct the Neural Key
3. Derive a new Identity Signing Key
4. Register new Machine Keys for current devices
5. Invalidate all previous sessions

## Authentication Methods

zero-id supports multiple authentication methods:

| Method | Description | Use Case |
|--------|-------------|----------|
| Machine Key | Ed25519 challenge-response | Primary authentication for enrolled devices |
| Email + Password | Argon2id password hashing | Fallback authentication, account linking |
| OAuth | Google, X/Twitter, Epic Games | Social login, account linking |
| Wallet | EVM signatures (EIP-191, SECP256k1) | Blockchain-based authentication |
| MFA | TOTP with backup codes | Additional security for sensitive operations |

The authentication system is designed to be extensible with OAuth and OIDC, allowing integration with any range of trusted identity providers. New providers can be added as modules to the system without modifying the core authentication logic.

All methods can be combined with MFA for high-security operations.

## Architecture

The system is composed of modular crates:

| Crate | Purpose |
|-------|---------|
| `zero-id-crypto` | Cryptographic primitives (Ed25519, X25519, XChaCha20-Poly1305, HKDF, Argon2id) |
| `zero-id-storage` | RocksDB abstraction layer with column families on server |
| `zero-id-policy` | Policy engine for authorization and rate limiting |
| `zero-id-identity-core` | Identity and Machine Key management |
| `zero-id-methods` | Authentication methods (Machine Key, Email, OAuth, Wallet, MFA) |
| `zero-id-sessions` | Session and JWT token management |
| `zero-id-integrations` | Event streaming (SSE) and webhooks |
| `zero-id-server` | HTTP API server (Axum) |
| `zero-id-client` | Official CLI client |

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
cargo run -p zero-id-server
```

The server starts on `http://127.0.0.1:9999` by default.

### Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SERVICE_MASTER_KEY` | Yes | - | 64-character hex string (32 bytes) for cryptographic operations |
| `BIND_ADDRESS` | No | `127.0.0.1:9999` | Server bind address |
| `DATABASE_PATH` | No | `./data/zero-id.db` | Path to RocksDB database |
| `JWT_ISSUER` | No | `https://zero-id.cypher.io` | JWT issuer claim |
| `JWT_AUDIENCE` | No | `zero-vault` | JWT audience claim |
| `ACCESS_TOKEN_EXPIRY_SECONDS` | No | `900` (15 min) | Access token lifetime |
| `REFRESH_TOKEN_EXPIRY_SECONDS` | No | `2592000` (30 days) | Refresh token lifetime |

### Using the CLI Client

```bash
# Create an identity with client-side cryptography
cargo run -p zero-id-client -- create-identity --device-name "My Laptop"

# Authenticate with machine key challenge-response
cargo run -p zero-id-client -- login

# View your credentials (Neural Key, identity, machine info)
cargo run -p zero-id-client -- show-credentials

# Enroll another device
cargo run -p zero-id-client -- enroll-machine --device-name "My Phone"

# List all enrolled machines
cargo run -p zero-id-client -- list-machines

# Refresh expired access token
cargo run -p zero-id-client -- refresh-token
```

#### Machine Management

```bash
# Remove a compromised or lost device
cargo run -p zero-id-client -- revoke-machine <machine-id> --reason "Device lost"

# Rotate a machine key (enroll replacement, then revoke old)
cargo run -p zero-id-client -- enroll-machine --device-name "My Laptop (rotated)"
cargo run -p zero-id-client -- revoke-machine <old-machine-id> --reason "Key rotation"
```

#### Neural Key Recovery

If you lose access to your Neural Key, reconstruct it from any 3 of your 5 Neural Shards:

```bash
# Recover identity using 3 Neural Shards (displayed during identity creation)
cargo run -p zero-id-client -- recover \
  --shard <shard1-hex> \
  --shard <shard2-hex> \
  --shard <shard3-hex> \
  --device-name "Recovery Device"
```

This reconstructs the Neural Key, derives fresh Machine Keys, and enrolls the recovery device. Store your Neural Shards securely in separate locations (password manager, safe deposit box, trusted contacts).

See `crates/zero-id-client/README.md` for complete client documentation.

### Testing

```bash
# Run all unit tests
cargo test --workspace

# Run integration tests
cargo test --workspace --test '*' -- --ignored

# Run with output
cargo test --test identity_creation -- --ignored --nocapture
```

### Test Coverage

| Crate | Unit Tests | Description |
|-------|------------|-------------|
| `zero-id-crypto` | 59 | Cryptographic primitives, key derivation, Shamir sharing |
| `zero-id-methods` | 35 | Authentication methods, OAuth/OIDC, MFA, wallet signing |
| `zero-id-integrations` | 24 | Webhooks, SSE events, external service integration |
| `zero-id-sessions` | 21 | JWT tokens, session lifecycle, introspection |
| `zero-id-policy` | 16 | Policy engine, rate limiting, authorization rules |
| `zero-id-storage` | 9 | RocksDB operations, column families |
| `zero-id-identity-core` | 5 | Identity and machine key management |
| `zero-id-server` | 4 | API handlers, request context |
| **Total** | **173** | |

**Integration Tests:** 1 end-to-end test (requires running server)

```bash
# Generate coverage report (requires cargo-llvm-cov)
cargo llvm-cov --workspace --html
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

### Namespace Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/v1/namespaces` | POST | Create new namespace |
| `/v1/namespaces` | GET | List namespaces for authenticated identity |
| `/v1/namespaces/:id` | GET | Get namespace details |
| `/v1/namespaces/:id` | PATCH | Update namespace (owner only) |
| `/v1/namespaces/:id/deactivate` | POST | Deactivate namespace (owner only) |
| `/v1/namespaces/:id/reactivate` | POST | Reactivate namespace (owner only) |
| `/v1/namespaces/:id` | DELETE | Delete namespace (owner only, must be empty) |
| `/v1/namespaces/:id/members` | GET | List namespace members |
| `/v1/namespaces/:id/members` | POST | Add member (owner/admin) |
| `/v1/namespaces/:id/members/:identity_id` | PATCH | Update member role (owner/admin) |
| `/v1/namespaces/:id/members/:identity_id` | DELETE | Remove member (owner/admin) |

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

### Classical Cryptography (Default)

| Operation | Algorithm | Standard |
|-----------|-----------|----------|
| Signatures | Ed25519 | RFC 8032 |
| Key Exchange | X25519 | RFC 7748 |
| Encryption | XChaCha20-Poly1305 | RFC 8439 |
| Key Derivation | HKDF-SHA256 | RFC 5869 |
| Password Hashing | Argon2id (64MB, 3 iterations) | RFC 9106 |
| Non-password Hashing | BLAKE3 | - |
| MFA | TOTP (SHA-1, 6 digits, 30s) | RFC 6238 |

### Post-Quantum Cryptography

zero-id supports PQ-Hybrid key derivation with ML-DSA-65 and ML-KEM-768 always available. Machine keys can include post-quantum keys alongside classical keys for defense against future quantum computers.

| Operation | Algorithm | Standard | Key/Signature Size |
|-----------|-----------|----------|-------------------|
| PQ Signatures | ML-DSA-65 | FIPS 204 | 1,952 B / 3,309 B |
| PQ Key Encapsulation | ML-KEM-768 | FIPS 203 | 1,184 B / 1,088 B |

#### Key Schemes

Machine keys support two schemes:

- **Classical** (default): Ed25519 + X25519 only. OpenMLS compatible, smaller keys.
- **PqHybrid**: Classical keys plus ML-DSA-65 + ML-KEM-768. Provides post-quantum protection while maintaining backward compatibility.

```rust
use zero_id_crypto::{derive_machine_keypair_with_scheme, KeyScheme, MachineKeyCapabilities};

// Derive machine keys with post-quantum protection
let keypair = derive_machine_keypair_with_scheme(
    &neural_key,
    &identity_id,
    &machine_id,
    epoch,
    MachineKeyCapabilities::FULL_DEVICE,
    KeyScheme::PqHybrid,
)?;

// Access PQ keys
if let Some(pq_sign_pk) = keypair.pq_signing_public_key() {
    // 1,952-byte ML-DSA-65 public key
}
if let Some(pq_enc_pk) = keypair.pq_encryption_public_key() {
    // 1,184-byte ML-KEM-768 public key
}
```

See [Quantum Considerations](docs/encryption/quantum.md) for migration strategy and threat analysis.

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

## Security Auditing

**This software is in alpha and has not undergone professional security audits.** We do not guarantee the security of this system. While we have designed zero-id with security as a primary concern and follow cryptographic best practices, unaudited software may contain vulnerabilities.

Users and developers should:

- Evaluate the system carefully before using it in production environments
- Consider the alpha status when making decisions about sensitive deployments
- Wait for further hardening and audit completion if your threat model requires verified security

Our intention is to pursue multiple independent security audits as zero-id matures. This section will be updated with audit reports, findings, and remediations as they become available.

## Integrating with Your Application

### Getting Started

You can integrate zero-id into your application by either using the hosted service at **https://auth.zero.tech** or running your own server.

**Option 1: Use the hosted service**

Point your application to the Cypher-managed server:

```rust
const AUTH_SERVER: &str = "https://auth.zero.tech";
```

**Option 2: Self-host**

Run your own zero-id server (see [Running the Server](#running-the-server)) and point to your instance.

### Required Dependencies

Add these to your `Cargo.toml` for Rust applications:

```toml
[dependencies]
reqwest = { version = "0.12", features = ["json"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
jsonwebtoken = "9.0"     # For local JWT validation
tokio = { version = "1.0", features = ["rt-multi-thread", "macros"] }
```

For client-side cryptographic operations (identity creation, machine enrollment):

```toml
[dependencies]
zero-id-crypto = { git = "https://github.com/cypher-agi/zero-id" }
```

### SDK Roadmap

We intend to provide:

- **Formal OpenAPI Specification** - Machine-readable API definition for code generation
- **TypeScript SDK** - First-class support for Node.js and browser applications
- **Additional language SDKs** - Based on community demand

Until SDKs are available, integrate via the REST API as shown below.

### Token Introspection

The simplest integration method - validate tokens by calling the introspection endpoint:

```rust
let response = client
    .post("http://127.0.0.1:9999/v1/auth/introspect")
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
