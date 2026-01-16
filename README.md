# zero-auth

Cryptographic identity and authentication service with client-controlled roots.

## Overview

zero-auth is a modular authentication system that provides:

- **Client-Controlled Cryptography**: Root keys (Neural Key) never leave client devices
- **Per-Device Operations**: Daily operations use Machine Keys, not root material
- **Threshold Recovery**: 3-of-5 Shamir Secret Sharing for account recovery
- **Protocol Agnostic**: Supports multiple authentication methods
- **Zero-Trust Server**: Server cannot decrypt, sign, or impersonate without client participation

## Architecture

The system is composed of modular crates:

### Core Components

- **zero-auth-crypto**: Cryptographic primitives (Ed25519, X25519, XChaCha20-Poly1305, HKDF)
- **zero-auth-storage**: RocksDB abstraction layer with column families
- **zero-auth-policy**: Policy engine for authorization and rate limiting
- **zero-auth-identity-core**: Identity and Machine Key management
- **zero-auth-auth-methods**: Authentication methods (Machine Key, Email, OAuth, Wallet, MFA)
- **zero-auth-sessions**: Session and JWT token management
- **zero-auth-integrations**: Event streaming and webhooks
- **zero-auth-server**: HTTP API server (Axum)
- **test-client**: Utility for generating cryptographically valid test data

## Implementation Status

### Completed

- Workspace structure and build configuration
- Cryptographic primitives with comprehensive test coverage
- Storage layer with RocksDB and 18 column families
- Policy engine with rate limiting
- Identity Core subsystem:
  - Identity creation and lifecycle management
  - Machine Key enrollment and revocation
  - Neural Key rotation ceremonies
  - Recovery ceremonies with approval signatures
  - Namespace management
- Authentication Methods subsystem:
  - Machine Key challenge-response authentication
  - Email + password authentication with Argon2id
  - OAuth/OIDC integration (Google, X/Twitter, Epic Games)
  - EVM wallet signature verification (SECP256k1, EIP-191)
  - MFA (TOTP) with backup codes
  - Challenge system with canonical encoding and replay protection
- Sessions & Tokens subsystem:
  - JWT issuance with EdDSA (Ed25519) signing
  - Refresh token management with rotation and reuse detection
  - Comprehensive token revocation (per-session, per-identity, token-family)
  - Token introspection endpoint
  - JWKS endpoint for public key distribution
  - JWT signing key rotation with overlap windows
- HTTP Server (Axum):
  - REST API endpoints for all subsystems
  - Request validation and error handling
  - Authentication middleware with JWT validation
  - Logging and tracing with structured output
  - CORS configuration

### In Progress

- Integrations & Events subsystem (partial implementation):
  - Service registration
  - Event streaming (SSE)
  - Webhook delivery system needs completion

### Testing

- 125+ tests passing across all crates
- Unit tests for cryptographic operations
- Integration tests for core workflows
- Property-based testing for key derivation

## Quick Start

### Prerequisites

- Rust 1.75.0 or later
- OpenSSL development libraries (for cryptographic operations)

### Building

```bash
# Build all crates
cargo build --workspace

# Run tests
cargo test --workspace

# Check formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

### Running the Server

The server requires a service master key for JWT signing and encryption operations.

```bash
# Generate a random service master key (64 hex characters = 32 bytes)
# On Unix/Linux/macOS:
export SERVICE_MASTER_KEY=$(openssl rand -hex 32)

# On Windows PowerShell:
$env:SERVICE_MASTER_KEY = -join ((1..64) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })

# Run the server
cargo run -p zero-auth-server
```

The server will start on `http://127.0.0.1:8080` by default.

### Configuration

Configuration is done via environment variables:

- `SERVICE_MASTER_KEY` (required): 64-character hex string (32 bytes) for cryptographic operations
- `BIND_ADDRESS` (optional): Server bind address, default `127.0.0.1:8080`
- `DATABASE_PATH` (optional): Path to RocksDB database, default `./data/zero-auth.db`
- `JWT_ISSUER` (optional): JWT issuer claim, default `https://zero-auth.cypher.io`
- `JWT_AUDIENCE` (optional): JWT audience claim, default `zero-vault`
- `ACCESS_TOKEN_EXPIRY_SECONDS` (optional): Access token lifetime, default `900` (15 minutes)
- `REFRESH_TOKEN_EXPIRY_SECONDS` (optional): Refresh token lifetime, default `2592000` (30 days)

### Testing the API

Use the test client to generate valid cryptographic test data:

```bash
cargo run -p test-client
```

This generates:
- A random Neural Key (root secret)
- Derived Ed25519 and X25519 key pairs
- Properly signed authorization messages
- Complete JSON request for identity creation

The output includes ready-to-use PowerShell or curl commands for testing the API.

## API Endpoints

### Health & Status

- `GET /health` - Health check
- `GET /ready` - Readiness check

### Identity Management

- `POST /v1/identity` - Create new identity
- `GET /v1/identity/:identity_id` - Get identity details
- `POST /v1/identity/freeze` - Freeze identity
- `POST /v1/identity/unfreeze` - Unfreeze identity
- `POST /v1/identity/recovery` - Perform recovery ceremony
- `POST /v1/identity/rotation` - Rotate Neural Key

### Machine Key Management

- `POST /v1/machines/enroll` - Enroll new device
- `GET /v1/machines` - List enrolled devices
- `DELETE /v1/machines/:machine_id` - Revoke device access

### Authentication

- `GET /v1/auth/challenge` - Get authentication challenge
- `POST /v1/auth/login/machine` - Login with machine key
- `POST /v1/auth/login/email` - Login with email/password
- `POST /v1/auth/login/wallet` - Login with crypto wallet
- `GET /v1/auth/oauth/:provider` - Initiate OAuth flow
- `POST /v1/auth/oauth/:provider/callback` - Complete OAuth flow

### Multi-Factor Authentication

- `POST /v1/mfa/setup` - Setup TOTP MFA
- `DELETE /v1/mfa` - Disable MFA

### Session Management

- `POST /v1/auth/refresh` - Refresh access token
- `POST /v1/session/revoke` - Revoke current session
- `POST /v1/session/revoke-all` - Revoke all sessions
- `POST /v1/auth/introspect` - Validate and inspect token
- `GET /.well-known/jwks.json` - JWT public keys (JWKS)

### Integrations

- `POST /v1/integrations/register` - Register external service
- `GET /v1/events/stream` - Server-Sent Events stream

## Cryptographic Standards

All cryptographic operations follow established standards:

- **Signatures**: Ed25519 (RFC 8032) for signing and verification
- **Key Exchange**: X25519 (RFC 7748) for Diffie-Hellman
- **Encryption**: XChaCha20-Poly1305 (RFC 8439) for AEAD encryption
- **Key Derivation**: HKDF-SHA256 (RFC 5869) with domain separation
- **Password Hashing**: Argon2id with 64MB memory, 3 iterations
- **Hashing**: BLAKE3 for non-password hashing (backups, challenges)
- **MFA**: TOTP (RFC 6238) with SHA-1, 6-digit codes, 30-second windows

## Security Properties

- **Client-Controlled Keys**: Root Neural Key never leaves client devices
- **Key Derivation**: All keys derived deterministically from Neural Key using HKDF
- **Zeroization**: All sensitive material is zeroized after use
- **No Unsafe Code**: Entire codebase is `#![forbid(unsafe_code)]`
- **Canonical Encoding**: All signed messages use canonical binary format
- **Domain Separation**: All key derivations use unique domain strings
- **Rate Limiting**: Built-in rate limiting per identity and operation
- **Token Security**: JWT tokens with EdDSA signatures, short-lived access tokens
- **Revocation**: Comprehensive revocation at session, identity, and epoch levels
- **MFA**: TOTP support for high-risk operations with backup codes

## Project Status

**Current Version**: 0.1.0 (Alpha)  
**Implementation**: Approximately 80% complete  
**Lines of Code**: ~18,000 LOC across 75 files  
**Test Coverage**: 125+ tests passing  

The core authentication and identity management functionality is complete and functional. The system can:
- Create and manage cryptographic identities
- Enroll and manage multiple devices per identity
- Authenticate using multiple methods (machine key, email, OAuth, wallet)
- Issue and validate JWT tokens
- Manage sessions with refresh token rotation
- Enforce rate limits and policies

Remaining work primarily involves completing the integrations/events subsystem for webhook delivery and advanced event streaming features.

## Contributing

This project uses standard Rust development practices:

1. Format code: `cargo fmt --all`
2. Check lints: `cargo clippy --all-targets --all-features -- -D warnings`
3. Run tests: `cargo test --workspace`
4. Update documentation as needed

## License

MIT OR Apache-2.0
