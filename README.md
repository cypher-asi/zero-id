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
- **zero-auth-storage**: RocksDB abstraction layer
- **zero-auth-policy**: Policy engine for authorization and rate limiting
- **zero-auth-identity-core**: Identity and Machine Key management
- **zero-auth-auth-methods**: Authentication methods (Machine Key, Email, OAuth, Wallet)
- **zero-auth-sessions**: Session and JWT token management
- **zero-auth-integrations**: Event streaming and webhooks
- **zero-auth-server**: HTTP API server (Axum)

## Implementation Status

### ✅ Completed

- Workspace structure and build configuration
- Cryptographic primitives with test coverage
- Storage layer with RocksDB
- Policy engine with basic evaluation
- Identity Core subsystem with:
  - Identity creation and lifecycle
  - Machine Key enrollment and revocation
  - Neural Key rotation ceremonies
  - Recovery ceremonies
  - Namespace management

### 🚧 Remaining Work

The following subsystems require implementation:

1. **Auth Methods Subsystem**
   - Machine Key challenge-response
   - Email + password authentication
   - OAuth provider integration
   - EVM wallet signatures
   - MFA (TOTP) setup and verification

2. **Sessions & Tokens Subsystem**
   - JWT issuance with EdDSA signing
   - Refresh token management
   - Token revocation
   - JWKS endpoint

3. **Integrations & Events Subsystem**
   - mTLS service authentication
   - Server-Sent Events (SSE) streaming
   - Webhook delivery with retry
   - Event filtering by namespace

4. **HTTP Server (Axum)**
   - REST API endpoints
   - Request validation
   - Error handling
   - Middleware (auth, rate limiting, logging)

5. **Comprehensive Testing**
   - Integration tests between subsystems
   - End-to-end authentication flows
   - Security property verification
   - Property-based testing

## Building

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

## Documentation

- **Specification**: See `docs/spec/zero-auth/` for detailed specifications
- **Requirements**: See `docs/requirements/` for system requirements
- **Architecture**: See `docs/spec/zero-auth/02-architecture.md`
- **Cryptographic Standards**: See `docs/requirements/cryptographic-constants.md`

## Security

- All cryptographic operations follow RFC standards
- Sensitive data is zeroized after use
- No unsafe Rust code
- Comprehensive error handling with thiserror
- Rate limiting and reputation scoring
- MFA support for high-risk operations

## License

MIT OR Apache-2.0
