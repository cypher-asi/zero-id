# Zero-ID Specification v0.1.1

This directory contains the comprehensive specification for Zero-ID v0.1.1, a cryptographic identity and authentication system built on neural keys and machine-based authentication.

## Document Index

The specifications are organized by dependency order, starting with the most fundamental crates.

| # | Document | Crate | Description |
|---|----------|-------|-------------|
| 00 | [00-system-overview.md](./00-system-overview.md) | — | Architecture, dependency graph, security model |
| 01 | [01-crypto.md](./01-crypto.md) | `zid-crypto` | Cryptographic primitives: key derivation, encryption, signatures, Shamir, DID |
| 02 | [02-storage.md](./02-storage.md) | `zid-storage` | Storage abstraction: traits, 33 column families, batch operations |
| 03 | [03-policy.md](./03-policy.md) | `zid-policy` | Policy engine: rate limiting, reputation, authorization decisions |
| 04 | [04-identity-core.md](./04-identity-core.md) | `zid-identity-core` | Identity management: identities, machines, namespaces, ceremonies |
| 05 | [05-sessions.md](./05-sessions.md) | `zid-sessions` | Session management: JWT issuance, refresh tokens, introspection |
| 06 | [06-integrations.md](./06-integrations.md) | `zid-integrations` | External integrations: mTLS auth, SSE streaming, webhooks |
| 07 | [07-methods.md](./07-methods.md) | `zid-methods` | Authentication methods: machine, email, OAuth, wallet, MFA |
| 08 | [08-server.md](./08-server.md) | `zid-server` | HTTP API server: endpoints, middleware, request handling |
| 09 | [09-client.md](./09-client.md) | `zid-client` | CLI client: commands, local storage, user workflows |
| 10 | [10-crypto-primitives.md](./10-crypto-primitives.md) | — | Cryptographic primitives: algorithms, binary formats, constants |

## Dependency Graph

```
┌─────────────────────────────────────────────────────────────────┐
│                      Application Layer                          │
│         zid-server    zid-methods    zid-client                 │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                        Domain Layer                             │
│    zid-identity-core   zid-sessions   zid-policy                │
│    zid-integrations                                             │
└───────────────────────────┬─────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                         Core Layer                              │
│                  zid-crypto    zid-storage                      │
└─────────────────────────────────────────────────────────────────┘
```

| Crate | Layer | Dependencies |
|-------|-------|--------------|
| `zid-crypto` | Core | (none) |
| `zid-storage` | Core | (none) |
| `zid-policy` | Domain | zid-storage |
| `zid-integrations` | Domain | zid-storage |
| `zid-sessions` | Domain | zid-crypto, zid-storage |
| `zid-identity-core` | Domain | zid-crypto, zid-storage, zid-policy |
| `zid-client` | Application | zid-crypto |
| `zid-methods` | Application | zid-crypto, zid-identity-core, zid-sessions, zid-policy |
| `zid-server` | Application | zid-methods, zid-identity-core, zid-sessions, zid-integrations, zid-policy, zid-storage |

## What's New in v0.1.1

### Identity Tiers

Zero-ID now supports two identity tiers:

| Tier | Description | Use Case |
|------|-------------|----------|
| **Managed** | Server-derived ISK from service master key | OAuth, email, wallet signup |
| **Self-Sovereign** | Client-side Neural Key with Shamir backup | Maximum security |

Managed identities can be upgraded to self-sovereign through an upgrade ceremony.

### DID Support

Identities now have Decentralized Identifiers in `did:key` format:

```
did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
```

### Post-Quantum Hybrid Keys

Machine keys can now use PQ-hybrid mode with:
- **ML-DSA-65** (NIST FIPS 204) for signing
- **ML-KEM-768** (NIST FIPS 203) for key encapsulation

### Auth Links

New storage schema for unified credential tracking across all auth methods:
- `auth_links` - Method links per identity
- `auth_links_by_method` - Method-to-identity lookup
- `primary_auth_method` - Primary auth method per identity

### 33 Column Families

Updated from 29 to 33 column families with new auth link tables.

## Canonical Specification Structure

Each crate specification follows this standardized structure:

### 1. Overview
- Purpose and responsibilities of the crate
- Position in the dependency graph
- Key design decisions

### 2. Public Interface
- Traits with complete method signatures
- Types (structs, enums) with field definitions
- Error types and error handling patterns

### 3. State Machines
- Entity state diagrams (using Mermaid `stateDiagram-v2`)
- Valid state transitions with triggers
- Invariants that must be maintained

### 4. Control Flow
- Key operation flows (using Mermaid `sequenceDiagram`)
- Decision points and branching logic
- Error handling and recovery paths

### 5. Data Structures
- Storage schemas (column families, key formats)
- Binary message formats with byte layouts
- Serialization formats

### 6. Security Considerations
- Cryptographic requirements and guarantees
- Input validation rules
- Threat model and mitigations

### 7. Dependencies
- Internal crate dependencies
- External library dependencies with versions

## Reading Order

For newcomers to the codebase, we recommend this reading order:

1. **[00-system-overview.md](./00-system-overview.md)** — Start here for the big picture
2. **[10-crypto-primitives.md](./10-crypto-primitives.md)** — Understand the cryptographic foundations
3. **[01-crypto.md](./01-crypto.md)** — Deep dive into the crypto crate
4. **[04-identity-core.md](./04-identity-core.md)** — Core identity concepts
5. **[07-methods.md](./07-methods.md)** — Authentication flows
6. **[05-sessions.md](./05-sessions.md)** — Session and token management
7. **[08-server.md](./08-server.md)** — API reference

For those focused on specific areas:

- **Storage implementers**: [02-storage.md](./02-storage.md)
- **Policy configuration**: [03-policy.md](./03-policy.md)
- **Integration developers**: [06-integrations.md](./06-integrations.md)
- **CLI users**: [09-client.md](./09-client.md)

## Terminology

| Term | Definition |
|------|------------|
| **Neural Key** | 32-byte root secret from which all identity keys are derived |
| **Identity** | A unique entity in the system, identified by its signing public key |
| **Machine** | A device/client authorized to act on behalf of an identity |
| **ISK** | Identity Signing Key — Ed25519 keypair derived from Neural Key |
| **MPK** | Machine Public Key — The public portion of a machine's signing key |
| **Namespace** | A logical grouping for access control and policy application |
| **Epoch** | Version counter for key rotation (starts at 0) |
| **DID** | Decentralized Identifier in `did:key` format |
| **Tier** | Identity type: Managed or Self-Sovereign |
| **PQ-Hybrid** | Post-quantum hybrid key scheme (Classical + ML-DSA + ML-KEM) |

## Conventions

### Diagrams

- **Dependency graphs**: ASCII art for universal rendering
- **State machines**: [Mermaid](https://mermaid.js.org/) `stateDiagram-v2`
- **Sequence diagrams**: Mermaid `sequenceDiagram`

### Code Examples

- Rust code examples are provided for all public interfaces
- Examples are self-contained and can be verified against the implementation
- Error handling is shown explicitly

### Binary Formats

- All multi-byte integers use **big-endian** (network byte order)
- UUIDs are serialized as 16 bytes
- Timestamps are Unix seconds as u64

## Version History

| Version | Date | Description |
|---------|------|-------------|
| 0.1.0 | 2026-01 | Initial specification |
| 0.1.1 | 2026-02 | Added identity tiers, DID support, PQ-hybrid keys, auth links |

## Contributing

When updating specifications:

1. Follow the canonical structure outlined above
2. Include Mermaid diagrams for complex flows
3. Provide concrete examples with actual byte sizes
4. Update this README if adding new documents
5. Increment version numbers for breaking changes
