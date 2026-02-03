# Cryptographic Mechanisms Comparison

A comprehensive analysis of signature schemes, cryptographic primitives, and encryption strategies across Zero-Auth, blockchain platforms (Bitcoin, Ethereum, Solana), and messaging applications (Signal, Telegram).

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Signature Schemes](#signature-schemes)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Architecture and Design Philosophy](#architecture-and-design-philosophy)
5. [Security Properties](#security-properties)
6. [Performance Metrics](#performance-metrics)
7. [Post-Quantum Readiness](#post-quantum-readiness)
8. [References](#references)

---

## Executive Summary

This document compares cryptographic mechanisms across three fundamentally different domains:

**Zero-Auth** (identity and authentication system) prioritizes:
- Cryptographic identity ownership via client-generated Neural Keys
- Hierarchical deterministic key derivation with domain separation
- Zero-knowledge of master secrets (Neural Key never leaves client)
- Secure key recovery via 3-of-5 Shamir Secret Sharing
- Modern authenticated encryption (XChaCha20-Poly1305)
- **Post-quantum security via PQ-Hybrid mode (ML-DSA-65 + ML-KEM-768)**

**Blockchain Platforms** (Bitcoin, Ethereum, Solana) prioritize:
- Transaction integrity and non-repudiation
- Public verifiability of all operations
- Deterministic key derivation for wallet recovery
- Resistance to double-spending attacks

**Messaging Platforms** (Signal, Telegram) prioritize:
- Confidentiality of message contents
- Forward secrecy (past messages stay secure if keys are compromised)
- Post-compromise security (sessions can recover after temporary compromise)
- Deniability of communications

### Key Differentiators

| Aspect | Zero-Auth | Blockchain | Messaging |
|--------|-----------|------------|-----------|
| Primary Goal | Identity ownership & auth | Public verification | Private communication |
| Data Model | Identity-centric, server-stored | Permanent, immutable ledger | Ephemeral messages |
| Key Lifetime | Long-lived (Neural Key) + rotatable machine keys | Long-lived (years) | Short-lived (per-message/session) |
| Encryption | XChaCha20-Poly1305 AEAD | Rarely used (public data) | Always used (E2EE) |
| Forward Secrecy | Per-machine key rotation | Not applicable | Critical requirement |
| Key Recovery | 3-of-5 Shamir Secret Sharing | BIP-39 mnemonics | Device-based |
| Post-Quantum | **PQ-Hybrid (ML-DSA-65 + ML-KEM-768)** | Vulnerable | Signal only (PQXDH) |

---

## Signature Schemes

### Overview Comparison

| Platform | Primary Scheme | Curve/Parameters | Signature Size | Public Key Size | Private Key Size |
|----------|---------------|------------------|----------------|-----------------|------------------|
| **Zero-Auth** | Ed25519 + ML-DSA-65 (PQ-Hybrid) | Curve25519 + Lattice | 64B (classical) / 3,309B (PQ) | 32B (classical) / 1,952B (PQ) | 32B |
| **Zero-Auth** | X25519 + ML-KEM-768 (PQ-Hybrid) | Curve25519 + Lattice | N/A (KEM) | 32B (classical) / 1,184B (PQ) | 32B |
| Bitcoin | ECDSA + Schnorr | secp256k1 | 70-72B (ECDSA), 64B (Schnorr) | 33B (compressed) | 32B |
| Ethereum | ECDSA + BLS | secp256k1, BLS12-381 | 65B (ECDSA), 48B (BLS) | 64B (uncompressed) | 32B |
| Solana | Ed25519 | Curve25519 | 64B | 32B | 32B |
| Signal | Ed25519 + ML-KEM-1024 (PQXDH) | Curve25519 + Lattice | 64B | 32B (classical) / 1,568B (PQ) | 32B |
| Telegram | RSA-2048 + DH | 2048-bit modulus | 256B | 256B | 256B |

### Zero-Auth: PQ-Hybrid Cryptography (Classical + Post-Quantum)

Zero-Auth uses a **PQ-Hybrid approach** combining classical Curve25519 algorithms with NIST post-quantum standards. This provides defense-in-depth: security is maintained if either the classical or post-quantum algorithm remains secure.

#### Ed25519 (Signing)

- **Standard**: RFC 8032 (EdDSA)
- **Signature Size**: 64 bytes (fixed)
- **Public Key Size**: 32 bytes
- **Characteristics**:
  - **Deterministic**: No random nonce required (derived from private key + message)
  - **Fast**: Optimized for high-throughput verification
  - **Safe by default**: Resistant to implementation errors

**Usage in Zero-Auth**:
- Identity Signing Keys: Sign machine enrollments, key rotations, recovery approvals
- Machine Signing Keys: Sign authentication challenges
- JWT Signing: EdDSA-based JWT tokens

#### X25519 (Classical Key Exchange)

- **Standard**: RFC 7748
- **Public Key Size**: 32 bytes
- **Characteristics**:
  - Used for ECDH key agreement
  - Machine encryption keys enable secure key exchange
  - Always present for OpenMLS compatibility

#### ML-DSA-65 (Post-Quantum Signatures)

- **Standard**: NIST FIPS 204
- **Security Level**: NIST Level 3 (128-bit post-quantum security)
- **Signature Size**: 3,309 bytes
- **Public Key Size**: 1,952 bytes
- **Characteristics**:
  - Lattice-based (Module-LWE problem)
  - Deterministic signatures
  - Resistant to Shor's algorithm

**Usage in Zero-Auth**:
- PQ-Hybrid machine signing keys (alongside Ed25519)
- Future-proof authentication challenges
- Protection against "harvest now, decrypt later" attacks

#### ML-KEM-768 (Post-Quantum Key Encapsulation)

- **Standard**: NIST FIPS 203
- **Security Level**: NIST Level 3 (128-bit post-quantum security)
- **Public Key Size**: 1,184 bytes
- **Ciphertext Size**: 1,088 bytes
- **Shared Secret**: 32 bytes
- **Characteristics**:
  - Lattice-based (Module-LWE problem)
  - IND-CCA2 secure key encapsulation
  - Resistant to Shor's algorithm

**Usage in Zero-Auth**:
- PQ-Hybrid machine encryption keys (alongside X25519)
- Quantum-resistant key agreement
- Hybrid shared secret derivation

#### Key Derivation Hierarchy

```
NeuralKey (32 bytes, client CSPRNG)
│
├── Identity Signing Key (Ed25519)
│   HKDF("cypher:id:identity:v1" || identity_id)
│
├── Machine Keys (per device) - Classical
│   ├── Signing Key (Ed25519)
│   │   HKDF("cypher:shared:machine:sign:v1" || machine_id)
│   └── Encryption Key (X25519)
│       HKDF("cypher:shared:machine:encrypt:v1" || machine_id)
│
├── Machine Keys (per device) - Post-Quantum (PQ-Hybrid mode)
│   ├── PQ Signing Key (ML-DSA-65)
│   │   HKDF("cypher:shared:machine:pq-sign:v1" || machine_id)
│   └── PQ Encryption Key (ML-KEM-768)
│       HKDF("cypher:shared:machine:pq-kem:v1" || machine_id)
│
└── MFA KEK (for TOTP secret encryption)
    HKDF("cypher:id:mfa-kek:v1" || identity_id)
```

**Design Choice**: Zero-Auth separates signing and encryption keys using domain separation strings, preventing cross-protocol attacks while maintaining deterministic derivation from a single root secret. The versioned domain strings (`:v1`) enable graceful algorithm migration to post-quantum cryptography.

### Bitcoin: ECDSA and Schnorr on secp256k1

Bitcoin uses the **secp256k1** elliptic curve defined by the equation:

```
y² = x³ + 7 (mod p)
```

where p = 2²⁵⁶ - 2³² - 977

#### ECDSA (Legacy)

- **Standard**: Implicit in Bitcoin protocol since 2009
- **Signature Format**: DER-encoded (r, s) values, 70-72 bytes variable
- **Security Level**: ~128-bit equivalent
- **Characteristics**:
  - Requires secure random nonce (k) for each signature
  - Nonce reuse leads to private key recovery (fatal vulnerability)
  - Signatures are malleable (third parties can modify valid signatures)

#### Schnorr Signatures (BIP-340, since 2021)

- **Standard**: BIP-340 (activated in Taproot upgrade)
- **Signature Format**: Fixed 64 bytes (32B R-point + 32B s-value)
- **Improvements over ECDSA**:
  - **Linearity**: Enables native multi-signatures (MuSig2) and threshold signatures
  - **Non-malleable**: Signatures cannot be modified by third parties
  - **Batch verification**: Multiple signatures can be verified faster together
  - **Provable security**: Reduces to discrete logarithm problem under random oracle model

```
Signature = (R, s) where:
  R = k·G (nonce point)
  s = k + e·x (mod n)
  e = H(R || P || m) (challenge)
```

### Ethereum: ECDSA and BLS Signatures

#### Execution Layer (ECDSA)

Ethereum uses ECDSA on secp256k1, identical to Bitcoin's curve, but with key differences:

- **Address Derivation**: Keccak-256 hash of public key, truncated to 20 bytes
- **Signature Components**: (r, s, v) where v is the recovery identifier (27 or 28, or EIP-155 chain ID encoded)
- **Recovery Feature**: Public key can be recovered from signature + message, eliminating need to transmit public key

```
Address = Keccak256(PublicKey)[12:32]
```

#### Consensus Layer (BLS12-381)

Ethereum's Proof-of-Stake consensus uses **BLS signatures** for validator attestations:

- **Curve**: BLS12-381 (Barreto-Lynn-Scott curve with embedding degree 12)
- **Signature Size**: 48 bytes (compressed G1 point)
- **Public Key Size**: 48 bytes (compressed G1 point)
- **Key Feature**: **Signature aggregation** - unlimited signatures combine into single 48-byte signature

```
AggregateSignature = σ₁ + σ₂ + ... + σₙ (point addition)
Verification: e(AggSig, G2) = e(H(m), Σ PKᵢ)
```

**Scaling Impact**: With 500,000+ validators, BLS aggregation reduces attestation data from ~32MB to under 100KB per slot.

### Solana: Ed25519

Solana exclusively uses **Ed25519** (Edwards-curve Digital Signature Algorithm):

- **Standard**: RFC 8032
- **Curve**: Twisted Edwards curve equivalent to Curve25519
- **Signature Size**: 64 bytes (fixed)
- **Public Key Size**: 32 bytes
- **Characteristics**:
  - **Deterministic**: No random nonce required (derived from private key + message)
  - **Fast**: Optimized for high-throughput verification
  - **Safe by default**: Resistant to implementation errors

```
Signature = (R, S) where:
  R = r·B (nonce point, r = H(prefix || m))
  S = r + H(R || A || m)·a (mod l)
```

**Implementation Note**: Solana uses a native program for Ed25519 verification, consuming significantly fewer compute units than in-contract implementations.

### Signal: Curve25519 Family

Signal uses the Curve25519 family for different purposes:

| Purpose | Algorithm | Key Type |
|---------|-----------|----------|
| Identity Keys | Ed25519 | Long-term signing |
| Signed Prekeys | Ed25519 | Medium-term signing |
| Key Agreement | X25519 | Ephemeral DH exchange |

The distinction between Ed25519 (signing) and X25519 (key exchange) stems from different curve representations optimized for each operation.

### Telegram: RSA + Diffie-Hellman

Telegram's MTProto 2.0 uses legacy cryptographic primitives:

- **Server Authentication**: RSA-2048 signatures
- **Key Exchange**: 2048-bit Diffie-Hellman (finite field, not elliptic curve)
- **Signature Size**: 256 bytes (RSA-2048)

This represents significantly larger key material compared to elliptic curve alternatives, with RSA-2048 providing roughly equivalent security to a 112-bit symmetric key (compared to 128-bit for 256-bit ECC).

---

## Cryptographic Primitives

### Hash Functions

| Platform | Primary Hash | Usage | Output Size | Standard |
|----------|-------------|-------|-------------|----------|
| **Zero-Auth** | BLAKE3 | Fast hashing, key ID derivation | 256 bits | - |
| **Zero-Auth** | SHA-256 | HKDF-SHA256 key derivation | 256 bits | FIPS 180-4 |
| **Zero-Auth** | Keccak-256 | EVM wallet address verification | 256 bits | Pre-FIPS SHA-3 |
| Bitcoin | SHA-256 | Block headers, TXID, addresses | 256 bits | FIPS 180-4 |
| Bitcoin | RIPEMD-160 | Address generation (after SHA-256) | 160 bits | ISO/IEC 10118-3 |
| Bitcoin | SHA-256d | Double SHA-256 for PoW | 256 bits | - |
| Ethereum | Keccak-256 | Addresses, state roots, signatures | 256 bits | Pre-FIPS SHA-3 |
| Solana | SHA-256 | Transaction hashes, Merkle trees | 256 bits | FIPS 180-4 |
| Signal | SHA-256 | HKDF, HMAC | 256 bits | FIPS 180-4 |
| Signal | SHA-512 | Ed25519 internal | 512 bits | FIPS 180-4 |
| Telegram | SHA-256 | MTProto 2.0 key derivation | 256 bits | FIPS 180-4 |

**Note**: Ethereum's Keccak-256 is **not** identical to NIST SHA-3 (SHA3-256). Keccak-256 uses different padding, making them incompatible. Zero-Auth uses Keccak-256 specifically for EVM wallet authentication compatibility.

### Key Derivation Functions

#### Zero-Auth: HKDF-SHA256 with Domain Separation

Zero-Auth uses HKDF (RFC 5869) extensively with unique domain strings:

```
Key Generation:
  neural_key = CSPRNG(32 bytes)  // Client-generated
  
Identity Key Derivation:
  seed = HKDF-Expand(neural_key, "cypher:id:identity:v1" || identity_id, 32)
  identity_keypair = Ed25519::from_seed(seed)

Machine Key Derivation:
  machine_seed = HKDF-Expand(neural_key, "cypher:shared:machine:v1" || identity_id || machine_id || epoch, 32)
  signing_seed = HKDF-Expand(machine_seed, "cypher:shared:machine:sign:v1" || machine_id, 32)
  encrypt_seed = HKDF-Expand(machine_seed, "cypher:shared:machine:encrypt:v1" || machine_id, 32)
```

**Key Differentiator**: Unlike BIP-32, Zero-Auth uses explicit domain separation strings following the pattern `cypher:{service}:{purpose}:v{version}`, enabling versioned algorithm migration and preventing cross-protocol key reuse.

#### Bitcoin: BIP-32 Hierarchical Deterministic Wallets

```
Master Key Generation:
  seed = PBKDF2(mnemonic, "mnemonic" + passphrase, 2048, 64)
  (master_key, chain_code) = HMAC-SHA512("Bitcoin seed", seed)

Child Key Derivation:
  For normal child:   HMAC-SHA512(chain_code, public_key || index)
  For hardened child: HMAC-SHA512(chain_code, 0x00 || private_key || index)
```

#### Ethereum: Same as Bitcoin (BIP-32/39/44)

Ethereum wallets use identical derivation with different path:
- Bitcoin: `m/44'/0'/0'/0/0`
- Ethereum: `m/44'/60'/0'/0/0`

#### Signal: HKDF (RFC 5869)

Signal uses HKDF-SHA256 extensively for key derivation:

```
HKDF-Expand(prk, info, length):
  T(0) = empty
  T(i) = HMAC(prk, T(i-1) || info || i)
  return first 'length' bytes of T(1) || T(2) || ...
```

#### Telegram: Custom KDF

MTProto 2.0 derives message keys using a custom construction:

```
msg_key = SHA256(auth_key[88:120] || plaintext)[8:24]
aes_key = SHA256(msg_key || auth_key[x:x+36])[:32]
aes_iv  = SHA256(auth_key[y:y+32] || msg_key)[4:20] || SHA256(msg_key || auth_key[z:z+32])[:12]
```

### Symmetric Encryption

| Platform | Algorithm | Mode | Key Size | Nonce/IV | Tag Size |
|----------|-----------|------|----------|----------|----------|
| **Zero-Auth** | ChaCha20 | XChaCha20-Poly1305 | 256 bits | 192 bits | 128 bits |
| Signal | AES-256 | GCM | 256 bits | 96 bits | 128 bits |
| Telegram (cloud) | AES-256 | IGE | 256 bits | 256 bits | N/A (no auth) |
| Telegram (secret) | AES-256 | IGE | 256 bits | 256 bits | N/A (SHA-256 MAC) |

**Critical Differences**:
- **Zero-Auth** uses XChaCha20-Poly1305 with 192-bit nonces, providing collision resistance even with random nonce generation (birthday bound at 2^96 messages per key)
- **Signal** uses AES-GCM with 96-bit nonces, requiring careful nonce management
- **Telegram** uses AES-IGE which requires a separate MAC for authentication

### Password Hashing

| Platform | Algorithm | Memory | Iterations | Purpose |
|----------|-----------|--------|------------|---------|
| **Zero-Auth** | Argon2id | 64 MB | 3 | Password hashing, passphrase-derived KEK |
| Signal | Argon2id | 64 MB | 3 | PIN-derived keys |
| Telegram | - | - | - | No client-side password hashing |

---

## Architecture and Design Philosophy

### Zero-Auth: Identity-Centric Hierarchical Key Management

```
┌─────────────────────────────────────────────────────────────┐
│                  Zero-Auth Architecture                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Client-Side (Neural Key never leaves)                     │
│   ┌─────────────────────────────────────────────────────┐   │
│   │            Neural Key (32 bytes)                     │   │
│   │  ┌─────────────┐      ┌─────────────────────────┐   │   │
│   │  │   CSPRNG    │      │  3-of-5 Shamir Backup   │   │   │
│   │  │  Generated  │      │  (recovery shards)      │   │   │
│   │  └─────────────┘      └─────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│                           ▼                                  │
│   ┌─────────────────────────────────────────────────────┐   │
│   │         HKDF-SHA256 Domain-Separated Derivation      │   │
│   │  ┌──────────────────┐  ┌──────────────────────┐     │   │
│   │  │ Identity Signing │  │   Machine Keys       │     │   │
│   │  │ Key (Ed25519)    │  │   (Ed25519 + X25519) │     │   │
│   │  └──────────────────┘  └──────────────────────┘     │   │
│   └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│                           ▼                                  │
│   Server-Side (Public keys only)                            │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  Challenge-Response Auth    │  JWT Sessions (EdDSA)  │   │
│   │  ┌───────────────────────┐  │  ┌─────────────────┐   │   │
│   │  │ Server: nonce         │  │  │ Access tokens   │   │   │
│   │  │ Client: Ed25519 sig   │  │  │ Refresh tokens  │   │   │
│   │  │ Server: verify        │  │  │ Key rotation    │   │   │
│   │  └───────────────────────┘  │  └─────────────────┘   │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Properties**:
- Neural Key is NEVER transmitted or stored on servers
- All key derivations use unique domain separation strings
- Machine keys can be rotated without changing identity
- 3-of-5 Shamir provides recovery without single point of failure
- XChaCha20-Poly1305 AEAD for all symmetric encryption

### Bitcoin: UTXO Model with Script

```
┌─────────────────────────────────────────────────────────────┐
│                    Bitcoin Transaction                       │
├─────────────────────────────────────────────────────────────┤
│  Inputs                          │  Outputs                 │
│  ┌───────────────────────────┐   │  ┌────────────────────┐  │
│  │ Previous TXID + Index     │   │  │ Value (satoshis)   │  │
│  │ ScriptSig (signature)     │   │  │ ScriptPubKey       │  │
│  │ Witness (Segwit sigs)     │   │  │ (locking script)   │  │
│  └───────────────────────────┘   │  └────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Key Properties**:
- Signatures commit to specific transaction outputs
- No encryption (all data is public)
- Deterministic verification by all nodes

### Ethereum: Account Model with EVM

```
┌─────────────────────────────────────────────────────────────┐
│                  Ethereum Architecture                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Execution Layer (ECDSA)         Consensus Layer (BLS)     │
│   ┌─────────────────────┐        ┌─────────────────────┐    │
│   │ User Transactions   │        │ Validator Votes     │    │
│   │ - secp256k1         │        │ - BLS12-381         │    │
│   │ - 65-byte sigs      │        │ - 48-byte agg sigs  │    │
│   │ - Keccak-256        │        │ - Slot attestations │    │
│   └─────────────────────┘        └─────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Dual Signature System**:
- Users sign transactions with ECDSA (familiar, compatible with existing wallets)
- Validators sign attestations with BLS (enables aggregation for scalability)

### Solana: Parallel Processing Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Solana Transaction                         │
├─────────────────────────────────────────────────────────────┤
│  Header                                                      │
│  ├── Signature Count                                         │
│  ├── Signatures[] (Ed25519, 64 bytes each)                  │
│  └── Message                                                 │
│      ├── Account Keys[] (32 bytes each)                     │
│      └── Instructions[]                                      │
│          ├── Program ID                                      │
│          ├── Account Indices                                 │
│          └── Data (offset-based for sig verification)       │
└─────────────────────────────────────────────────────────────┘
```

**Design Choices**:
- Ed25519 chosen for deterministic signatures and fast batch verification
- Native signature verification program (not in-contract)
- Transaction size limit: 1,232 bytes (constrains multi-sig operations)

### Signal: Triple Ratchet Protocol (2025)

Signal's current architecture combines three key mechanisms:

```
┌─────────────────────────────────────────────────────────────┐
│                Signal Triple Ratchet                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              PQXDH Initial Handshake                 │    │
│  │  ┌─────────────┐         ┌─────────────────────┐    │    │
│  │  │   X25519    │    +    │    ML-KEM-1024      │    │    │
│  │  │ (classical) │         │  (post-quantum)     │    │    │
│  │  └─────────────┘         └─────────────────────┘    │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                           ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Double Ratchet (ongoing)                │    │
│  │  ┌─────────────────┐    ┌─────────────────────┐     │    │
│  │  │  DH Ratchet     │    │  Symmetric Ratchet  │     │    │
│  │  │  (X25519)       │    │  (HKDF chain)       │     │    │
│  │  └─────────────────┘    └─────────────────────┘     │    │
│  └─────────────────────────────────────────────────────┘    │
│                           │                                  │
│                           ▼                                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │         Sparse Post-Quantum Ratchet (SPQR)           │    │
│  │  ML-KEM encapsulation every N messages               │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Key Operations**:

1. **PQXDH** (Post-Quantum Extended Diffie-Hellman):
   ```
   shared_secret = HKDF(X25519_result || ML-KEM_result)
   ```

2. **Double Ratchet**:
   - DH ratchet: New X25519 keys exchanged with each message round-trip
   - Symmetric ratchet: HKDF chain derives per-message keys

3. **SPQR**: Periodic ML-KEM key encapsulation for post-quantum forward secrecy

### Telegram: MTProto 2.0

```
┌─────────────────────────────────────────────────────────────┐
│                    MTProto 2.0                               │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   Cloud Chats (Default)           Secret Chats (Optional)   │
│   ┌─────────────────────┐        ┌─────────────────────┐    │
│   │ Client ←→ Server    │        │ Client ←→ Client    │    │
│   │ encryption          │        │ E2EE                │    │
│   │                     │        │                     │    │
│   │ Keys on server      │        │ Keys only on devices│    │
│   │ Multi-device sync   │        │ Single device only  │    │
│   │ Cloud backup        │        │ No backup           │    │
│   └─────────────────────┘        └─────────────────────┘    │
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │              Key Exchange                            │   │
│   │  1. Server sends RSA-encrypted DH parameters        │   │
│   │  2. Client responds with DH public value            │   │
│   │  3. Shared auth_key (2048-bit) established          │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
│   ┌─────────────────────────────────────────────────────┐   │
│   │              Message Encryption                      │   │
│   │  msg_key = SHA256(auth_key[88:120] || plaintext)    │   │
│   │  aes_key, aes_iv = KDF(auth_key, msg_key)           │   │
│   │  ciphertext = AES-256-IGE(plaintext, aes_key, iv)   │   │
│   └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

**Critical Limitations**:
- Cloud chats: Server has decryption keys
- Secret chats: Must be manually enabled, no group support
- IGE mode: Requires separate integrity check (not AEAD)

---

## Security Properties

### Comparison Matrix

| Property | Zero-Auth | Bitcoin | Ethereum | Solana | Signal | Telegram (Cloud) | Telegram (Secret) |
|----------|-----------|---------|----------|--------|--------|------------------|-------------------|
| Confidentiality | Yes (AEAD) | N/A | N/A | N/A | Yes | Server can read | Yes |
| Integrity | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| Authentication | Yes (Ed25519 + ML-DSA-65) | Yes | Yes | Yes | Yes | Yes | Yes |
| Non-repudiation | Yes | Yes | Yes | Yes | Optional | No | No |
| Forward Secrecy | Machine key rotation | N/A | N/A | N/A | Yes | No | Limited |
| Post-Compromise Security | Via recovery ceremony | N/A | N/A | N/A | Yes | No | No |
| Deniability | No | No | No | No | Yes | No | Partial |
| Zero-Knowledge of Master Key | Yes (Neural Key) | No | No | No | No | No | No |
| Key Recovery | 3-of-5 Shamir | BIP-39 mnemonic | BIP-39 mnemonic | BIP-39 mnemonic | Device-based | No | No |
| **Post-Quantum Safe** | **Yes (PQ-Hybrid)** | No | No | No | Yes (PQXDH) | No | No |

### Forward Secrecy Analysis

**Signal**: Achieves forward secrecy through continuous key ratcheting:
- Compromising current keys reveals nothing about past messages
- Each message uses a unique derived key
- DH ratchet ensures even session keys are ephemeral

**Telegram Secret Chats**: Limited forward secrecy:
- Initial DH provides some protection
- No continuous ratcheting within a session
- Rekeying requires explicit user action

**Blockchains**: Forward secrecy is not applicable because:
- All data is intentionally public
- Historical verifiability is a feature, not a bug
- Keys are meant for long-term ownership proof

### Known Vulnerabilities and Mitigations

#### Zero-Auth PQ-Hybrid (Ed25519/X25519 + ML-DSA-65/ML-KEM-768)

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Neural Key extraction | Root key compromise reveals all derived keys | Zeroization on drop, 3-of-5 Shamir (never stored whole) |
| Memory timing attacks | Side-channel leaks in signature verification | Constant-time operations via `subtle` crate |
| Nonce reuse | Repeated nonces could leak key material | 192-bit random nonces (birthday bound at 2^96) |
| Domain separation failure | Cross-protocol key reuse | Unique domain strings per key type with versioning |
| Server compromise | Attacker gains access to stored data | Only public keys stored server-side, Neural Key client-only |
| Quantum attack (Shor's) | Future quantum computers break classical crypto | **PQ-Hybrid mode with ML-DSA-65 + ML-KEM-768** |
| PQ algorithm weakness | New attacks on lattice assumptions | Hybrid approach retains classical security as fallback |

#### Bitcoin/Ethereum ECDSA

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Nonce reuse | Reusing k in two signatures reveals private key | RFC 6979 deterministic nonces |
| Weak RNG | Poor randomness in k compromises key | Hardware RNG, deterministic derivation |
| Signature malleability | Third parties can modify (r,s) to (r,-s) | Enforce low-S values (BIP-62, EIP-2) |

#### Solana Ed25519

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Offset manipulation | Contract trusts wrong signature data | Explicit structural validation |
| Double public key | Same key used for sign/encrypt | Separate Ed25519/X25519 keys |

#### Signal Protocol

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Key server compromise | Attacker registers fake prekeys | Safety numbers verification |
| Metadata exposure | Server sees who talks to whom | Sealed sender feature |

#### Telegram MTProto 2.0

| Vulnerability | Description | Mitigation |
|--------------|-------------|------------|
| Server key access | Cloud chat keys stored on server | Use Secret Chats |
| Timing side channels | AES-IGE timing leaks | Rate limiting (theoretical) |
| Unknown key-share | Rekeying protocol flaw | Protocol updates (2021+) |

---

## Performance Metrics

### Signature Operation Benchmarks

Benchmarks on modern hardware (ARM Cortex-A76, single core):

| Algorithm | Sign (ops/sec) | Verify (ops/sec) | Relative Speed | Used By |
|-----------|---------------|------------------|----------------|---------|
| Ed25519 | ~30,775 | ~11,870 | 1.0x (baseline) | **Zero-Auth** (classical), Solana, Signal |
| ML-DSA-65 | ~3,300 | ~2,900 | ~0.11x sign, ~0.24x verify | **Zero-Auth** (PQ-Hybrid) |
| ECDSA P-256 | ~32,866 | ~10,449 | ~1.1x sign, ~0.9x verify | TLS |
| ECDSA secp256k1 | ~28,000 | ~9,500 | ~0.9x sign, ~0.8x verify | Bitcoin, Ethereum, Zero-Auth (EVM wallets) |
| Schnorr (secp256k1) | ~30,000 | ~11,000 | ~1.0x | Bitcoin (Taproot) |
| BLS12-381 | ~1,200 | ~450 | ~0.04x (but aggregates) | Ethereum (consensus) |
| RSA-2048 | ~900 | ~45,000 | ~0.03x sign, ~3.8x verify | Telegram |

### Key Encapsulation Benchmarks

| Algorithm | Keygen (ops/sec) | Encapsulate (ops/sec) | Decapsulate (ops/sec) | Used By |
|-----------|-----------------|----------------------|----------------------|---------|
| X25519 | ~40,000 | ~33,000 | ~33,000 | **Zero-Auth** (classical), Signal |
| ML-KEM-768 | ~20,000 | ~14,000 | ~17,000 | **Zero-Auth** (PQ-Hybrid), Signal |

**Key Observations**:
- **Zero-Auth** uses Ed25519 for optimal classical signing/verification performance
- **ML-DSA-65** is ~10x slower than Ed25519 but provides quantum resistance
- **ML-KEM-768** is ~2x slower than X25519 but provides quantum-safe key exchange
- PQ-Hybrid mode trades performance for future-proof security
- Ed25519 and ECDSA are comparable for individual operations
- BLS is slower per-signature but aggregation makes it efficient at scale
- RSA verification is fast but signing is extremely slow

### BLS Aggregation Efficiency

**Note**: Zero-Auth does not use BLS signatures as it doesn't require signature aggregation. Each machine key signs its own challenges individually.

For Ethereum consensus with N validators:

| Validators | Without Aggregation | With BLS Aggregation | Savings |
|------------|--------------------|--------------------|---------|
| 1,000 | 65 KB signatures | 48 bytes | 99.93% |
| 100,000 | 6.5 MB signatures | 48 bytes | 99.9993% |
| 500,000 | 32.5 MB signatures | 48 bytes | 99.99985% |

### Transaction/Authentication Throughput Impact

| Platform | Signature Scheme | Typical TPS | Signature Overhead |
|----------|-----------------|-------------|-------------------|
| **Zero-Auth** | Ed25519 + ML-DSA-65 (PQ-Hybrid) | N/A (auth system) | 64B (classical) or 3,373B (hybrid) per auth |
| Bitcoin | ECDSA/Schnorr | 7 | ~50% of transaction size |
| Ethereum | ECDSA | 15-30 | ~40% of transaction size |
| Solana | Ed25519 | 65,000 | ~5% due to native verification |

### Message Encryption Overhead

| Platform | Encryption | Key Exchange | Per-Message Overhead |
|----------|------------|--------------|---------------------|
| **Zero-Auth** | XChaCha20-Poly1305 | HKDF-derived keys | 40 bytes (24B nonce + 16B tag) |
| Signal | AES-256-GCM | PQXDH (~3 KB initial) | ~50 bytes (MAC + headers) |
| Telegram | AES-256-IGE | DH (~512 bytes) | ~32 bytes (msg_key + padding) |

---

## Post-Quantum Readiness

### Threat Model

Quantum computers running **Shor's algorithm** can efficiently solve:
- Integer factorization (breaks RSA)
- Discrete logarithm problem (breaks DH, DSA)
- Elliptic curve discrete logarithm (breaks ECDSA, Ed25519, X25519)

**Grover's algorithm** provides quadratic speedup for:
- Symmetric key search (AES-256 → ~AES-128 security)
- Hash collisions (SHA-256 → ~SHA-128 security)

### Platform Status (as of February 2026)

| Platform | Current Status | Implementation | Timeline |
|----------|---------------|----------------|----------|
| **Zero-Auth** | **Production Ready** | ML-DSA-65 + ML-KEM-768 (FIPS 203/204) | **Deployed** |
| **Signal** | **Production Ready** | PQXDH + Triple Ratchet with ML-KEM-1024 | Deployed (2024) |
| Bitcoin | Vulnerable (ECDSA/Schnorr) | Research: SPHINCS+, XMSS hash-based signatures | No concrete timeline |
| Ethereum | Vulnerable (ECDSA/BLS) | Research: ML-DSA for consensus, account abstraction for users | Long-term research |
| Solana | Vulnerable (Ed25519) | Research: NIST PQC standards (ML-DSA, SLH-DSA) | No concrete timeline |
| Telegram | Vulnerable (RSA/DH) | No announced roadmap | Unknown |

### Zero-Auth's Post-Quantum Implementation

Zero-Auth is **production-ready** with full PQ-Hybrid cryptography. Unlike blockchain platforms constrained by on-chain storage costs, Zero-Auth can adopt larger post-quantum keys without protocol-level barriers.

**Key Schemes** (always available, no feature flag required):
```rust
pub enum KeyScheme {
    Classical,  // Ed25519 + X25519 only (default)
    PqHybrid,   // Classical + ML-DSA-65 + ML-KEM-768
}
```

**Domain Separation**:
```
Classical signing:     "cypher:shared:machine:sign:v1"     → Ed25519
Classical encryption:  "cypher:shared:machine:encrypt:v1"  → X25519
PQ signing:           "cypher:shared:machine:pq-sign:v1"  → ML-DSA-65
PQ KEM:               "cypher:shared:machine:pq-kem:v1"   → ML-KEM-768
```

**Implementation Status**:

| Algorithm | Status | Notes |
|-----------|--------|-------|
| ML-DSA-65 (Dilithium-3) | ✅ Implemented | NIST FIPS 204, always available |
| ML-KEM-768 (Kyber-768) | ✅ Implemented | NIST FIPS 203, always available |
| BLAKE3 | No change needed | Quantum-resistant hash |

**PQ-Hybrid Key Derivation**:
- Classical keys (Ed25519 + X25519) always present for OpenMLS compatibility
- PQ keys derived alongside classical keys from same machine seed
- Deterministic derivation from Neural Key preserved
- Uses `fips203` and `fips204` crates for NIST-compliant implementations

### Signal's Post-Quantum Implementation

Signal was the first major messaging platform with deployed post-quantum cryptography:

**PQXDH Protocol**:
```
Classical: X25519 key agreement
    +
Post-Quantum: ML-KEM-1024 (Kyber) encapsulation
    =
Hybrid shared secret (secure if either algorithm holds)
```

**Triple Ratchet Additions**:
- Sparse Post-Quantum Ratchet (SPQR) using Katana (optimized Kyber variant)
- ~37% bandwidth reduction compared to naive ML-KEM integration
- Maintains classical security even if PQ assumptions fail

### NIST Post-Quantum Standards

Standardized algorithms for future blockchain/messaging migration:

| Algorithm | Type | Use Case | Key Size | Signature Size |
|-----------|------|----------|----------|----------------|
| ML-KEM (Kyber) | KEM | Key exchange | 1,568 B (ML-KEM-1024) | N/A |
| ML-DSA (Dilithium) | Signature | Transaction signing | 2,592 B | 4,627 B |
| SLH-DSA (SPHINCS+) | Signature | Hash-based, stateless | 64 B | 49,856 B |

**Challenge for Blockchains**: Post-quantum signatures are 50-100x larger than current ECDSA/Ed25519 signatures, requiring significant protocol changes.

**Zero-Auth Advantage**: As an identity system (not a public ledger), Zero-Auth can migrate to PQ algorithms without the on-chain storage constraints that blockchains face. The domain-versioned key derivation allows graceful hybrid transitions.

---

## References

### Zero-Auth Specifications

- [**zid-crypto Specification v0.1**](../spec/v0.1/01-crypto.md): Cryptographic primitives and key derivation hierarchy
- [**Cryptographic Primitives Specification v0.1**](../spec/v0.1/11-crypto-primitives.md): Algorithms, binary formats, and domain separation

### Standards and Specifications

- [**RFC 8032**](https://datatracker.ietf.org/doc/html/rfc8032): Edwards-Curve Digital Signature Algorithm (EdDSA)
- [**RFC 7748**](https://datatracker.ietf.org/doc/html/rfc7748): Elliptic Curves for Security (X25519, X448)
- [**RFC 8439**](https://datatracker.ietf.org/doc/html/rfc8439): ChaCha20 and Poly1305 for IETF Protocols
- [**RFC 5869**](https://datatracker.ietf.org/doc/html/rfc5869): HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- [**RFC 9106**](https://datatracker.ietf.org/doc/html/rfc9106): Argon2 Memory-Hard Function
- [**RFC 6238**](https://datatracker.ietf.org/doc/html/rfc6238): TOTP: Time-Based One-Time Password Algorithm
- [**FIPS 180-4**](https://csrc.nist.gov/publications/detail/fips/180/4/final): Secure Hash Standard (SHA-2)
- [**FIPS 186-5**](https://csrc.nist.gov/publications/detail/fips/186/5/final): Digital Signature Standard (DSS)
- [**FIPS 203**](https://csrc.nist.gov/publications/detail/fips/203/final): Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)
- [**FIPS 204**](https://csrc.nist.gov/publications/detail/fips/204/final): Module-Lattice-Based Digital Signature (ML-DSA)

### Bitcoin Improvement Proposals

- [**BIP-32**](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki): Hierarchical Deterministic Wallets
- [**BIP-39**](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): Mnemonic code for generating deterministic keys
- [**BIP-44**](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki): Multi-Account Hierarchy for Deterministic Wallets
- [**BIP-340**](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki): Schnorr Signatures for secp256k1

### Ethereum Specifications

- [**Ethereum Yellow Paper**](https://ethereum.github.io/yellowpaper/paper.pdf): Formal specification of the Ethereum protocol
- [**EIP-2**](https://eips.ethereum.org/EIPS/eip-2): Homestead Hard-fork Changes (signature malleability fix)
- [**EIP-155**](https://eips.ethereum.org/EIPS/eip-155): Simple replay attack protection (chain ID in signatures)
- [**Ethereum Consensus Specs**](https://github.com/ethereum/consensus-specs): BLS12-381 signature aggregation

### Protocol Documentation

- [**Signal Protocol Specifications**](https://signal.org/docs/): X3DH, Double Ratchet, PQXDH
- [**MTProto 2.0**](https://core.telegram.org/mtproto): Telegram's transport protocol documentation

### Academic Research

- Albrecht et al. (2022): ["Four Attacks and a Proof for Telegram"](https://link.springer.com/article/10.1007/s00145-022-09437-7) - Journal of Cryptology
- Cohn-Gordon et al. (2020): ["A Formal Security Analysis of the Signal Messaging Protocol"](https://eprint.iacr.org/2016/1013.pdf) - Journal of Cryptology
- Stebila & Mosca (2016): ["Post-quantum Key Exchange for the Internet"](https://eprint.iacr.org/2015/1092.pdf) - Selected Areas in Cryptography

### Security Analyses

- Cryptography Engineering Blog (2024): ["Is Telegram really an encrypted messaging app?"](https://blog.cryptographyengineering.com/2024/08/25/telegram-is-not-really-an-encrypted-messaging-app/)
- Helius Blog (2025): ["What Would Solana Need to Change to Become Quantum Resistant?"](https://www.helius.dev/blog/what-would-solana-need-to-change-to-become-quantum-resistant)
- Cantina Security (2025): ["Signature Verification Risks in Solana"](https://cantina.xyz/blog/signature-verification-risks-in-solana)
