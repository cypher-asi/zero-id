//! Cryptographic constants and domain separation strings.
//!
//! This module implements the specifications from:
//! `docs/requirements/cryptographic-constants.md`
//!
//! All constants are normative and MUST NOT be changed without updating the spec.

/// Size of Neural Key in bytes (256 bits)
pub const NEURAL_KEY_SIZE: usize = 32;

/// Size of public keys (Ed25519 and X25519) in bytes
pub const PUBLIC_KEY_SIZE: usize = 32;

/// Size of private keys (Ed25519 and X25519) in bytes
pub const PRIVATE_KEY_SIZE: usize = 32;

/// Size of Ed25519 signatures in bytes
pub const SIGNATURE_SIZE: usize = 64;

/// Size of XChaCha20-Poly1305 nonces in bytes (192 bits)
pub const NONCE_SIZE: usize = 24;

/// Size of XChaCha20-Poly1305 authentication tags in bytes (128 bits)
pub const TAG_SIZE: usize = 16;

/// Size of HKDF output (SHA-256) in bytes
pub const HKDF_OUTPUT_SIZE: usize = 32;

/// Size of salt for Argon2id
pub const ARGON2_SALT_SIZE: usize = 32;

/// Size of random challenge nonces in bytes
pub const CHALLENGE_NONCE_SIZE: usize = 32;

/// Challenge expiry time in seconds (60 seconds)
pub const CHALLENGE_EXPIRY_SECONDS: u64 = 60;

/// Session token expiry time in seconds (15 minutes)
pub const SESSION_TOKEN_EXPIRY_SECONDS: u64 = 900;

/// Refresh token expiry time in seconds (30 days)
pub const REFRESH_TOKEN_EXPIRY_SECONDS: u64 = 2_592_000;

/// Approval ceremony expiry time in seconds (15 minutes)
pub const APPROVAL_EXPIRY_SECONDS: u64 = 900;

/// Operation ceremony expiry time in seconds (1 hour)
pub const OPERATION_EXPIRY_SECONDS: u64 = 3600;

/// Shamir secret sharing threshold (3 of 5)
pub const SHAMIR_THRESHOLD: usize = 3;

/// Shamir secret sharing total shares
pub const SHAMIR_TOTAL_SHARES: usize = 5;

/// Number of MFA backup codes
pub const MFA_BACKUP_CODES_COUNT: usize = 10;

/// Domain Separation Strings (as specified in cryptographic-constants.md § 11)
/// Domain separation for Identity Signing Key derivation
/// Format: "cypher:auth:identity:v1" || identity_id
pub const DOMAIN_IDENTITY_SIGNING: &str = "cypher:auth:identity:v1";

/// Domain separation for Machine seed derivation
/// Format: "cypher:shared:machine:v1" || identity_id || machine_id || epoch
pub const DOMAIN_MACHINE_SEED: &str = "cypher:shared:machine:v1";

/// Domain separation for Machine signing key derivation
/// Format: "cypher:shared:machine:sign:v1" || machine_id
pub const DOMAIN_MACHINE_SIGN: &str = "cypher:shared:machine:sign:v1";

/// Domain separation for Machine encryption key derivation
/// Format: "cypher:shared:machine:encrypt:v1" || machine_id
pub const DOMAIN_MACHINE_ENCRYPT: &str = "cypher:shared:machine:encrypt:v1";

/// Domain separation for JWT signing key seed derivation
/// Format: "cypher:auth:jwt:v1" || key_epoch
pub const DOMAIN_JWT_SIGNING: &str = "cypher:auth:jwt:v1";

/// Domain separation for MFA KEK derivation
/// Format: "cypher:auth:mfa-kek:v1" || identity_id
pub const DOMAIN_MFA_KEK: &str = "cypher:auth:mfa-kek:v1";

/// Domain separation for MFA TOTP AAD
/// Format: "cypher:auth:mfa-totp:v1" || identity_id
pub const DOMAIN_MFA_TOTP_AAD: &str = "cypher:auth:mfa-totp:v1";

/// Domain separation for recovery share backup KEK
/// Format: "cypher:share-backup-kek:v1" || identity_id
pub const DOMAIN_SHARE_BACKUP_KEK: &str = "cypher:share-backup-kek:v1";

/// Domain separation for recovery share backup AAD
/// Format: "cypher:share-backup:v1" || identity_id || share_index
pub const DOMAIN_SHARE_BACKUP_AAD: &str = "cypher:share-backup:v1";

/// Domain separation for Shared Vault Key (SVK) derivation (zero-vault)
/// Format: "cypher:vault:svk:v1" || cell_id || vault_id
pub const DOMAIN_VAULT_SVK: &str = "cypher:vault:svk:v1";

/// Domain separation for Vault Data Encryption Key (VDEK) derivation (zero-vault)
/// Format: "cypher:vault:vdek:v1" || cell_id || vault_id || vdek_epoch
pub const DOMAIN_VAULT_VDEK: &str = "cypher:vault:vdek:v1";

/// Domain separation for signing key client share derivation (zero-vault)
/// Format: "cypher:vault:signing:v1" || cell_id || vault_id || key_id || scheme || chain_id
pub const DOMAIN_VAULT_SIGNING: &str = "cypher:vault:signing:v1";

/// Argon2id parameters for password hashing
pub mod argon2_params {
    use argon2::{Params, Version};

    /// Memory cost: 64 MiB
    pub const MEMORY_COST: u32 = 64 * 1024;

    /// Time cost: 3 iterations
    pub const TIME_COST: u32 = 3;

    /// Parallelism: 1 thread
    pub const PARALLELISM: u32 = 1;

    /// Output length: 32 bytes
    pub const OUTPUT_LENGTH: usize = 32;

    /// Get Argon2id parameters
    pub fn get_params() -> Params {
        Params::new(MEMORY_COST, TIME_COST, PARALLELISM, Some(OUTPUT_LENGTH))
            .expect("valid Argon2id parameters")
    }

    /// Argon2 version
    pub const VERSION: Version = Version::V0x13;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_are_correct_sizes() {
        assert_eq!(NEURAL_KEY_SIZE, 32);
        assert_eq!(PUBLIC_KEY_SIZE, 32);
        assert_eq!(SIGNATURE_SIZE, 64);
        assert_eq!(NONCE_SIZE, 24);
        assert_eq!(TAG_SIZE, 16);
    }

    #[test]
    fn test_domain_strings_follow_spec() {
        // All domain strings must follow format: "cypher:{service}:{purpose}:v{version}"
        assert!(DOMAIN_IDENTITY_SIGNING.starts_with("cypher:"));
        assert!(DOMAIN_IDENTITY_SIGNING.contains(":v1"));

        assert!(DOMAIN_MACHINE_SEED.starts_with("cypher:"));
        assert!(DOMAIN_MACHINE_SEED.contains(":v1"));

        assert!(DOMAIN_JWT_SIGNING.starts_with("cypher:"));
        assert!(DOMAIN_JWT_SIGNING.contains(":v1"));
    }

    #[test]
    fn test_shamir_threshold_is_valid() {
        // Use runtime comparison to avoid clippy constant assertion warning
        let threshold = SHAMIR_THRESHOLD;
        let total = SHAMIR_TOTAL_SHARES;
        assert!(threshold <= total, "Threshold must be <= total shares");
        assert_eq!(threshold, 3);
        assert_eq!(total, 5);
    }

    #[test]
    fn test_argon2_params_are_valid() {
        let params = argon2_params::get_params();
        assert!(params.m_cost() > 0);
        assert!(params.t_cost() > 0);
    }
}
