//! Hashing utilities using BLAKE3 and Argon2id.

use crate::{constants::*, errors::*};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use blake3::Hasher as Blake3Hasher;

/// Hash data using BLAKE3
///
/// BLAKE3 is used for fast, non-cryptographic hashing of data (checksums, key IDs).
/// For password hashing, use `hash_password` with Argon2id.
pub fn blake3_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Derive a key ID from a public key using BLAKE3
/// Returns first 16 bytes of BLAKE3 hash as key identifier
pub fn derive_key_id(public_key: &[u8; 32]) -> [u8; 16] {
    let hash = blake3_hash(public_key);
    let mut key_id = [0u8; 16];
    key_id.copy_from_slice(&hash[..16]);
    key_id
}

/// Hash a password using Argon2id
///
/// This implements the Argon2id parameters from cryptographic-constants.md § 10.
///
/// # Arguments
///
/// * `password` - The password to hash
/// * `salt` - Salt string (use `generate_salt()` to create)
///
/// # Returns
///
/// PHC-formatted hash string that includes algorithm, parameters, salt, and hash
pub fn hash_password(password: &[u8], salt: &SaltString) -> Result<String> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2_params::VERSION,
        argon2_params::get_params(),
    );

    let password_hash = argon2
        .hash_password(password, salt)
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))?;

    Ok(password_hash.to_string())
}

/// Verify a password against an Argon2id hash
///
/// # Arguments
///
/// * `password` - The password to verify
/// * `hash_str` - The PHC-formatted hash string from `hash_password`
///
/// # Returns
///
/// `Ok(())` if password matches, `Err` otherwise
pub fn verify_password(password: &[u8], hash_str: &str) -> Result<()> {
    let parsed_hash = PasswordHash::new(hash_str).map_err(|_| CryptoError::InvalidHashFormat)?;

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2_params::VERSION,
        argon2_params::get_params(),
    );

    argon2
        .verify_password(password, &parsed_hash)
        .map_err(|e| CryptoError::Argon2Failed(e.to_string()))
}

/// Generate a random salt for password hashing
pub fn generate_salt() -> SaltString {
    SaltString::generate(&mut rand::thread_rng())
}

/// Securely compare two byte slices in constant time
///
/// This prevents timing attacks when comparing secrets like MAC tags or password hashes.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash_deterministic() {
        let data = b"test data";
        let hash1 = blake3_hash(data);
        let hash2 = blake3_hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_blake3_hash_different_inputs() {
        let hash1 = blake3_hash(b"data1");
        let hash2 = blake3_hash(b"data2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_derive_key_id() {
        let public_key = [42u8; 32];
        let key_id = derive_key_id(&public_key);
        assert_eq!(key_id.len(), 16);
    }

    #[test]
    fn test_password_hash_and_verify() {
        let password = b"correct horse battery staple";
        let salt = generate_salt();

        let hash = hash_password(password, &salt).unwrap();
        assert!(verify_password(password, &hash).is_ok());

        let wrong_password = b"wrong password";
        assert!(verify_password(wrong_password, &hash).is_err());
    }

    #[test]
    fn test_generate_salt_is_random() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert_ne!(salt1.as_str(), salt2.as_str());
    }

    #[test]
    fn test_constant_time_compare() {
        let a = b"secret";
        let b = b"secret";
        let c = b"public";

        assert!(constant_time_compare(a, b));
        assert!(!constant_time_compare(a, c));
        assert!(!constant_time_compare(a, &b[..3])); // Different lengths
    }

    #[test]
    fn test_password_hash_includes_parameters() {
        let password = b"test password";
        let salt = generate_salt();
        let hash = hash_password(password, &salt).unwrap();

        // PHC format should include $argon2id$
        assert!(hash.starts_with("$argon2id$"));
    }
}
