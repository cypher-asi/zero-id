//! Multi-factor authentication (TOTP) implementation.

use crate::{errors::*, types::MfaSetup};
use rand::Rng;
use totp_rs::{Algorithm, Secret, TOTP};
use zero_auth_crypto::{
    decrypt_mfa_secret as decrypt_secret, encrypt_mfa_secret as encrypt_secret,
};

/// TOTP parameters
const TOTP_DIGITS: usize = 6;
const TOTP_STEP: u64 = 30; // 30 seconds

/// Number of backup codes to generate
const BACKUP_CODE_COUNT: usize = 10;

/// Length of backup codes
const BACKUP_CODE_LENGTH: usize = 8;

/// Generate a new TOTP secret and setup information
pub fn generate_mfa_setup(issuer: &str, account_name: &str) -> Result<MfaSetup> {
    // Generate random secret (20 bytes = 160 bits, standard for TOTP)
    let mut rng = rand::thread_rng();
    let mut secret_bytes = vec![0u8; 20];
    rng.fill(&mut secret_bytes[..]);

    // Encode to base32 for display
    let secret_base32 = Secret::Raw(secret_bytes.clone()).to_encoded().to_string();

    // Create TOTP instance using SHA-256 for improved security
    // Note: SHA-256 is recommended over SHA-1 for new implementations
    let _totp = TOTP::new(
        Algorithm::SHA256,
        TOTP_DIGITS,
        1, // skew (for time sync tolerance)
        TOTP_STEP,
        secret_bytes,
    )
    .map_err(|e| AuthMethodsError::TotpError(e.to_string()))?;

    // Generate OTPAuth URL for QR code
    // Note: algorithm=SHA256 - ensure authenticator app supports SHA-256
    let otpauth_url = format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA256&digits={}&period={}",
        issuer, account_name, secret_base32, issuer, TOTP_DIGITS, TOTP_STEP
    );

    // For now, just return the URL (frontend can generate QR code)
    let qr_code_url = format!("data:text/plain;charset=utf-8,{}", otpauth_url);

    // Generate backup codes
    let backup_codes = generate_backup_codes();

    Ok(MfaSetup {
        secret: secret_base32,
        qr_code_url,
        backup_codes,
    })
}

/// Verify a TOTP code against a secret
pub fn verify_totp_code(secret_base32: &str, code: &str) -> Result<bool> {
    // Decode base32 secret
    let secret_bytes = match Secret::Encoded(secret_base32.to_string()).to_bytes() {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(AuthMethodsError::TotpError(
                "Invalid secret encoding".to_string(),
            ))
        }
    };

    let totp = TOTP::new(
        Algorithm::SHA256,
        TOTP_DIGITS,
        1,
        TOTP_STEP,
        secret_bytes.to_vec(),
    )
    .map_err(|e| AuthMethodsError::TotpError(e.to_string()))?;

    // Check with tolerance window (±1 time step = ±30 seconds)
    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| AuthMethodsError::TotpError(e.to_string()))?
        .as_secs();

    Ok(totp.check(code, current_time))
}

/// Encrypt MFA secret with per-user KEK
/// Returns (ciphertext, nonce)
pub fn encrypt_mfa_secret_data(
    secret: &str,
    kek: &[u8; 32],
    identity_id: &uuid::Uuid,
) -> Result<(Vec<u8>, [u8; 24])> {
    // Generate random nonce
    // SECURITY: XChaCha20 uses 192-bit nonces (24 bytes), making random collisions
    // extremely unlikely (birthday bound at 2^96 operations). Each nonce is stored
    // with its ciphertext, enabling collision detection. Future enhancement: consider
    // counter-based nonces for deterministic uniqueness (see keys.rs::generate_nonce).
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 24];
    rng.fill(&mut nonce);

    let secret_bytes = secret.as_bytes();
    let ciphertext =
        encrypt_secret(kek, secret_bytes, &nonce, identity_id).map_err(AuthMethodsError::Crypto)?;

    Ok((ciphertext, nonce))
}

/// Decrypt MFA secret with per-user KEK
pub fn decrypt_mfa_secret_data(
    encrypted: &[u8],
    nonce: &[u8; 24],
    kek: &[u8; 32],
    identity_id: &uuid::Uuid,
) -> Result<String> {
    let decrypted =
        decrypt_secret(kek, encrypted, nonce, identity_id).map_err(AuthMethodsError::Crypto)?;
    String::from_utf8(decrypted).map_err(|e| AuthMethodsError::Other(e.to_string()))
}

/// Generate backup codes
fn generate_backup_codes() -> Vec<String> {
    let mut rng = rand::thread_rng();
    (0..BACKUP_CODE_COUNT)
        .map(|_| {
            let code: String = (0..BACKUP_CODE_LENGTH)
                .map(|_| rng.gen_range(0..10).to_string())
                .collect();
            code
        })
        .collect()
}

/// Hash backup code for storage
pub fn hash_backup_code(code: &str) -> String {
    use zero_auth_crypto::blake3_hash;
    hex::encode(blake3_hash(code.as_bytes()))
}

/// Verify backup code against stored hash
///
/// Uses constant-time comparison to prevent timing attacks.
pub fn verify_backup_code(code: &str, hash: &str) -> bool {
    let computed_hash = hash_backup_code(code);
    // Use constant-time comparison to prevent timing attacks
    zero_auth_crypto::constant_time_compare(computed_hash.as_bytes(), hash.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mfa_setup() {
        let setup = generate_mfa_setup("ZeroAuth", "user@example.com").unwrap();

        // Secret should be base32 encoded
        assert!(!setup.secret.is_empty());
        assert!(setup
            .secret
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));

        // QR code should be a data URL (otpauth URL for now)
        assert!(setup.qr_code_url.starts_with("data:text/plain"));

        // Should have correct number of backup codes
        assert_eq!(setup.backup_codes.len(), BACKUP_CODE_COUNT);

        // Each backup code should be 8 digits
        for code in &setup.backup_codes {
            assert_eq!(code.len(), BACKUP_CODE_LENGTH);
            assert!(code.chars().all(|c| c.is_ascii_digit()));
        }
    }

    #[test]
    fn test_verify_totp_code() {
        // Generate a random secret
        let mut rng = rand::thread_rng();
        let mut secret_bytes = vec![0u8; 20];
        rng.fill(&mut secret_bytes[..]);

        // Encode to base32
        let secret_base32 = Secret::Raw(secret_bytes.clone()).to_encoded().to_string();

        // Generate current code
        let totp = TOTP::new(Algorithm::SHA256, TOTP_DIGITS, 1, TOTP_STEP, secret_bytes).unwrap();

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let code = totp.generate(current_time);

        // Verification should succeed
        assert!(verify_totp_code(&secret_base32, &code).unwrap());

        // Wrong code should fail
        assert!(!verify_totp_code(&secret_base32, "000000").unwrap());
    }

    #[test]
    fn test_encrypt_decrypt_mfa_secret() {
        let secret = "JBSWY3DPEHPK3PXP";
        let kek = [0x42; 32];
        let identity_id = uuid::Uuid::new_v4();

        // Encrypt
        let (encrypted, nonce) = encrypt_mfa_secret_data(secret, &kek, &identity_id).unwrap();

        // Decrypt
        let decrypted = decrypt_mfa_secret_data(&encrypted, &nonce, &kek, &identity_id).unwrap();

        assert_eq!(secret, decrypted);
    }

    #[test]
    fn test_backup_codes() {
        let code = "12345678";
        let hash = hash_backup_code(code);

        // Same code should verify
        assert!(verify_backup_code(code, &hash));

        // Different code should not verify
        assert!(!verify_backup_code("87654321", &hash));
    }

    #[test]
    fn test_backup_code_hash_deterministic() {
        let code = "12345678";
        let hash1 = hash_backup_code(code);
        let hash2 = hash_backup_code(code);

        // Same input should produce same hash
        assert_eq!(hash1, hash2);
    }
}
