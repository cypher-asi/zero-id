//! Encryption operations using XChaCha20-Poly1305.

use crate::{constants::*, errors::*};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

/// Encrypt data using XChaCha20-Poly1305 AEAD
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `plaintext` - Data to encrypt
/// * `nonce` - 24-byte nonce (MUST be unique per key)
/// * `aad` - Associated authenticated data (not encrypted, but authenticated)
///
/// # Returns
///
/// Ciphertext with 16-byte authentication tag appended
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(xnonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))
}

/// Decrypt data using XChaCha20-Poly1305 AEAD
///
/// # Arguments
///
/// * `key` - 32-byte encryption key
/// * `ciphertext` - Data to decrypt (includes 16-byte tag at end)
/// * `nonce` - 24-byte nonce (same as used for encryption)
/// * `aad` - Associated authenticated data (same as used for encryption)
///
/// # Returns
///
/// Decrypted plaintext
pub fn decrypt(
    key: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let xnonce = XNonce::from_slice(nonce);

    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(xnonce, payload)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Encrypt MFA TOTP secret
///
/// As specified in cryptographic-constants.md § 10.1
///
/// Uses KEK derived from Neural Key, with AAD including identity_id
pub fn encrypt_mfa_secret(
    mfa_kek: &[u8; 32],
    totp_secret: &[u8],
    nonce: &[u8; NONCE_SIZE],
    identity_id: &uuid::Uuid,
) -> Result<Vec<u8>> {
    // Build AAD: "cypher:auth:mfa-totp:v1" || identity_id
    let mut aad = Vec::with_capacity(DOMAIN_MFA_TOTP_AAD.len() + 16);
    aad.extend_from_slice(DOMAIN_MFA_TOTP_AAD.as_bytes());
    aad.extend_from_slice(identity_id.as_bytes());

    encrypt(mfa_kek, totp_secret, nonce, &aad)
}

/// Decrypt MFA TOTP secret
///
/// As specified in cryptographic-constants.md § 10.1
pub fn decrypt_mfa_secret(
    mfa_kek: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    identity_id: &uuid::Uuid,
) -> Result<Vec<u8>> {
    // Build AAD: "cypher:auth:mfa-totp:v1" || identity_id
    let mut aad = Vec::with_capacity(DOMAIN_MFA_TOTP_AAD.len() + 16);
    aad.extend_from_slice(DOMAIN_MFA_TOTP_AAD.as_bytes());
    aad.extend_from_slice(identity_id.as_bytes());

    decrypt(mfa_kek, ciphertext, nonce, &aad)
}

/// Encrypt recovery share for backup
///
/// As specified in cryptographic-constants.md § 3.5
///
/// Uses backup KEK with AAD including identity_id and share_index
pub fn encrypt_recovery_share(
    backup_kek: &[u8; 32],
    share: &[u8],
    nonce: &[u8; NONCE_SIZE],
    identity_id: &uuid::Uuid,
    share_index: u8,
) -> Result<Vec<u8>> {
    // Build AAD: "cypher:share-backup:v1" || identity_id || share_index
    let mut aad = Vec::with_capacity(DOMAIN_SHARE_BACKUP_AAD.len() + 16 + 1);
    aad.extend_from_slice(DOMAIN_SHARE_BACKUP_AAD.as_bytes());
    aad.extend_from_slice(identity_id.as_bytes());
    aad.push(share_index);

    encrypt(backup_kek, share, nonce, &aad)
}

/// Decrypt recovery share from backup
///
/// As specified in cryptographic-constants.md § 3.5
pub fn decrypt_recovery_share(
    backup_kek: &[u8; 32],
    ciphertext: &[u8],
    nonce: &[u8; NONCE_SIZE],
    identity_id: &uuid::Uuid,
    share_index: u8,
) -> Result<Vec<u8>> {
    // Build AAD: "cypher:share-backup:v1" || identity_id || share_index
    let mut aad = Vec::with_capacity(DOMAIN_SHARE_BACKUP_AAD.len() + 16 + 1);
    aad.extend_from_slice(DOMAIN_SHARE_BACKUP_AAD.as_bytes());
    aad.extend_from_slice(identity_id.as_bytes());
    aad.push(share_index);

    decrypt(backup_kek, ciphertext, nonce, &aad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_nonce;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"secret message";
        let nonce = generate_nonce().unwrap();
        let aad = b"additional authenticated data";

        let ciphertext = encrypt(&key, plaintext, &nonce, aad).unwrap();
        let decrypted = decrypt(&key, &ciphertext, &nonce, aad).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key = [42u8; 32];
        let wrong_key = [43u8; 32];
        let plaintext = b"secret message";
        let nonce = generate_nonce().unwrap();
        let aad = b"aad";

        let ciphertext = encrypt(&key, plaintext, &nonce, aad).unwrap();
        let result = decrypt(&wrong_key, &ciphertext, &nonce, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_nonce() {
        let key = [42u8; 32];
        let plaintext = b"secret message";
        let nonce = generate_nonce().unwrap();
        let wrong_nonce = generate_nonce().unwrap();
        let aad = b"aad";

        let ciphertext = encrypt(&key, plaintext, &nonce, aad).unwrap();
        let result = decrypt(&key, &ciphertext, &wrong_nonce, aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_aad() {
        let key = [42u8; 32];
        let plaintext = b"secret message";
        let nonce = generate_nonce().unwrap();
        let aad = b"correct aad";
        let wrong_aad = b"wrong aad";

        let ciphertext = encrypt(&key, plaintext, &nonce, aad).unwrap();
        let result = decrypt(&key, &ciphertext, &nonce, wrong_aad);

        assert!(result.is_err());
    }

    #[test]
    fn test_ciphertext_includes_tag() {
        let key = [42u8; 32];
        let plaintext = b"secret";
        let nonce = generate_nonce().unwrap();
        let aad = b"";

        let ciphertext = encrypt(&key, plaintext, &nonce, aad).unwrap();

        // Ciphertext should be plaintext length + TAG_SIZE
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_encrypt_mfa_secret() {
        let mfa_kek = [1u8; 32];
        let totp_secret = b"JBSWY3DPEHPK3PXP";
        let nonce = generate_nonce().unwrap();
        let identity_id = uuid::Uuid::new_v4();

        let ciphertext = encrypt_mfa_secret(&mfa_kek, totp_secret, &nonce, &identity_id).unwrap();
        let decrypted =
            decrypt_mfa_secret(&mfa_kek, &ciphertext, &nonce, &identity_id).unwrap();

        assert_eq!(totp_secret, decrypted.as_slice());
    }

    #[test]
    fn test_encrypt_recovery_share() {
        let backup_kek = [2u8; 32];
        let share = b"recovery share bytes";
        let nonce = generate_nonce().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let share_index = 1;

        let ciphertext =
            encrypt_recovery_share(&backup_kek, share, &nonce, &identity_id, share_index).unwrap();
        let decrypted =
            decrypt_recovery_share(&backup_kek, &ciphertext, &nonce, &identity_id, share_index)
                .unwrap();

        assert_eq!(share, decrypted.as_slice());
    }

    #[test]
    fn test_mfa_secret_wrong_identity_fails() {
        let mfa_kek = [1u8; 32];
        let totp_secret = b"JBSWY3DPEHPK3PXP";
        let nonce = generate_nonce().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let wrong_identity_id = uuid::Uuid::new_v4();

        let ciphertext = encrypt_mfa_secret(&mfa_kek, totp_secret, &nonce, &identity_id).unwrap();
        let result = decrypt_mfa_secret(&mfa_kek, &ciphertext, &nonce, &wrong_identity_id);

        assert!(result.is_err());
    }
}
