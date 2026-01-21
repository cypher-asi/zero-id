//! Digital signature operations using Ed25519.

use crate::{constants::*, errors::*, keys::Ed25519KeyPair};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Challenge for authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge ID
    pub challenge_id: Uuid,
    /// Machine ID or entity ID this challenge is for
    pub entity_id: Uuid,
    /// Entity type (machine, wallet, email)
    pub entity_type: EntityType,
    /// Purpose of the challenge
    pub purpose: String,
    /// Audience (service URL)
    pub aud: String,
    /// Issued at timestamp
    pub iat: u64,
    /// Expiry timestamp
    pub exp: u64,
    /// Random nonce
    pub nonce: [u8; 32],
    /// Whether challenge has been used (replay protection)
    pub used: bool,
}

/// Entity type for challenges
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u8)]
pub enum EntityType {
    /// Machine key authentication
    Machine = 0x01,
    /// Wallet signature authentication
    Wallet = 0x02,
    /// Email + password authentication
    Email = 0x03,
}

/// Sign a message with Ed25519
///
/// # Arguments
///
/// * `keypair` - The Ed25519 key pair to sign with
/// * `message` - The message to sign
///
/// # Returns
///
/// 64-byte Ed25519 signature
pub fn sign_message(keypair: &Ed25519KeyPair, message: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let signature = keypair.private_key().sign(message);
    signature.to_bytes()
}

/// Verify an Ed25519 signature
///
/// # Arguments
///
/// * `public_key` - The Ed25519 public key (32 bytes)
/// * `message` - The message that was signed
/// * `signature` - The signature to verify (64 bytes)
///
/// # Returns
///
/// `Ok(())` if signature is valid, `Err` otherwise
pub fn verify_signature(
    public_key: &[u8; PUBLIC_KEY_SIZE],
    message: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(public_key)
        .map_err(|e| CryptoError::Ed25519Error(e.to_string()))?;

    let sig = Signature::from_bytes(signature);

    verifying_key
        .verify(message, &sig)
        .map_err(|_| CryptoError::SignatureVerificationFailed)
}

/// Create a canonical binary message for identity creation authorization
///
/// As specified in 03-identity-core.md § 3.3
///
/// Format: version(1) || identity_id(16) || identity_signing_public_key(32) ||
///         first_machine_id(16) || machine_signing_key(32) ||
///         machine_encryption_key(32) || created_at(8)
///
/// Total: 137 bytes
pub fn canonicalize_identity_creation_message(
    identity_id: &uuid::Uuid,
    identity_signing_public_key: &[u8; 32],
    first_machine_id: &uuid::Uuid,
    machine_signing_key: &[u8; 32],
    machine_encryption_key: &[u8; 32],
    created_at: u64,
) -> [u8; 137] {
    let mut message = [0u8; 137];

    message[0] = 0x01; // Version
    message[1..17].copy_from_slice(identity_id.as_bytes());
    message[17..49].copy_from_slice(identity_signing_public_key);
    message[49..65].copy_from_slice(first_machine_id.as_bytes());
    message[65..97].copy_from_slice(machine_signing_key);
    message[97..129].copy_from_slice(machine_encryption_key);
    message[129..137].copy_from_slice(&created_at.to_be_bytes());

    message
}

/// Create a canonical binary message for machine key enrollment authorization
///
/// As specified in 03-identity-core.md § 4.3
///
/// Format: version(1) || machine_id(16) || namespace_id(16) ||
///         signing_public_key(32) || encryption_public_key(32) ||
///         capabilities(4) || created_at(8)
///
/// Total: 109 bytes
pub fn canonicalize_enrollment_message(
    machine_id: &uuid::Uuid,
    namespace_id: &uuid::Uuid,
    signing_public_key: &[u8; 32],
    encryption_public_key: &[u8; 32],
    capabilities: u32,
    created_at: u64,
) -> [u8; 109] {
    let mut message = [0u8; 109];

    message[0] = 0x01; // Version
    message[1..17].copy_from_slice(machine_id.as_bytes());
    message[17..33].copy_from_slice(namespace_id.as_bytes());
    message[33..65].copy_from_slice(signing_public_key);
    message[65..97].copy_from_slice(encryption_public_key);
    message[97..101].copy_from_slice(&capabilities.to_be_bytes());
    message[101..109].copy_from_slice(&created_at.to_be_bytes());

    message
}

/// Create a canonical binary message for recovery approval
///
/// As specified in 03-identity-core.md § 6.4
///
/// Format: version(1) || identity_id(16) || recovery_machine_id(16) ||
///         recovery_signing_key(32) || timestamp(8)
///
/// Total: 73 bytes
pub fn canonicalize_recovery_approval_message(
    identity_id: &uuid::Uuid,
    recovery_machine_id: &uuid::Uuid,
    recovery_signing_key: &[u8; 32],
    timestamp: u64,
) -> [u8; 73] {
    let mut message = [0u8; 73];

    message[0] = 0x01; // Version
    message[1..17].copy_from_slice(identity_id.as_bytes());
    message[17..33].copy_from_slice(recovery_machine_id.as_bytes());
    message[33..65].copy_from_slice(recovery_signing_key);
    message[65..73].copy_from_slice(&timestamp.to_be_bytes());

    message
}

/// Create a canonical binary message for Neural Key rotation approval
///
/// As specified in 03-identity-core.md § 7.3
///
/// Format: version(1) || identity_id(16) || new_identity_signing_public_key(32) ||
///         timestamp(8)
///
/// Total: 57 bytes
pub fn canonicalize_rotation_approval_message(
    identity_id: &uuid::Uuid,
    new_identity_signing_public_key: &[u8; 32],
    timestamp: u64,
) -> [u8; 57] {
    let mut message = [0u8; 57];

    message[0] = 0x01; // Version
    message[1..17].copy_from_slice(identity_id.as_bytes());
    message[17..49].copy_from_slice(new_identity_signing_public_key);
    message[49..57].copy_from_slice(&timestamp.to_be_bytes());

    message
}

/// Canonicalize challenge into binary format for signing
///
/// Binary layout (130 bytes total):
/// - version: u8 (1 byte)
/// - challenge_id: UUID (16 bytes)
/// - entity_id: UUID (16 bytes)
/// - entity_type: u8 (1 byte)
/// - purpose: [u8; 16] padded (16 bytes)
/// - aud: [u8; 32] padded (32 bytes)
/// - iat: u64 big-endian (8 bytes)
/// - exp: u64 big-endian (8 bytes)
/// - nonce: [u8; 32] (32 bytes)
pub fn canonicalize_challenge(challenge: &Challenge) -> [u8; 130] {
    let mut message = [0u8; 130];

    // Version
    message[0] = 0x01;

    // Challenge ID
    message[1..17].copy_from_slice(challenge.challenge_id.as_bytes());

    // Entity ID
    message[17..33].copy_from_slice(challenge.entity_id.as_bytes());

    // Entity type
    message[33] = challenge.entity_type as u8;

    // Purpose (padded to 16 bytes)
    let purpose_bytes = challenge.purpose.as_bytes();
    let purpose_len = purpose_bytes.len().min(16);
    message[34..(34 + purpose_len)].copy_from_slice(&purpose_bytes[..purpose_len]);

    // Audience (padded to 32 bytes)
    let aud_bytes = challenge.aud.as_bytes();
    let aud_len = aud_bytes.len().min(32);
    message[50..(50 + aud_len)].copy_from_slice(&aud_bytes[..aud_len]);

    // IAT (issued at)
    message[82..90].copy_from_slice(&challenge.iat.to_be_bytes());

    // EXP (expiry)
    message[90..98].copy_from_slice(&challenge.exp.to_be_bytes());

    // Nonce
    message[98..130].copy_from_slice(&challenge.nonce);

    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Ed25519KeyPair;

    #[test]
    fn test_sign_and_verify() {
        let seed = [42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();
        let message = b"test message";

        let signature = sign_message(&keypair, message);
        let public_key = keypair.public_key_bytes();

        assert!(verify_signature(&public_key, message, &signature).is_ok());
    }

    #[test]
    fn test_verify_invalid_signature() {
        let seed = [42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();
        let message = b"test message";
        let public_key = keypair.public_key_bytes();

        let wrong_signature = [0u8; SIGNATURE_SIZE];
        assert!(verify_signature(&public_key, message, &wrong_signature).is_err());
    }

    #[test]
    fn test_verify_wrong_message() {
        let seed = [42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();
        let message = b"original message";
        let wrong_message = b"tampered message";

        let signature = sign_message(&keypair, message);
        let public_key = keypair.public_key_bytes();

        assert!(verify_signature(&public_key, wrong_message, &signature).is_err());
    }

    #[test]
    fn test_canonicalize_identity_creation() {
        let identity_id = uuid::Uuid::new_v4();
        let identity_signing_public_key = [1u8; 32];
        let first_machine_id = uuid::Uuid::new_v4();
        let machine_signing_key = [2u8; 32];
        let machine_encryption_key = [3u8; 32];
        let created_at = 1705320000u64;

        let message = canonicalize_identity_creation_message(
            &identity_id,
            &identity_signing_public_key,
            &first_machine_id,
            &machine_signing_key,
            &machine_encryption_key,
            created_at,
        );

        assert_eq!(message.len(), 137);
        assert_eq!(message[0], 0x01); // Version
    }

    #[test]
    fn test_canonicalize_enrollment() {
        let machine_id = uuid::Uuid::new_v4();
        let namespace_id = uuid::Uuid::new_v4();
        let signing_public_key = [1u8; 32];
        let encryption_public_key = [2u8; 32];
        let capabilities = 0b00111111u32; // FULL_DEVICE
        let created_at = 1705320000u64;

        let message = canonicalize_enrollment_message(
            &machine_id,
            &namespace_id,
            &signing_public_key,
            &encryption_public_key,
            capabilities,
            created_at,
        );

        assert_eq!(message.len(), 109);
        assert_eq!(message[0], 0x01); // Version
    }

    #[test]
    fn test_canonical_messages_are_deterministic() {
        let identity_id = uuid::Uuid::new_v4();
        let identity_signing_public_key = [1u8; 32];
        let first_machine_id = uuid::Uuid::new_v4();
        let machine_signing_key = [2u8; 32];
        let machine_encryption_key = [3u8; 32];
        let created_at = 1705320000u64;

        let message1 = canonicalize_identity_creation_message(
            &identity_id,
            &identity_signing_public_key,
            &first_machine_id,
            &machine_signing_key,
            &machine_encryption_key,
            created_at,
        );

        let message2 = canonicalize_identity_creation_message(
            &identity_id,
            &identity_signing_public_key,
            &first_machine_id,
            &machine_signing_key,
            &machine_encryption_key,
            created_at,
        );

        assert_eq!(message1, message2);
    }
}
