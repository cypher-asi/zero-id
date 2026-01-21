//! EVM wallet authentication using SECP256k1 signatures.
//!
//! Implements EIP-191 message signing for Ethereum-compatible wallets.

use crate::{errors::*, types::*};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

/// Recover Ethereum address from message hash and signature
///
/// # Arguments
/// * `message_hash` - Keccak256 hash of the message
/// * `signature` - 65-byte signature (r, s, v)
///
/// # Returns
/// Ethereum address in lowercase with 0x prefix
pub fn recover_address(message_hash: &[u8; 32], signature: &[u8; 65]) -> Result<String> {
    // Extract recovery ID (v parameter)
    let recovery_id = RecoveryId::try_from(signature[64] % 27).map_err(|e| {
        AuthMethodsError::WalletSignatureInvalid(format!("Invalid recovery ID: {}", e))
    })?;

    // Extract signature (r, s parameters)
    let sig = Signature::try_from(&signature[..64]).map_err(|e| {
        AuthMethodsError::WalletSignatureInvalid(format!("Invalid signature: {}", e))
    })?;

    // Recover public key from signature
    let verifying_key = VerifyingKey::recover_from_prehash(message_hash, &sig, recovery_id)
        .map_err(|e| AuthMethodsError::WalletSignatureInvalid(format!("Recovery failed: {}", e)))?;

    // Get uncompressed public key (65 bytes: 0x04 + x + y)
    let public_key = verifying_key.to_encoded_point(false);
    let public_key_bytes = public_key.as_bytes();

    // Ethereum address = last 20 bytes of keccak256(public_key[1..])
    // Skip the first byte (0x04 prefix for uncompressed key)
    let hash = keccak256(&public_key_bytes[1..]);
    let address = format!("0x{}", hex::encode(&hash[12..]));

    Ok(address.to_lowercase())
}

/// Compute Keccak256 hash
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Build EIP-191 message for signing
///
/// Format: "\x19Ethereum Signed Message:\n" + len(message) + message
pub fn build_eip191_message(message: &str) -> String {
    format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message)
}

/// Verify wallet signature against challenge
///
/// # Arguments
/// * `challenge` - The challenge that was signed
/// * `wallet_address` - Expected wallet address
/// * `signature` - 65-byte SECP256k1 signature
///
/// # Returns
/// Ok(()) if signature is valid, Err otherwise
pub fn verify_wallet_signature(
    challenge: &Challenge,
    wallet_address: &str,
    signature: &[u8; 65],
) -> Result<()> {
    // Serialize challenge to JSON (canonical)
    let challenge_json = serde_json::to_string(challenge)
        .map_err(|e| AuthMethodsError::Other(format!("Challenge serialization failed: {}", e)))?;

    // Build EIP-191 message
    let message = build_eip191_message(&challenge_json);

    // Hash message
    let message_hash = keccak256(message.as_bytes());

    // Recover address from signature
    let recovered_address = recover_address(&message_hash, signature)?;

    // Compare addresses (case-insensitive)
    if recovered_address.to_lowercase() != wallet_address.to_lowercase() {
        return Err(AuthMethodsError::WalletAddressMismatch {
            expected: wallet_address.to_string(),
            recovered: recovered_address,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256() {
        let data = b"hello world";
        let hash = keccak256(data);

        // Known keccak256 hash of "hello world"
        let expected =
            hex::decode("47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad")
                .unwrap();

        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_eip191_message_format() {
        let message = "Hello, Ethereum!";
        let eip191 = build_eip191_message(message);

        assert_eq!(eip191, "\x19Ethereum Signed Message:\n16Hello, Ethereum!");
    }

    #[test]
    fn test_recover_address_invalid_signature() {
        let message_hash = [0u8; 32];
        let signature = [0u8; 65];

        let result = recover_address(&message_hash, &signature);
        assert!(result.is_err());
    }
}
