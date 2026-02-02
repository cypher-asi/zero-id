//! Wallet authentication using SECP256k1 (EVM) and Ed25519 (Solana) signatures.
//!
//! Implements:
//! - EIP-191 message signing for Ethereum-compatible wallets
//! - Ed25519 signature verification for Solana wallets

use crate::{errors::*, types::*};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sha3::{Digest, Keccak256};

// ============================================================================
// Unified Wallet Signature Verification
// ============================================================================

/// Verify wallet signature based on wallet type
///
/// # Arguments
/// * `wallet_type` - Type of wallet (EVM or Solana)
/// * `address` - Wallet address (0x-prefix for EVM, base58 for Solana)
/// * `message` - Message that was signed (raw bytes)
/// * `signature` - Signature bytes (65 bytes for EVM, 64 bytes for Solana)
///
/// # Returns
/// Ok(()) if signature is valid, Err otherwise
pub fn verify_wallet_signature_typed(
    wallet_type: WalletType,
    address: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    match wallet_type.signature_scheme() {
        SignatureScheme::Secp256k1Eip191 => {
            verify_eip191_signature(address, message, signature)
        }
        SignatureScheme::Ed25519 => {
            verify_solana_signature(address, message, signature)
        }
    }
}

/// Verify EIP-191 (Ethereum personal_sign) signature
///
/// # Arguments
/// * `address` - Expected Ethereum address (0x-prefixed)
/// * `message` - Message that was signed (will be wrapped in EIP-191 format)
/// * `signature` - 65-byte SECP256k1 signature (r, s, v)
fn verify_eip191_signature(
    address: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() != 65 {
        return Err(AuthMethodsError::WalletSignatureInvalid(
            format!("EVM signature must be 65 bytes, got {}", signature.len())
        ));
    }

    let mut sig_array = [0u8; 65];
    sig_array.copy_from_slice(signature);

    // Build EIP-191 message
    let message_str = String::from_utf8_lossy(message);
    let eip191_message = build_eip191_message(&message_str);

    // Hash message
    let message_hash = keccak256(eip191_message.as_bytes());

    // Recover address from signature
    let recovered_address = recover_address(&message_hash, &sig_array)?;

    // Compare addresses (case-insensitive)
    if recovered_address.to_lowercase() != address.to_lowercase() {
        return Err(AuthMethodsError::WalletAddressMismatch {
            expected: address.to_string(),
            recovered: recovered_address,
        });
    }

    Ok(())
}

/// Verify Solana Ed25519 signature
///
/// In Solana, wallet addresses ARE the public keys (base58 encoded).
///
/// # Arguments
/// * `address` - Solana wallet address (base58 encoded public key)
/// * `message` - Message that was signed
/// * `signature` - 64-byte Ed25519 signature
fn verify_solana_signature(
    address: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    if signature.len() != 64 {
        return Err(AuthMethodsError::WalletSignatureInvalid(
            format!("Solana signature must be 64 bytes, got {}", signature.len())
        ));
    }

    // Decode base58 address to get public key bytes
    let pubkey_bytes = bs58::decode(address)
        .into_vec()
        .map_err(|e| AuthMethodsError::WalletSignatureInvalid(
            format!("Invalid base58 address: {}", e)
        ))?;

    if pubkey_bytes.len() != 32 {
        return Err(AuthMethodsError::WalletSignatureInvalid(
            format!("Solana address must decode to 32 bytes, got {}", pubkey_bytes.len())
        ));
    }

    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pubkey_bytes);

    let mut sig = [0u8; 64];
    sig.copy_from_slice(signature);

    // Use Ed25519 verification from zid-crypto
    zid_crypto::verify_signature(&pubkey, message, &sig)
        .map_err(|_| AuthMethodsError::WalletSignatureInvalid(
            "Ed25519 signature verification failed".to_string()
        ))
}

/// Validate and normalize wallet address based on type
///
/// # Arguments
/// * `wallet_type` - Type of wallet
/// * `address` - Address to validate
///
/// # Returns
/// Normalized address (lowercase for EVM, unchanged for Solana)
pub fn normalize_wallet_address(wallet_type: WalletType, address: &str) -> Result<String> {
    match wallet_type {
        WalletType::Ethereum | WalletType::Polygon | WalletType::Arbitrum | WalletType::Base => {
            // EVM addresses should be 0x-prefixed and 42 chars total
            let addr = address.trim();
            if !addr.starts_with("0x") && !addr.starts_with("0X") {
                return Err(AuthMethodsError::WalletSignatureInvalid(
                    "EVM address must start with 0x".to_string()
                ));
            }
            if addr.len() != 42 {
                return Err(AuthMethodsError::WalletSignatureInvalid(
                    format!("EVM address must be 42 characters, got {}", addr.len())
                ));
            }
            // Validate hex characters
            hex::decode(&addr[2..]).map_err(|_| {
                AuthMethodsError::WalletSignatureInvalid(
                    "Invalid hex characters in EVM address".to_string()
                )
            })?;
            Ok(addr.to_lowercase())
        }
        WalletType::Solana => {
            // Solana addresses are base58 encoded, typically 32-44 characters
            let addr = address.trim();
            if addr.len() < 32 || addr.len() > 44 {
                return Err(AuthMethodsError::WalletSignatureInvalid(
                    format!("Solana address should be 32-44 characters, got {}", addr.len())
                ));
            }
            // Validate base58 encoding
            bs58::decode(addr).into_vec().map_err(|e| {
                AuthMethodsError::WalletSignatureInvalid(
                    format!("Invalid base58 encoding: {}", e)
                )
            })?;
            Ok(addr.to_string())
        }
    }
}

// ============================================================================
// EVM-specific Functions (Legacy compatibility)
// ============================================================================

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

/// Verify wallet signature against challenge (EVM only - legacy compatibility)
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

    #[test]
    fn test_normalize_evm_address() {
        let addr = "0x1234567890123456789012345678901234567890";
        let normalized = normalize_wallet_address(WalletType::Ethereum, addr).unwrap();
        assert_eq!(normalized, addr.to_lowercase());

        // Should work with uppercase
        let upper = "0x1234567890ABCDEF1234567890ABCDEF12345678";
        let normalized_upper = normalize_wallet_address(WalletType::Ethereum, upper).unwrap();
        assert_eq!(normalized_upper, upper.to_lowercase());
    }

    #[test]
    fn test_normalize_evm_address_invalid() {
        // Missing 0x prefix
        let result = normalize_wallet_address(WalletType::Ethereum, "1234567890123456789012345678901234567890");
        assert!(result.is_err());

        // Wrong length
        let result = normalize_wallet_address(WalletType::Ethereum, "0x12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_normalize_solana_address() {
        // Example Solana address (base58 encoded)
        let addr = "11111111111111111111111111111112";
        let normalized = normalize_wallet_address(WalletType::Solana, addr).unwrap();
        assert_eq!(normalized, addr);
    }

    #[test]
    fn test_normalize_solana_address_invalid() {
        // Too short
        let result = normalize_wallet_address(WalletType::Solana, "short");
        assert!(result.is_err());

        // Invalid base58 (contains 0, O, I, l which are not in base58)
        let result = normalize_wallet_address(WalletType::Solana, "0000000000000000000000000000000000000000000");
        assert!(result.is_err());
    }

    #[test]
    fn test_wallet_type_is_evm() {
        assert!(WalletType::Ethereum.is_evm());
        assert!(WalletType::Polygon.is_evm());
        assert!(WalletType::Arbitrum.is_evm());
        assert!(WalletType::Base.is_evm());
        assert!(!WalletType::Solana.is_evm());
    }

    #[test]
    fn test_wallet_type_signature_scheme() {
        assert_eq!(WalletType::Ethereum.signature_scheme(), SignatureScheme::Secp256k1Eip191);
        assert_eq!(WalletType::Solana.signature_scheme(), SignatureScheme::Ed25519);
    }

    #[test]
    fn test_solana_signature_wrong_length() {
        let addr = "11111111111111111111111111111112";
        let message = b"test message";
        let bad_sig = [0u8; 32]; // Wrong length

        let result = verify_solana_signature(addr, message, &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_solana_address_wrong_decoded_length() {
        // This is a valid base58 string but decodes to wrong length
        let addr = "111111"; // Decodes to only a few bytes
        let message = b"test message";
        let sig = [0u8; 64];

        let result = verify_solana_signature(addr, message, &sig);
        assert!(result.is_err());
    }
}
