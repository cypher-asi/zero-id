//! Shamir Secret Sharing for Neural Key backup and recovery.
//!
//! Implements 3-of-5 Shamir Secret Sharing for splitting and reconstructing
//! the 32-byte Neural Key into Neural Shards.
//!
//! # Security Model
//!
//! - The Neural Key is split into 5 Neural Shards using Shamir's Secret Sharing
//! - Any 3 shards can reconstruct the original Neural Key
//! - Fewer than 3 shards reveal no information about the Neural Key
//! - Shards are distributed to trusted custodians for safekeeping

use crate::{
    constants::{SHAMIR_THRESHOLD, SHAMIR_TOTAL_SHARES},
    errors::{CryptoError, Result},
    keys::NeuralKey,
};
use sharks::{Share, Sharks};

/// A Neural Shard - a Shamir secret share used to reconstruct the Neural Key.
///
/// The Neural Key is split into 5 shards using 3-of-5 Shamir Secret Sharing.
/// Any 3 shards can reconstruct the original Neural Key, but 2 or fewer
/// reveal no information about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NeuralShard {
    /// Shard index (1-255, but we use 1-5)
    pub index: u8,
    /// Shard data (same length as secret)
    pub data: [u8; 32],
}

impl NeuralShard {
    /// Create a new NeuralShard from index and data.
    pub fn new(index: u8, data: [u8; 32]) -> Self {
        Self { index, data }
    }

    /// Convert the shard to a hex string.
    ///
    /// Format: index byte followed by 32 bytes of data = 33 bytes total = 66 hex chars
    pub fn to_hex(&self) -> String {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(self.index);
        bytes.extend_from_slice(&self.data);
        hex::encode(bytes)
    }

    /// Parse a shard from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidShardFormat("Invalid hex encoding".to_string()))?;

        Self::from_bytes(&bytes)
    }

    /// Convert the shard to raw bytes (33 bytes: 1 byte index + 32 bytes data).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(self.index);
        bytes.extend_from_slice(&self.data);
        bytes
    }

    /// Parse a shard from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 33 {
            return Err(CryptoError::InvalidShardFormat(format!(
                "Expected 33 bytes, got {}",
                bytes.len()
            )));
        }

        let index = bytes[0];
        if index == 0 {
            return Err(CryptoError::InvalidShardFormat(
                "Shard index cannot be 0".to_string(),
            ));
        }

        let mut data = [0u8; 32];
        data.copy_from_slice(&bytes[1..33]);

        Ok(Self { index, data })
    }

    /// Convert to sharks::Share format (internal)
    fn to_sharks_share(&self) -> Share {
        let mut bytes = Vec::with_capacity(33);
        bytes.push(self.index);
        bytes.extend_from_slice(&self.data);
        Share::try_from(bytes.as_slice()).expect("valid shard format")
    }

    /// Convert from sharks::Share format (internal)
    fn from_sharks_share(share: &Share) -> Self {
        let bytes: Vec<u8> = share.into();
        let index = bytes[0];
        let mut data = [0u8; 32];
        data.copy_from_slice(&bytes[1..33]);
        Self { index, data }
    }
}

/// Split a Neural Key into 5 Neural Shards.
///
/// Uses a 3-of-5 threshold scheme, meaning any 3 shards can reconstruct
/// the original Neural Key, but 2 or fewer shards reveal nothing.
///
/// # Arguments
///
/// * `neural_key` - The 32-byte Neural Key to split
///
/// # Returns
///
/// An array of 5 NeuralShard objects, each containing an index and 32 bytes of shard data.
pub fn split_neural_key(neural_key: &NeuralKey) -> Result<[NeuralShard; SHAMIR_TOTAL_SHARES]> {
    let secret = neural_key.as_bytes();

    // Create sharks dealer with threshold
    let sharks = Sharks(SHAMIR_THRESHOLD as u8);

    // Generate shards
    let dealer = sharks.dealer(secret);
    let shards: Vec<Share> = dealer.take(SHAMIR_TOTAL_SHARES).collect();

    if shards.len() != SHAMIR_TOTAL_SHARES {
        return Err(CryptoError::ShamirSplitFailed(format!(
            "Expected {} shards, got {}",
            SHAMIR_TOTAL_SHARES,
            shards.len()
        )));
    }

    // Convert to our NeuralShard format
    Ok([
        NeuralShard::from_sharks_share(&shards[0]),
        NeuralShard::from_sharks_share(&shards[1]),
        NeuralShard::from_sharks_share(&shards[2]),
        NeuralShard::from_sharks_share(&shards[3]),
        NeuralShard::from_sharks_share(&shards[4]),
    ])
}

/// Combine Neural Shards to reconstruct the Neural Key.
///
/// Requires at least 3 shards to reconstruct the original Neural Key.
///
/// # Arguments
///
/// * `shards` - A slice of 3-5 NeuralShard objects
///
/// # Returns
///
/// The reconstructed Neural Key if successful.
///
/// # Errors
///
/// Returns an error if:
/// - Fewer than 3 shards are provided
/// - More than 5 shards are provided
/// - Shard indices are duplicated
/// - Shards are invalid or corrupted
pub fn combine_shards(shards: &[NeuralShard]) -> Result<NeuralKey> {
    // Validate shard count
    if shards.len() < SHAMIR_THRESHOLD {
        return Err(CryptoError::InsufficientShards {
            required: SHAMIR_THRESHOLD,
            provided: shards.len(),
        });
    }

    if shards.len() > SHAMIR_TOTAL_SHARES {
        return Err(CryptoError::TooManyShards {
            maximum: SHAMIR_TOTAL_SHARES,
            provided: shards.len(),
        });
    }

    // Check for duplicate indices
    let mut seen_indices = std::collections::HashSet::new();
    for shard in shards {
        if !seen_indices.insert(shard.index) {
            return Err(CryptoError::DuplicateShardIndex(shard.index));
        }
    }

    // Convert to sharks shares
    let sharks_shares: Vec<Share> = shards.iter().map(|s| s.to_sharks_share()).collect();

    // Create sharks with same threshold
    let sharks = Sharks(SHAMIR_THRESHOLD as u8);

    // Recover the secret
    let secret = sharks
        .recover(&sharks_shares)
        .map_err(|e| CryptoError::ShamirCombineFailed(format!("{}", e)))?;

    if secret.len() != 32 {
        return Err(CryptoError::ShamirCombineFailed(format!(
            "Invalid secret length: expected 32 bytes, got {}",
            secret.len()
        )));
    }

    let mut neural_key_bytes = [0u8; 32];
    neural_key_bytes.copy_from_slice(&secret);

    Ok(NeuralKey::from_bytes(neural_key_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_combine_roundtrip() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        // Combine all 5 shards
        let recovered = combine_shards(&shards).unwrap();
        assert_eq!(
            neural_key.as_bytes(),
            recovered.as_bytes(),
            "Recovered key should match original"
        );
    }

    #[test]
    fn test_combine_with_exactly_3_shards() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        // Use only 3 shards (threshold)
        let subset = &shards[0..3];
        let recovered = combine_shards(subset).unwrap();
        assert_eq!(
            neural_key.as_bytes(),
            recovered.as_bytes(),
            "Should recover with exactly 3 shards"
        );
    }

    #[test]
    fn test_combine_with_4_shards() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        // Use 4 shards (more than threshold)
        let subset = &shards[0..4];
        let recovered = combine_shards(subset).unwrap();
        assert_eq!(
            neural_key.as_bytes(),
            recovered.as_bytes(),
            "Should recover with 4 shards"
        );
    }

    #[test]
    fn test_combine_with_5_shards() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        // Use all 5 shards
        let recovered = combine_shards(&shards).unwrap();
        assert_eq!(
            neural_key.as_bytes(),
            recovered.as_bytes(),
            "Should recover with all 5 shards"
        );
    }

    #[test]
    fn test_combine_with_2_shards_fails() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        // Try with only 2 shards (below threshold)
        let subset = &shards[0..2];
        let result = combine_shards(subset);
        assert!(result.is_err(), "Should fail with only 2 shards");

        match result {
            Err(CryptoError::InsufficientShards { required, provided }) => {
                assert_eq!(required, 3);
                assert_eq!(provided, 2);
            }
            _ => panic!("Expected InsufficientShards error"),
        }
    }

    #[test]
    fn test_shard_hex_roundtrip() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        for shard in &shards {
            let hex_str = shard.to_hex();
            let recovered_shard = NeuralShard::from_hex(&hex_str).unwrap();
            assert_eq!(shard.index, recovered_shard.index);
            assert_eq!(shard.data, recovered_shard.data);
        }
    }

    #[test]
    fn test_different_shard_combinations() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        // Test various 3-shard combinations
        let combinations = [
            [0, 1, 2],
            [0, 1, 3],
            [0, 1, 4],
            [0, 2, 3],
            [0, 2, 4],
            [0, 3, 4],
            [1, 2, 3],
            [1, 2, 4],
            [1, 3, 4],
            [2, 3, 4],
        ];

        for combo in combinations {
            let subset: Vec<NeuralShard> = combo.iter().map(|&i| shards[i].clone()).collect();
            let recovered = combine_shards(&subset).unwrap();
            assert_eq!(
                neural_key.as_bytes(),
                recovered.as_bytes(),
                "Combination {:?} should recover correctly",
                combo
            );
        }
    }

    #[test]
    fn test_duplicate_shard_index_fails() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        // Create a duplicate by using the same shard twice
        let duplicate_shards = vec![shards[0].clone(), shards[0].clone(), shards[1].clone()];

        let result = combine_shards(&duplicate_shards);
        assert!(result.is_err(), "Should fail with duplicate shard indices");

        match result {
            Err(CryptoError::DuplicateShardIndex(idx)) => {
                assert_eq!(idx, shards[0].index);
            }
            _ => panic!("Expected DuplicateShardIndex error"),
        }
    }

    #[test]
    fn test_shard_indices_are_nonzero() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        for shard in &shards {
            assert!(shard.index > 0, "Shard index should be > 0");
        }
    }

    #[test]
    fn test_invalid_hex_parsing() {
        // Invalid hex
        assert!(NeuralShard::from_hex("not_hex").is_err());

        // Too short
        assert!(NeuralShard::from_hex("0102030405").is_err());

        // Too long
        let long_hex = "00".repeat(50);
        assert!(NeuralShard::from_hex(&long_hex).is_err());
    }

    #[test]
    fn test_empty_shards_fails() {
        let empty: Vec<NeuralShard> = vec![];
        let result = combine_shards(&empty);
        assert!(result.is_err(), "Should fail with empty shards");
    }

    #[test]
    fn test_too_many_shards_fails() {
        let neural_key = NeuralKey::generate().unwrap();
        let shards = split_neural_key(&neural_key).unwrap();

        // Create more than 5 shards by adding a fake one
        let mut too_many = shards.to_vec();
        too_many.push(NeuralShard::new(99, [0u8; 32]));

        let result = combine_shards(&too_many);
        assert!(result.is_err(), "Should fail with more than 5 shards");

        match result {
            Err(CryptoError::TooManyShards { maximum, provided }) => {
                assert_eq!(maximum, 5);
                assert_eq!(provided, 6);
            }
            _ => panic!("Expected TooManyShards error"),
        }
    }

    #[test]
    fn test_zero_index_fails_parsing() {
        // Zero index is invalid
        let mut bytes = vec![0u8]; // index 0
        bytes.extend_from_slice(&[1u8; 32]); // dummy data
        let hex_str = hex::encode(bytes);
        assert!(NeuralShard::from_hex(&hex_str).is_err());
    }
}
