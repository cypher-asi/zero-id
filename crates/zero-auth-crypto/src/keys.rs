//! Key generation and management.
//!
//! This module handles generation of Neural Keys, Machine Keys, and other cryptographic keys.

use crate::{constants::*, errors::*};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519PrivateKey};
use zeroize::{Zeroize, ZeroizeOnDrop};
use bitflags::bitflags;

/// Neural Key (root cryptographic seed)
///
/// This is the most sensitive key in the system. It MUST be:
/// - Generated client-side only
/// - Never transmitted over network
/// - Never stored whole on any system
/// - Protected via Shamir Secret Sharing
/// - Zeroized immediately after use
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct NeuralKey([u8; NEURAL_KEY_SIZE]);

impl NeuralKey {
    /// Generate a new Neural Key using cryptographically secure RNG
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; NEURAL_KEY_SIZE];
        rand::thread_rng()
            .try_fill_bytes(&mut key)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
        Ok(Self(key))
    }

    /// Create from existing bytes (e.g., after Shamir reconstruction)
    ///
    /// # Security
    ///
    /// The input bytes will be zeroized after copying into the NeuralKey.
    pub fn from_bytes(mut bytes: [u8; NEURAL_KEY_SIZE]) -> Self {
        let key = Self(bytes);
        bytes.zeroize();
        key
    }

    /// Get a reference to the key bytes
    ///
    /// # Security
    ///
    /// Use with extreme caution. Never log or persist these bytes.
    pub fn as_bytes(&self) -> &[u8; NEURAL_KEY_SIZE] {
        &self.0
    }

    /// Validate that the Neural Key has sufficient entropy
    ///
    /// This is a basic check to ensure the key isn't obviously weak.
    pub fn validate_entropy(&self) -> Result<()> {
        // Check for all zeros
        if self.0.iter().all(|&b| b == 0) {
            return Err(CryptoError::InvalidInput(
                "Neural Key cannot be all zeros".to_string(),
            ));
        }

        // Check for simple repeated patterns
        let first_byte = self.0[0];
        if self.0.iter().all(|&b| b == first_byte) {
            return Err(CryptoError::InvalidInput(
                "Neural Key has insufficient entropy".to_string(),
            ));
        }

        Ok(())
    }
}

/// Ed25519 signing key pair
#[derive(Clone)]
pub struct Ed25519KeyPair {
    /// Private signing key (32 bytes)
    private_key: SigningKey,
    /// Public verification key (32 bytes)
    public_key: VerifyingKey,
}

impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        // Ed25519 keys from ed25519-dalek handle zeroization internally
    }
}

impl Ed25519KeyPair {
    /// Generate a new Ed25519 key pair from a seed
    ///
    /// The seed MUST be 32 bytes of high-entropy random data.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let private_key = SigningKey::from_bytes(seed);
        let public_key = private_key.verifying_key();

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.public_key.to_bytes()
    }

    /// Get a reference to the private key
    ///
    /// # Security
    ///
    /// Use with extreme caution. Never log or persist.
    pub fn private_key(&self) -> &SigningKey {
        &self.private_key
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }
}

/// X25519 encryption key pair
#[derive(Clone)]
pub struct X25519KeyPair {
    /// Private encryption key (32 bytes)
    private_key: X25519PrivateKey,
    /// Public encryption key (32 bytes)
    public_key: X25519PublicKey,
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        // X25519 keys from x25519-dalek handle zeroization internally
    }
}

impl X25519KeyPair {
    /// Generate a new X25519 key pair from a seed
    ///
    /// The seed MUST be 32 bytes of high-entropy random data.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let private_key = X25519PrivateKey::from(*seed);
        let public_key = X25519PublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Get the public key bytes
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        *self.public_key.as_bytes()
    }

    /// Get a reference to the private key
    ///
    /// # Security
    ///
    /// Use with extreme caution. Never log or persist.
    pub fn private_key(&self) -> &X25519PrivateKey {
        &self.private_key
    }

    /// Get a reference to the public key
    pub fn public_key(&self) -> &X25519PublicKey {
        &self.public_key
    }

    /// Perform Diffie-Hellman key agreement
    pub fn diffie_hellman(&self, their_public: &X25519PublicKey) -> [u8; 32] {
        let shared_secret = self.private_key.diffie_hellman(their_public);
        *shared_secret.as_bytes()
    }
}

bitflags! {
    /// Machine Key capabilities bitflags
    ///
    /// As specified in cryptographic-constants.md § 5.2
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MachineKeyCapabilities: u32 {
        /// Can authenticate to zero-auth
        const AUTHENTICATE = 0b00000001;
        /// Can sign challenges
        const SIGN = 0b00000010;
        /// Can encrypt/decrypt
        const ENCRYPT = 0b00000100;
        /// Can unwrap vault keys (zero-vault)
        const SVK_UNWRAP = 0b00001000;
        /// Can participate in MLS groups
        const MLS_MESSAGING = 0b00010000;
        /// Can access zero-vault operations
        const VAULT_OPERATIONS = 0b00100000;

        /// Full device capabilities (all operations)
        const FULL_DEVICE = Self::AUTHENTICATE.bits()
            | Self::SIGN.bits()
            | Self::ENCRYPT.bits()
            | Self::SVK_UNWRAP.bits()
            | Self::MLS_MESSAGING.bits()
            | Self::VAULT_OPERATIONS.bits();

        /// Service machine capabilities (no MLS)
        const SERVICE_MACHINE = Self::AUTHENTICATE.bits()
            | Self::SIGN.bits()
            | Self::VAULT_OPERATIONS.bits();

        /// Limited device capabilities (no vault access)
        const LIMITED_DEVICE = Self::AUTHENTICATE.bits()
            | Self::SIGN.bits()
            | Self::MLS_MESSAGING.bits();
    }
}

// Manual Serialize/Deserialize for bitflags
impl Serialize for MachineKeyCapabilities {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.bits().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for MachineKeyCapabilities {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = u32::deserialize(deserializer)?;
        Ok(MachineKeyCapabilities::from_bits_truncate(bits))
    }
}

/// Machine Key pair (signing + encryption)
///
/// As specified in cryptographic-constants.md § 5
#[derive(Clone)]
pub struct MachineKeyPair {
    /// Ed25519 signing key pair
    signing_key: Ed25519KeyPair,
    /// X25519 encryption key pair
    encryption_key: X25519KeyPair,
    /// Machine capabilities
    capabilities: MachineKeyCapabilities,
}

impl Drop for MachineKeyPair {
    fn drop(&mut self) {
        // Component keys handle zeroization internally
    }
}

impl MachineKeyPair {
    /// Create a new Machine Key pair from signing and encryption seeds
    ///
    /// Both seeds MUST be 32 bytes of high-entropy random data.
    pub fn from_seeds(
        signing_seed: &[u8; 32],
        encryption_seed: &[u8; 32],
        capabilities: MachineKeyCapabilities,
    ) -> Result<Self> {
        let signing_key = Ed25519KeyPair::from_seed(signing_seed)?;
        let encryption_key = X25519KeyPair::from_seed(encryption_seed)?;

        Ok(Self {
            signing_key,
            encryption_key,
            capabilities,
        })
    }

    /// Get the signing public key bytes
    pub fn signing_public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.signing_key.public_key_bytes()
    }

    /// Get the encryption public key bytes
    pub fn encryption_public_key(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.encryption_key.public_key_bytes()
    }

    /// Get a reference to the signing key pair
    pub fn signing_key_pair(&self) -> &Ed25519KeyPair {
        &self.signing_key
    }

    /// Get a reference to the encryption key pair
    pub fn encryption_key_pair(&self) -> &X25519KeyPair {
        &self.encryption_key
    }

    /// Get the capabilities
    pub fn capabilities(&self) -> MachineKeyCapabilities {
        self.capabilities
    }
}

/// Generate a random nonce for encryption
pub fn generate_nonce() -> Result<[u8; NONCE_SIZE]> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(nonce)
}

/// Generate a random challenge nonce
pub fn generate_challenge_nonce() -> Result<[u8; CHALLENGE_NONCE_SIZE]> {
    let mut nonce = [0u8; CHALLENGE_NONCE_SIZE];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_neural_key_generate() {
        let key1 = NeuralKey::generate().unwrap();
        let key2 = NeuralKey::generate().unwrap();

        // Keys should be different (extremely high probability)
        assert_ne!(key1.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_neural_key_validate_entropy() {
        let good_key = NeuralKey::generate().unwrap();
        assert!(good_key.validate_entropy().is_ok());

        let zero_key = NeuralKey::from_bytes([0u8; 32]);
        assert!(zero_key.validate_entropy().is_err());

        let repeated_key = NeuralKey::from_bytes([42u8; 32]);
        assert!(repeated_key.validate_entropy().is_err());
    }

    #[test]
    fn test_ed25519_keypair_from_seed() {
        let seed = [42u8; 32];
        let keypair = Ed25519KeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair.public_key_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_x25519_keypair_from_seed() {
        let seed = [42u8; 32];
        let keypair = X25519KeyPair::from_seed(&seed).unwrap();

        assert_eq!(keypair.public_key_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_machine_key_capabilities() {
        let full = MachineKeyCapabilities::FULL_DEVICE;
        assert!(full.contains(MachineKeyCapabilities::AUTHENTICATE));
        assert!(full.contains(MachineKeyCapabilities::SIGN));
        assert!(full.contains(MachineKeyCapabilities::ENCRYPT));

        let limited = MachineKeyCapabilities::LIMITED_DEVICE;
        assert!(limited.contains(MachineKeyCapabilities::AUTHENTICATE));
        assert!(!limited.contains(MachineKeyCapabilities::VAULT_OPERATIONS));
    }

    #[test]
    fn test_machine_keypair_from_seeds() {
        let signing_seed = [1u8; 32];
        let encryption_seed = [2u8; 32];

        let machine_key = MachineKeyPair::from_seeds(
            &signing_seed,
            &encryption_seed,
            MachineKeyCapabilities::FULL_DEVICE,
        )
        .unwrap();

        assert_eq!(machine_key.signing_public_key().len(), PUBLIC_KEY_SIZE);
        assert_eq!(machine_key.encryption_public_key().len(), PUBLIC_KEY_SIZE);
        assert_eq!(machine_key.capabilities(), MachineKeyCapabilities::FULL_DEVICE);
    }

    #[test]
    fn test_generate_nonce() {
        let nonce1 = generate_nonce().unwrap();
        let nonce2 = generate_nonce().unwrap();

        assert_eq!(nonce1.len(), NONCE_SIZE);
        assert_ne!(nonce1, nonce2); // Should be random
    }

    #[test]
    fn test_x25519_diffie_hellman() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let keypair1 = X25519KeyPair::from_seed(&seed1).unwrap();
        let keypair2 = X25519KeyPair::from_seed(&seed2).unwrap();

        let shared1 = keypair1.diffie_hellman(keypair2.public_key());
        let shared2 = keypair2.diffie_hellman(keypair1.public_key());

        assert_eq!(shared1, shared2);
    }
}
