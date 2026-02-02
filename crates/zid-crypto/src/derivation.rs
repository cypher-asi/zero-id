//! Key derivation using HKDF-SHA256.
//!
//! All key derivations follow the specifications in cryptographic-constants.md § 3-7.
//!
//! # Post-Quantum Key Derivation
//!
//! Additional derivation functions are available for ML-DSA-65 and ML-KEM-768 keys:
//!
//! - `derive_machine_pq_signing_seed`: Derives 32-byte seed for ML-DSA-65
//! - `derive_machine_pq_kem_seed`: Derives 64-byte seed for ML-KEM-768
//! - `derive_machine_keypair_with_scheme`: Derives full key pair with scheme selection

use crate::{constants::*, errors::*, keys::*};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Derive a key using HKDF-SHA256
///
/// # Arguments
///
/// * `ikm` - Input key material
/// * `info` - Domain separation string and context
/// * `output_len` - Length of output key material (default 32 bytes)
///
/// # Returns
///
/// Derived key material of specified length
pub fn hkdf_derive(ikm: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hkdf = Hkdf::<Sha256>::new(None, ikm);
    let mut output = vec![0u8; output_len];

    hkdf.expand(info, &mut output)
        .map_err(|_| CryptoError::HkdfError)?;

    Ok(output)
}

/// Derive a 32-byte key using HKDF-SHA256
///
/// This is the most common case and returns a fixed-size array.
pub fn hkdf_derive_32(ikm: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    let output = hkdf_derive(ikm, info, 32)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(&output);
    Ok(key)
}

/// Derive Identity Signing Keypair from Neural Key
///
/// As specified in cryptographic-constants.md § 4.2
///
/// Formula: identity_signing_seed = HKDF(neural_key, "cypher:auth:identity:v1" || identity_id)
///          (private_key, public_key) = Ed25519_derive(identity_signing_seed)
///
/// The Identity Signing Key (formerly "central key") is used to sign identity-level
/// operations such as machine enrollments.
pub fn derive_identity_signing_keypair(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
) -> Result<([u8; 32], Ed25519KeyPair)> {
    // Build info: "cypher:auth:identity:v1" || identity_id
    let mut info = Vec::with_capacity(DOMAIN_IDENTITY_SIGNING.len() + 16);
    info.extend_from_slice(DOMAIN_IDENTITY_SIGNING.as_bytes());
    info.extend_from_slice(identity_id.as_bytes());

    // Derive signing seed
    let signing_seed = hkdf_derive_32(neural_key.as_bytes(), &info)?;

    // Generate Ed25519 keypair
    let keypair = Ed25519KeyPair::from_seed(&signing_seed)?;
    let public_key = keypair.public_key_bytes();

    Ok((public_key, keypair))
}

/// Derive Machine Key seed from Neural Key
///
/// As specified in cryptographic-constants.md § 5.3
///
/// Formula: machine_seed = HKDF(neural_key, "cypher:shared:machine:v1" || identity_id || machine_id || epoch)
pub fn derive_machine_seed(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
    machine_id: &uuid::Uuid,
    epoch: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:shared:machine:v1" || identity_id || machine_id || epoch
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_SEED.len() + 16 + 16 + 8);
    info.extend_from_slice(DOMAIN_MACHINE_SEED.as_bytes());
    info.extend_from_slice(identity_id.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());
    info.extend_from_slice(&epoch.to_be_bytes());

    let seed = hkdf_derive_32(neural_key.as_bytes(), &info)?;
    Ok(Zeroizing::new(seed))
}

/// Derive Machine Key signing seed from machine seed
///
/// As specified in cryptographic-constants.md § 5.3
///
/// Formula: signing_seed = HKDF(machine_seed, "cypher:shared:machine:sign:v1" || machine_id)
pub fn derive_machine_signing_seed(
    machine_seed: &[u8; 32],
    machine_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:shared:machine:sign:v1" || machine_id
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_SIGN.len() + 16);
    info.extend_from_slice(DOMAIN_MACHINE_SIGN.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());

    let seed = hkdf_derive_32(machine_seed, &info)?;
    Ok(Zeroizing::new(seed))
}

/// Derive Machine Key encryption seed from machine seed
///
/// As specified in cryptographic-constants.md § 5.3
///
/// Formula: encryption_seed = HKDF(machine_seed, "cypher:shared:machine:encrypt:v1" || machine_id)
pub fn derive_machine_encryption_seed(
    machine_seed: &[u8; 32],
    machine_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:shared:machine:encrypt:v1" || machine_id
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_ENCRYPT.len() + 16);
    info.extend_from_slice(DOMAIN_MACHINE_ENCRYPT.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());

    let seed = hkdf_derive_32(machine_seed, &info)?;
    Ok(Zeroizing::new(seed))
}

// =============================================================================
// Post-Quantum Key Derivation (requires "post-quantum" feature)
// =============================================================================

/// Derive ML-DSA-65 signing seed from machine seed
///
/// Formula: pq_signing_seed = HKDF(machine_seed, "cypher:shared:machine:pq-sign:v1" || machine_id)
///
/// # Arguments
///
/// * `machine_seed` - 32-byte machine seed derived from Neural Key
/// * `machine_id` - UUID of the machine
///
/// # Returns
///
/// 32-byte seed suitable for ML-DSA-65 key generation
pub fn derive_machine_pq_signing_seed(
    machine_seed: &[u8; 32],
    machine_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:shared:machine:pq-sign:v1" || machine_id
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_PQ_SIGN.len() + 16);
    info.extend_from_slice(DOMAIN_MACHINE_PQ_SIGN.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());

    let seed = hkdf_derive_32(machine_seed, &info)?;
    Ok(Zeroizing::new(seed))
}

/// Derive ML-KEM-768 encryption seed from machine seed
///
/// Formula: pq_kem_seed = HKDF(machine_seed, "cypher:shared:machine:pq-kem:v1" || machine_id, 64)
///
/// ML-KEM-768 requires a 64-byte seed (d || z) for deterministic key generation.
///
/// # Arguments
///
/// * `machine_seed` - 32-byte machine seed derived from Neural Key
/// * `machine_id` - UUID of the machine
///
/// # Returns
///
/// 64-byte seed suitable for ML-KEM-768 key generation
pub fn derive_machine_pq_kem_seed(
    machine_seed: &[u8; 32],
    machine_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; ML_KEM_768_SEED_SIZE]>> {
    // Build info: "cypher:shared:machine:pq-kem:v1" || machine_id
    let mut info = Vec::with_capacity(DOMAIN_MACHINE_PQ_KEM.len() + 16);
    info.extend_from_slice(DOMAIN_MACHINE_PQ_KEM.as_bytes());
    info.extend_from_slice(machine_id.as_bytes());

    // ML-KEM-768 needs 64 bytes (d || z)
    let seed_vec = hkdf_derive(machine_seed, &info, ML_KEM_768_SEED_SIZE)?;
    let mut seed = [0u8; ML_KEM_768_SEED_SIZE];
    seed.copy_from_slice(&seed_vec);
    Ok(Zeroizing::new(seed))
}

/// Derive complete Machine Key pair from Neural Key (Classical scheme)
///
/// This is the high-level function that combines all machine key derivation steps.
/// It derives only classical keys (Ed25519 + X25519) for backward compatibility.
///
/// For PQ-Hybrid scheme with post-quantum keys, use `derive_machine_keypair_with_scheme`.
///
/// As specified in cryptographic-constants.md § 5.3
pub fn derive_machine_keypair(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
    machine_id: &uuid::Uuid,
    epoch: u64,
    capabilities: MachineKeyCapabilities,
) -> Result<MachineKeyPair> {
    // Step 1: Derive machine seed
    let machine_seed = derive_machine_seed(neural_key, identity_id, machine_id, epoch)?;

    // Step 2: Derive signing seed
    let signing_seed = derive_machine_signing_seed(&machine_seed, machine_id)?;

    // Step 3: Derive encryption seed
    let encryption_seed = derive_machine_encryption_seed(&machine_seed, machine_id)?;

    // Step 4: Create keypair (Classical scheme)
    let machine_keypair =
        MachineKeyPair::from_seeds(&signing_seed, &encryption_seed, capabilities)?;

    Ok(machine_keypair)
}

/// Derive complete Machine Key pair with explicit scheme selection
///
/// This function supports both Classical and PqHybrid schemes:
///
/// - **Classical**: Derives Ed25519 + X25519 keys only
/// - **PqHybrid**: Derives classical keys plus ML-DSA-65 + ML-KEM-768
///
/// # Arguments
///
/// * `neural_key` - The root Neural Key
/// * `identity_id` - Identity UUID
/// * `machine_id` - Machine UUID
/// * `epoch` - Key epoch for rotation support
/// * `capabilities` - Machine key capabilities
/// * `scheme` - Key scheme (Classical or PqHybrid)
///
/// # Example
///
/// ```ignore
/// use zid_crypto::{NeuralKey, MachineKeyCapabilities, KeyScheme, derive_machine_keypair_with_scheme};
///
/// let neural_key = NeuralKey::generate()?;
/// let identity_id = uuid::Uuid::new_v4();
/// let machine_id = uuid::Uuid::new_v4();
///
/// // Derive with PqHybrid scheme for post-quantum protection
/// let keypair = derive_machine_keypair_with_scheme(
///     &neural_key,
///     &identity_id,
///     &machine_id,
///     1,
///     MachineKeyCapabilities::FULL_DEVICE,
///     KeyScheme::PqHybrid,
/// )?;
///
/// assert!(keypair.has_post_quantum_keys());
/// ```
pub fn derive_machine_keypair_with_scheme(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
    machine_id: &uuid::Uuid,
    epoch: u64,
    capabilities: MachineKeyCapabilities,
    scheme: KeyScheme,
) -> Result<MachineKeyPair> {
    // Step 1: Derive machine seed
    let machine_seed = derive_machine_seed(neural_key, identity_id, machine_id, epoch)?;

    // Step 2: Derive classical signing seed
    let signing_seed = derive_machine_signing_seed(&machine_seed, machine_id)?;

    // Step 3: Derive classical encryption seed
    let encryption_seed = derive_machine_encryption_seed(&machine_seed, machine_id)?;

    // Step 4: Derive PQ seeds if needed
    let (pq_signing_seed, pq_kem_seed) = match scheme {
        KeyScheme::Classical => (None, None),
        KeyScheme::PqHybrid => {
            let pq_sign_seed = derive_machine_pq_signing_seed(&machine_seed, machine_id)?;
            let pq_kem_seed = derive_machine_pq_kem_seed(&machine_seed, machine_id)?;
            (Some(pq_sign_seed), Some(pq_kem_seed))
        }
    };

    // Step 5: Create keypair with scheme
    let machine_keypair = MachineKeyPair::from_seeds_with_scheme(
        &signing_seed,
        &encryption_seed,
        pq_signing_seed.as_deref(),
        pq_kem_seed.as_deref(),
        capabilities,
        scheme,
    )?;

    Ok(machine_keypair)
}

/// Derive managed Identity Signing Keypair (server-side)
///
/// Used for managed identities where the ISK is deterministically derived from
/// the service master key and the authentication method used for signup.
///
/// Formula: identity_signing_seed = HKDF(service_master_key || method_type || method_id,
///                                       "cypher:managed:identity:v1")
///          (private_key, public_key) = Ed25519_derive(identity_signing_seed)
///
/// SECURITY: This key is deterministic from service master key.
/// The service operator can regenerate this key. Users should
/// upgrade to self-sovereign for full security.
///
/// # Arguments
///
/// * `service_master_key` - The service's master secret key (32 bytes)
/// * `method_type` - Authentication method type (e.g., "oauth:google", "email", "wallet:evm")
/// * `method_id` - Method-specific identifier (e.g., provider sub claim, email hash, wallet address)
///
/// # Returns
///
/// Tuple of (public_key bytes, Ed25519KeyPair)
pub fn derive_managed_identity_signing_keypair(
    service_master_key: &[u8; 32],
    method_type: &str,
    method_id: &str,
) -> Result<([u8; 32], Ed25519KeyPair)> {
    // Build IKM: service_master_key || method_type || method_id
    let mut ikm = Vec::with_capacity(32 + method_type.len() + method_id.len());
    ikm.extend_from_slice(service_master_key);
    ikm.extend_from_slice(method_type.as_bytes());
    ikm.extend_from_slice(method_id.as_bytes());

    // Derive signing seed using domain separation
    let signing_seed = hkdf_derive_32(&ikm, DOMAIN_MANAGED_IDENTITY.as_bytes())?;

    // Generate Ed25519 keypair from seed
    let keypair = Ed25519KeyPair::from_seed(&signing_seed)?;
    let public_key = keypair.public_key_bytes();

    Ok((public_key, keypair))
}

/// Derive MFA KEK from Neural Key
///
/// As specified in cryptographic-constants.md § 10.1
///
/// Formula: mfa_kek = HKDF(neural_key, "cypher:auth:mfa-kek:v1" || identity_id)
pub fn derive_mfa_kek(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:auth:mfa-kek:v1" || identity_id
    let mut info = Vec::with_capacity(DOMAIN_MFA_KEK.len() + 16);
    info.extend_from_slice(DOMAIN_MFA_KEK.as_bytes());
    info.extend_from_slice(identity_id.as_bytes());

    let kek = hkdf_derive_32(neural_key.as_bytes(), &info)?;
    Ok(Zeroizing::new(kek))
}

/// Derive JWT signing key seed from service master key
///
/// As specified in cryptographic-constants.md § 9.2
///
/// Formula: jwt_signing_seed = HKDF(service_master_key, "cypher:auth:jwt:v1" || key_epoch)
pub fn derive_jwt_signing_seed(
    service_master_key: &[u8; 32],
    key_epoch: u64,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:auth:jwt:v1" || key_epoch
    let mut info = Vec::with_capacity(DOMAIN_JWT_SIGNING.len() + 8);
    info.extend_from_slice(DOMAIN_JWT_SIGNING.as_bytes());
    info.extend_from_slice(&key_epoch.to_be_bytes());

    let seed = hkdf_derive_32(service_master_key, &info)?;
    Ok(Zeroizing::new(seed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive_is_deterministic() {
        let ikm = b"input key material";
        let info = b"domain:context:v1";

        let output1 = hkdf_derive(ikm, info, 32).unwrap();
        let output2 = hkdf_derive(ikm, info, 32).unwrap();

        assert_eq!(output1, output2);
    }

    #[test]
    fn test_hkdf_derive_different_info() {
        let ikm = b"input key material";
        let info1 = b"domain:context1:v1";
        let info2 = b"domain:context2:v1";

        let output1 = hkdf_derive(ikm, info1, 32).unwrap();
        let output2 = hkdf_derive(ikm, info2, 32).unwrap();

        assert_ne!(output1, output2);
    }

    #[test]
    fn test_hkdf_derive_32() {
        let ikm = b"input key material";
        let info = b"domain:context:v1";

        let output = hkdf_derive_32(ikm, info).unwrap();
        assert_eq!(output.len(), 32);
    }

    #[test]
    fn test_derive_identity_signing_keypair() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();

        let (public_key, keypair) = derive_identity_signing_keypair(&neural_key, &identity_id).unwrap();

        assert_eq!(public_key.len(), 32);
        assert_eq!(keypair.public_key_bytes(), public_key);
    }

    #[test]
    fn test_derive_machine_seed() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();
        let epoch = 1u64;

        let seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, epoch).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_derive_machine_seed_different_epochs() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let seed1 = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();
        let seed2 = derive_machine_seed(&neural_key, &identity_id, &machine_id, 2).unwrap();

        assert_ne!(*seed1, *seed2);
    }

    #[test]
    fn test_derive_complete_machine_keypair() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();
        let epoch = 1u64;

        let machine_key = derive_machine_keypair(
            &neural_key,
            &identity_id,
            &machine_id,
            epoch,
            MachineKeyCapabilities::FULL_DEVICE,
        )
        .unwrap();

        assert_eq!(machine_key.signing_public_key().len(), 32);
        assert_eq!(machine_key.encryption_public_key().len(), 32);
        assert_eq!(
            machine_key.capabilities(),
            MachineKeyCapabilities::FULL_DEVICE
        );
    }

    #[test]
    fn test_derive_mfa_kek() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();

        let kek = derive_mfa_kek(&neural_key, &identity_id).unwrap();
        assert_eq!(kek.len(), 32);
    }

    #[test]
    fn test_derive_jwt_signing_seed() {
        let service_master_key = [42u8; 32];
        let key_epoch = 1u64;

        let seed = derive_jwt_signing_seed(&service_master_key, key_epoch).unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_jwt_seed_different_epochs() {
        let service_master_key = [42u8; 32];

        let seed1 = derive_jwt_signing_seed(&service_master_key, 1).unwrap();
        let seed2 = derive_jwt_signing_seed(&service_master_key, 2).unwrap();

        assert_ne!(*seed1, *seed2);
    }

    #[test]
    fn test_derive_managed_identity_signing_keypair() {
        let service_master_key = [42u8; 32];
        let method_type = "oauth:google";
        let method_id = "google-user-123";

        let (public_key, keypair) =
            derive_managed_identity_signing_keypair(&service_master_key, method_type, method_id)
                .unwrap();

        assert_eq!(public_key.len(), 32);
        assert_eq!(keypair.public_key_bytes(), public_key);
    }

    #[test]
    fn test_managed_identity_derivation_is_deterministic() {
        let service_master_key = [42u8; 32];
        let method_type = "email";
        let method_id = "user@example.com";

        let (pk1, _) =
            derive_managed_identity_signing_keypair(&service_master_key, method_type, method_id)
                .unwrap();
        let (pk2, _) =
            derive_managed_identity_signing_keypair(&service_master_key, method_type, method_id)
                .unwrap();

        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_managed_identity_different_methods() {
        let service_master_key = [42u8; 32];

        let (pk_google, _) =
            derive_managed_identity_signing_keypair(&service_master_key, "oauth:google", "user-123")
                .unwrap();
        let (pk_email, _) =
            derive_managed_identity_signing_keypair(&service_master_key, "email", "user@test.com")
                .unwrap();
        let (pk_wallet, _) = derive_managed_identity_signing_keypair(
            &service_master_key,
            "wallet:evm",
            "0x1234567890123456789012345678901234567890",
        )
        .unwrap();

        assert_ne!(pk_google, pk_email);
        assert_ne!(pk_google, pk_wallet);
        assert_ne!(pk_email, pk_wallet);
    }

    #[test]
    fn test_derivations_use_correct_domains() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        // These should all produce different outputs due to domain separation
        let identity_signing_key = derive_identity_signing_keypair(&neural_key, &identity_id)
            .unwrap()
            .0;
        let mfa_kek = derive_mfa_kek(&neural_key, &identity_id).unwrap();
        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();

        // All should be different
        assert_ne!(identity_signing_key, *mfa_kek);
        assert_ne!(identity_signing_key, *machine_seed);
        assert_ne!(*mfa_kek, *machine_seed);
    }
}

#[cfg(test)]
mod pq_tests {
    use super::*;

    #[test]
    fn test_derive_machine_pq_signing_seed() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();
        let pq_signing_seed = derive_machine_pq_signing_seed(&machine_seed, &machine_id).unwrap();

        assert_eq!(pq_signing_seed.len(), 32);
    }

    #[test]
    fn test_derive_machine_pq_kem_seed() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();
        let pq_kem_seed = derive_machine_pq_kem_seed(&machine_seed, &machine_id).unwrap();

        assert_eq!(pq_kem_seed.len(), ML_KEM_768_SEED_SIZE);
    }

    #[test]
    fn test_pq_seeds_are_deterministic() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();

        let pq_sign_seed1 = derive_machine_pq_signing_seed(&machine_seed, &machine_id).unwrap();
        let pq_sign_seed2 = derive_machine_pq_signing_seed(&machine_seed, &machine_id).unwrap();
        assert_eq!(*pq_sign_seed1, *pq_sign_seed2);

        let pq_kem_seed1 = derive_machine_pq_kem_seed(&machine_seed, &machine_id).unwrap();
        let pq_kem_seed2 = derive_machine_pq_kem_seed(&machine_seed, &machine_id).unwrap();
        assert_eq!(*pq_kem_seed1, *pq_kem_seed2);
    }

    #[test]
    fn test_pq_seeds_differ_from_classical() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let machine_seed = derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();

        let signing_seed = derive_machine_signing_seed(&machine_seed, &machine_id).unwrap();
        let encryption_seed = derive_machine_encryption_seed(&machine_seed, &machine_id).unwrap();
        let pq_signing_seed = derive_machine_pq_signing_seed(&machine_seed, &machine_id).unwrap();
        let pq_kem_seed = derive_machine_pq_kem_seed(&machine_seed, &machine_id).unwrap();

        // All should be different due to domain separation
        assert_ne!(*signing_seed, *encryption_seed);
        assert_ne!(*signing_seed, *pq_signing_seed);
        assert_ne!(*encryption_seed, pq_kem_seed[0..32]);
    }

    #[test]
    fn test_derive_machine_keypair_with_scheme_classical() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let keypair = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::Classical,
        )
        .unwrap();

        assert_eq!(keypair.scheme(), KeyScheme::Classical);
        assert!(!keypair.has_post_quantum_keys());
        assert!(keypair.pq_signing_public_key().is_none());
        assert!(keypair.pq_encryption_public_key().is_none());
    }

    #[test]
    fn test_derive_machine_keypair_with_scheme_pq_hybrid() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let keypair = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        assert_eq!(keypair.scheme(), KeyScheme::PqHybrid);
        assert!(keypair.has_post_quantum_keys());

        // Classical keys should be present
        assert_eq!(keypair.signing_public_key().len(), 32);
        assert_eq!(keypair.encryption_public_key().len(), 32);

        // PQ keys should be present
        let pq_sign_pk = keypair.pq_signing_public_key().unwrap();
        assert_eq!(pq_sign_pk.len(), ML_DSA_65_PUBLIC_KEY_SIZE);

        let pq_enc_pk = keypair.pq_encryption_public_key().unwrap();
        assert_eq!(pq_enc_pk.len(), ML_KEM_768_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_pq_hybrid_derivation_is_deterministic() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let keypair1 = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        let keypair2 = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        // Classical keys should match
        assert_eq!(keypair1.signing_public_key(), keypair2.signing_public_key());
        assert_eq!(
            keypair1.encryption_public_key(),
            keypair2.encryption_public_key()
        );

        // PQ keys should match
        assert_eq!(
            keypair1.pq_signing_public_key(),
            keypair2.pq_signing_public_key()
        );
        assert_eq!(
            keypair1.pq_encryption_public_key(),
            keypair2.pq_encryption_public_key()
        );
    }

    #[test]
    fn test_different_epochs_produce_different_pq_keys() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        let keypair1 = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            1,
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        let keypair2 = derive_machine_keypair_with_scheme(
            &neural_key,
            &identity_id,
            &machine_id,
            2, // Different epoch
            MachineKeyCapabilities::FULL_DEVICE,
            KeyScheme::PqHybrid,
        )
        .unwrap();

        // Different epochs should produce different keys
        assert_ne!(
            keypair1.pq_signing_public_key(),
            keypair2.pq_signing_public_key()
        );
        assert_ne!(
            keypair1.pq_encryption_public_key(),
            keypair2.pq_encryption_public_key()
        );
    }
}
