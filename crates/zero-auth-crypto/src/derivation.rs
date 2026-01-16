//! Key derivation using HKDF-SHA256.
//!
//! All key derivations follow the specifications in cryptographic-constants.md § 3-7.

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

/// Derive Central Public Key from Neural Key
///
/// As specified in cryptographic-constants.md § 4.2
///
/// Formula: identity_signing_seed = HKDF(neural_key, "cypher:auth:identity:v1" || identity_id)
///          (private_key, public_key) = Ed25519_derive(identity_signing_seed)
pub fn derive_central_public_key(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
) -> Result<([u8; 32], Ed25519KeyPair)> {
    // Build info: "cypher:auth:identity:v1" || identity_id
    let mut info = Vec::with_capacity(DOMAIN_IDENTITY.len() + 16);
    info.extend_from_slice(DOMAIN_IDENTITY.as_bytes());
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

/// Derive complete Machine Key pair from Neural Key
///
/// This is the high-level function that combines all machine key derivation steps.
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

    // Step 4: Create keypair
    let machine_keypair =
        MachineKeyPair::from_seeds(&signing_seed, &encryption_seed, capabilities)?;

    Ok(machine_keypair)
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

/// Derive backup KEK from Neural Key for recovery share encryption
///
/// As specified in cryptographic-constants.md § 3.5 Option 2
///
/// Formula: backup_kek = HKDF(neural_key, "cypher:share-backup-kek:v1" || identity_id)
pub fn derive_share_backup_kek(
    neural_key: &NeuralKey,
    identity_id: &uuid::Uuid,
) -> Result<Zeroizing<[u8; 32]>> {
    // Build info: "cypher:share-backup-kek:v1" || identity_id
    let mut info = Vec::with_capacity(DOMAIN_SHARE_BACKUP_KEK.len() + 16);
    info.extend_from_slice(DOMAIN_SHARE_BACKUP_KEK.as_bytes());
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
    fn test_derive_central_public_key() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();

        let (public_key, keypair) = derive_central_public_key(&neural_key, &identity_id).unwrap();

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
        assert_eq!(machine_key.capabilities(), MachineKeyCapabilities::FULL_DEVICE);
    }

    #[test]
    fn test_derive_mfa_kek() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();

        let kek = derive_mfa_kek(&neural_key, &identity_id).unwrap();
        assert_eq!(kek.len(), 32);
    }

    #[test]
    fn test_derive_share_backup_kek() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();

        let kek = derive_share_backup_kek(&neural_key, &identity_id).unwrap();
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
    fn test_derivations_use_correct_domains() {
        let neural_key = NeuralKey::generate().unwrap();
        let identity_id = uuid::Uuid::new_v4();
        let machine_id = uuid::Uuid::new_v4();

        // These should all produce different outputs due to domain separation
        let central_key = derive_central_public_key(&neural_key, &identity_id).unwrap().0;
        let mfa_kek = derive_mfa_kek(&neural_key, &identity_id).unwrap();
        let backup_kek = derive_share_backup_kek(&neural_key, &identity_id).unwrap();
        let machine_seed =
            derive_machine_seed(&neural_key, &identity_id, &machine_id, 1).unwrap();

        // All should be different
        assert_ne!(central_key, *mfa_kek);
        assert_ne!(central_key, *backup_kek);
        assert_ne!(central_key, *machine_seed);
        assert_ne!(*mfa_kek, *backup_kek);
        assert_ne!(*mfa_kek, *machine_seed);
        assert_ne!(*backup_kek, *machine_seed);
    }
}
