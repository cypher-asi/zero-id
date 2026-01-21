/*!
 * Type definitions for zero-auth client
 */

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Client credentials stored locally with 2 encrypted Neural Shards.
///
/// # Security Model (2+1 Neural Shard Split)
///
/// The Neural Key is split into 5 Neural Shards (3-of-5 threshold):
/// - 2 shards are stored here, encrypted with a user passphrase
/// - 3 shards are given to the user at identity creation
///
/// To reconstruct the Neural Key for login:
/// - User provides passphrase (decrypts stored 2 shards)
/// - User provides 1 of their 3 shards
/// - 2 + 1 = 3 shards = threshold met
///
/// **Key security property:** Even if the device is stolen AND the passphrase
/// is cracked, the attacker only gets 2 shards which reveal nothing about
/// the Neural Key (Shamir's information-theoretic security).
///
/// The Neural Key is NEVER stored whole, not even encrypted.
#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ClientCredentials {
    /// Encrypted Neural Shard 1 (XChaCha20-Poly1305 ciphertext + 16-byte tag)
    #[serde(with = "hex_serde")]
    pub encrypted_shard_1: Vec<u8>,
    /// Encrypted Neural Shard 2 (XChaCha20-Poly1305 ciphertext + 16-byte tag)
    #[serde(with = "hex_serde")]
    pub encrypted_shard_2: Vec<u8>,
    /// Nonce used for shard encryption (24 bytes for XChaCha20)
    #[serde(with = "hex_serde")]
    pub shards_nonce: Vec<u8>,
    /// Salt used for Argon2id key derivation (32 bytes)
    #[serde(with = "hex_serde")]
    pub kek_salt: Vec<u8>,
    /// Identity ID (not sensitive, skipped from zeroization)
    #[zeroize(skip)]
    pub identity_id: Uuid,
    /// Machine ID (not sensitive, skipped from zeroization)
    #[zeroize(skip)]
    pub machine_id: Uuid,
    pub identity_signing_public_key: String,
    pub machine_signing_public_key: String,
    pub machine_encryption_public_key: String,
    pub device_name: String,
    pub device_platform: String,
}

/// Session data stored after login
///
/// Contains sensitive tokens that are zeroized when dropped.
#[derive(Serialize, Deserialize, Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionData {
    pub access_token: String,
    pub refresh_token: String,
    /// Session ID (not sensitive, skipped from zeroization)
    #[zeroize(skip)]
    pub session_id: Uuid,
    pub expires_at: String,
}

/// Helper module for hex serialization of byte vectors
mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

// API Response types
#[derive(Deserialize, Debug)]
pub struct CreateIdentityResponse {
    pub identity_id: Uuid,
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub created_at: String,
}

#[derive(Deserialize, Debug)]
pub struct ChallengeResponse {
    pub challenge_id: Uuid,
    pub challenge: String,
    pub expires_at: String,
}

#[derive(Deserialize, Debug)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub session_id: Uuid,
    pub machine_id: Uuid,
    pub expires_at: String,
    pub warning: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct IntrospectResponse {
    pub active: bool,
    pub identity_id: Option<Uuid>,
    pub machine_id: Option<Uuid>,
    pub mfa_verified: Option<bool>,
    pub capabilities: Option<Vec<String>>,
    #[allow(dead_code)] // Deserialized by clients that need revocation data.
    pub revocation_epoch: Option<u32>,
    pub exp: Option<i64>,
}

#[derive(Deserialize, Debug)]
pub struct RefreshResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: String,
}

#[derive(Deserialize, Debug)]
pub struct AddCredentialResponse {
    pub message: String,
}

#[derive(Deserialize, Debug)]
pub struct EnrollMachineResponse {
    pub machine_id: Uuid,
    pub namespace_id: Uuid,
    pub enrolled_at: String,
}

#[derive(Deserialize, Debug)]
pub struct ListMachinesResponse {
    pub machines: Vec<MachineInfo>,
}

#[derive(Deserialize, Debug)]
pub struct MachineInfo {
    pub machine_id: Uuid,
    pub device_name: String,
    pub device_platform: String,
    pub created_at: String,
    pub last_used_at: Option<String>,
    pub revoked: bool,
}
