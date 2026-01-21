/*!
 * Local storage helpers for credentials and sessions
 *
 * # Security Model (2+1 Neural Shard Split)
 *
 * The Neural Key is split into 5 Neural Shards (3-of-5 threshold):
 * - 2 shards are stored encrypted on device (below threshold = cryptographically useless alone)
 * - 3 shards are given to the user
 *
 * To reconstruct the Neural Key:
 * - User provides passphrase (decrypts 2 stored shards)
 * - User provides 1 of their 3 shards
 * - 2 + 1 = 3 shards = threshold met
 *
 * Encryption uses:
 * - Argon2id (m=64MiB, t=3, p=4) to derive a 32-byte KEK from the user's passphrase
 * - XChaCha20-Poly1305 for authenticated encryption of each shard
 */

use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroize;
use zero_auth_crypto::{combine_shards, decrypt, encrypt, NeuralKey, NeuralShard};

use crate::types::{ClientCredentials, SessionData};

/// Argon2id parameters for KEK derivation
/// These match the server-side parameters from cryptographic-constants.md § 10
const ARGON2_M_COST: u32 = 65536; // 64 MiB
const ARGON2_T_COST: u32 = 3;
const ARGON2_P_COST: u32 = 4;

/// Domain separation for Neural Shard encryption
const SHARD_ENCRYPTION_DOMAIN: &[u8] = b"zero-auth:client:neural-shard-encryption:v1";

pub fn get_credentials_path() -> PathBuf {
    PathBuf::from("./.session/credentials.json")
}

pub fn get_session_path() -> PathBuf {
    PathBuf::from("./.session/session.json")
}

/// Derive a 32-byte KEK from a passphrase using Argon2id
fn derive_kek_from_passphrase(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(ARGON2_M_COST, ARGON2_T_COST, ARGON2_P_COST, Some(32))
        .map_err(|e| anyhow::anyhow!("Invalid Argon2 parameters: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut kek)
        .map_err(|e| anyhow::anyhow!("Argon2id key derivation failed: {}", e))?;

    Ok(kek)
}

/// Save credentials with 2 Neural Shards encrypted on device.
///
/// # Arguments
///
/// * `shards` - All 5 Neural Shards (shards 0-1 will be stored, 2-4 returned to user)
/// * `identity_id` - Identity UUID
/// * `machine_id` - Machine UUID
/// * `identity_signing_public_key` - Identity signing public key (hex-encoded)
/// * `machine_signing_public_key` - Machine signing public key (hex-encoded)
/// * `machine_encryption_public_key` - Machine encryption public key (hex-encoded)
/// * `device_name` - Human-readable device name
/// * `device_platform` - Platform identifier (e.g., "windows", "linux", "macos")
/// * `passphrase` - User-provided passphrase to derive KEK
///
/// # Returns
///
/// The 3 user shards that must be displayed and saved by the user.
#[allow(clippy::too_many_arguments)]
pub fn save_credentials_with_shards(
    shards: &[NeuralShard; 5],
    identity_id: uuid::Uuid,
    machine_id: uuid::Uuid,
    identity_signing_public_key: &str,
    machine_signing_public_key: &str,
    machine_encryption_public_key: &str,
    device_name: &str,
    device_platform: &str,
    passphrase: &str,
) -> Result<[NeuralShard; 3]> {
    use rand::RngCore;

    // Generate random salt (32 bytes)
    let mut salt = [0u8; 32];
    rand::thread_rng()
        .try_fill_bytes(&mut salt)
        .map_err(|e| anyhow::anyhow!("Failed to generate salt: {}", e))?;

    // Generate random nonce (24 bytes for XChaCha20)
    let mut nonce = [0u8; 24];
    rand::thread_rng()
        .try_fill_bytes(&mut nonce)
        .map_err(|e| anyhow::anyhow!("Failed to generate nonce: {}", e))?;

    // Derive KEK from passphrase
    let mut kek = derive_kek_from_passphrase(passphrase, &salt)?;

    // Encrypt shards 0 and 1 (stored on device)
    // Each shard is 33 bytes (1 byte index + 32 bytes data)
    let shard_1_bytes = shards[0].to_bytes();
    let shard_2_bytes = shards[1].to_bytes();

    let encrypted_shard_1 = encrypt(&kek, &shard_1_bytes, &nonce, SHARD_ENCRYPTION_DOMAIN)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt Neural Shard 1: {}", e))?;

    // Use a different nonce for second shard (increment last byte)
    let mut nonce_2 = nonce;
    nonce_2[23] = nonce_2[23].wrapping_add(1);

    let encrypted_shard_2 = encrypt(&kek, &shard_2_bytes, &nonce_2, SHARD_ENCRYPTION_DOMAIN)
        .map_err(|e| anyhow::anyhow!("Failed to encrypt Neural Shard 2: {}", e))?;

    // Zeroize KEK after use
    kek.zeroize();

    // Create credentials with encrypted shards
    let credentials = ClientCredentials {
        encrypted_shard_1,
        encrypted_shard_2,
        shards_nonce: nonce.to_vec(),
        kek_salt: salt.to_vec(),
        identity_id,
        machine_id,
        identity_signing_public_key: identity_signing_public_key.to_string(),
        machine_signing_public_key: machine_signing_public_key.to_string(),
        machine_encryption_public_key: machine_encryption_public_key.to_string(),
        device_name: device_name.to_string(),
        device_platform: device_platform.to_string(),
    };

    // Ensure the .session directory exists
    let path = get_credentials_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(&credentials)?;
    fs::write(path, json)?;

    // Return the 3 user shards (indices 2, 3, 4)
    Ok([shards[2].clone(), shards[3].clone(), shards[4].clone()])
}

/// Load credentials and reconstruct the Neural Key from 2 stored shards + 1 user shard.
///
/// # Arguments
///
/// * `passphrase` - User-provided passphrase to derive KEK and decrypt stored shards
/// * `user_shard` - One of the user's 3 Neural Shards
///
/// # Returns
///
/// Tuple of (NeuralKey, ClientCredentials)
pub fn load_and_reconstruct_neural_key(
    passphrase: &str,
    user_shard: &NeuralShard,
) -> Result<(NeuralKey, ClientCredentials)> {
    let json = fs::read_to_string(get_credentials_path())
        .context("Failed to load credentials. Run 'create-identity' first.")?;
    let credentials: ClientCredentials = serde_json::from_str(&json)?;

    // Derive KEK from passphrase using stored salt
    let mut kek = derive_kek_from_passphrase(passphrase, &credentials.kek_salt)?;

    // Convert nonce to fixed-size array
    let nonce: [u8; 24] = credentials
        .shards_nonce
        .as_slice()
        .try_into()
        .context("Invalid nonce length")?;

    // Decrypt shard 1
    let decrypted_shard_1_bytes = decrypt(
        &kek,
        &credentials.encrypted_shard_1,
        &nonce,
        SHARD_ENCRYPTION_DOMAIN,
    )
    .map_err(|_| anyhow::anyhow!("Failed to decrypt Neural Shard 1. Wrong passphrase?"))?;

    // Decrypt shard 2 (uses incremented nonce)
    let mut nonce_2 = nonce;
    nonce_2[23] = nonce_2[23].wrapping_add(1);

    let decrypted_shard_2_bytes = decrypt(
        &kek,
        &credentials.encrypted_shard_2,
        &nonce_2,
        SHARD_ENCRYPTION_DOMAIN,
    )
    .map_err(|_| anyhow::anyhow!("Failed to decrypt Neural Shard 2. Wrong passphrase?"))?;

    // Zeroize KEK after use
    kek.zeroize();

    // Parse decrypted bytes back into NeuralShard
    let shard_1 = NeuralShard::from_bytes(&decrypted_shard_1_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Neural Shard 1 format: {}", e))?;
    let shard_2 = NeuralShard::from_bytes(&decrypted_shard_2_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid Neural Shard 2 format: {}", e))?;

    // Combine 3 shards to reconstruct Neural Key
    let shards = [shard_1, shard_2, user_shard.clone()];
    let neural_key = combine_shards(&shards)
        .map_err(|e| anyhow::anyhow!("Failed to reconstruct Neural Key: {}", e))?;

    Ok((neural_key, credentials))
}

/// Load credentials without decryption (for operations that don't need the Neural Key)
pub fn load_credentials() -> Result<ClientCredentials> {
    let json = fs::read_to_string(get_credentials_path())
        .context("Failed to load credentials. Run 'create-identity' first.")?;
    let credentials = serde_json::from_str(&json)?;
    Ok(credentials)
}

/// Prompt user for passphrase (hidden input)
pub fn prompt_passphrase(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("Failed to read passphrase")
}

/// Prompt user for passphrase with confirmation (for new credentials)
pub fn prompt_new_passphrase() -> Result<String> {
    loop {
        let passphrase = prompt_passphrase("Enter passphrase to protect your credentials: ")?;

        if passphrase.len() < 8 {
            println!("Passphrase must be at least 8 characters. Please try again.");
            continue;
        }

        let confirm = prompt_passphrase("Confirm passphrase: ")?;

        if passphrase != confirm {
            println!("Passphrases do not match. Please try again.");
            continue;
        }

        return Ok(passphrase);
    }
}

/// Prompt user to enter one of their Neural Shards (hex format)
pub fn prompt_neural_shard() -> Result<NeuralShard> {
    use std::io::{self, Write};

    print!("Enter one of your Neural Shards: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim();

    NeuralShard::from_hex(input).map_err(|e| anyhow::anyhow!("Invalid Neural Shard format: {}", e))
}

pub fn save_session(session: &SessionData) -> Result<()> {
    let path = get_session_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(session)?;
    fs::write(path, json)?;
    Ok(())
}

pub fn load_session() -> Result<SessionData> {
    let json = fs::read_to_string(get_session_path())
        .context("Failed to load session. Run 'login' first.")?;
    let session = serde_json::from_str(&json)?;
    Ok(session)
}
