//! Shared API helper functions.

use crate::error::ApiError;
use zero_auth_crypto::{blake3_hash, MachineKeyCapabilities};
use zero_auth_methods::OAuthProvider;

/// Parse a hex string into a 32-byte array
pub fn parse_hex_32(hex_str: &str) -> Result<[u8; 32], ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
    if bytes.len() != 32 {
        return Err(ApiError::InvalidRequest("Expected 32 bytes".to_string()));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Parse a hex string into a 64-byte array
pub fn parse_hex_64(hex_str: &str) -> Result<[u8; 64], ApiError> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| ApiError::InvalidRequest("Invalid hex encoding".to_string()))?;
    if bytes.len() != 64 {
        return Err(ApiError::InvalidRequest("Expected 64 bytes".to_string()));
    }
    let mut array = [0u8; 64];
    array.copy_from_slice(&bytes);
    Ok(array)
}

/// Parse capability strings into MachineKeyCapabilities bitflags
pub fn parse_capabilities(caps: &[String]) -> Result<MachineKeyCapabilities, ApiError> {
    let mut result = MachineKeyCapabilities::empty();
    for s in caps {
        match s.as_str() {
            "FULL_DEVICE" => result |= MachineKeyCapabilities::FULL_DEVICE,
            "AUTHENTICATE" => result |= MachineKeyCapabilities::AUTHENTICATE,
            "SIGN" => result |= MachineKeyCapabilities::SIGN,
            "ENCRYPT" => result |= MachineKeyCapabilities::ENCRYPT,
            "SVK_UNWRAP" => result |= MachineKeyCapabilities::SVK_UNWRAP,
            "MLS_MESSAGING" => result |= MachineKeyCapabilities::MLS_MESSAGING,
            "VAULT_OPERATIONS" => result |= MachineKeyCapabilities::VAULT_OPERATIONS,
            "SERVICE_MACHINE" => result |= MachineKeyCapabilities::SERVICE_MACHINE,
            _ => {
                return Err(ApiError::InvalidRequest(format!(
                    "Invalid capability: {}",
                    s
                )))
            }
        }
    }
    Ok(result)
}

/// Format a unix timestamp (seconds) as RFC3339.
pub fn format_timestamp_rfc3339(timestamp: u64) -> Result<String, ApiError> {
    Ok(chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("Invalid timestamp")))?
        .to_rfc3339())
}

pub fn parse_oauth_provider(provider_str: &str) -> Result<OAuthProvider, ApiError> {
    match provider_str.to_lowercase().as_str() {
        "google" => Ok(OAuthProvider::Google),
        "x" | "twitter" => Ok(OAuthProvider::X),
        "epic" => Ok(OAuthProvider::EpicGames),
        _ => Err(ApiError::InvalidRequest(format!(
            "Unknown OAuth provider: {}",
            provider_str
        ))),
    }
}

pub fn hash_for_log(value: &str) -> String {
    let hash = blake3_hash(value.as_bytes());
    hex::encode(&hash[..8])
}
