//! Challenge generation and management.

use crate::types::*;
use rand::Rng;
use uuid::Uuid;

/// Challenge expiry time in seconds (60 seconds)
pub const CHALLENGE_EXPIRY_SECONDS: u64 = 60;

/// Default audience for challenges
pub const DEFAULT_AUDIENCE: &str = "zero-auth.cypher.io";

/// Generate a new challenge
pub fn generate_challenge(machine_id: Uuid, purpose: Option<String>) -> Challenge {
    let now = current_timestamp();
    let mut rng = rand::thread_rng();
    let mut nonce = [0u8; 32];
    rng.fill(&mut nonce);

    Challenge {
        challenge_id: Uuid::new_v4(),
        entity_id: machine_id,
        entity_type: EntityType::Machine,
        purpose: purpose.unwrap_or_else(|| "machine_auth".to_string()),
        aud: DEFAULT_AUDIENCE.to_string(),
        iat: now,
        exp: now + CHALLENGE_EXPIRY_SECONDS,
        nonce,
        used: false,
    }
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

/// Check if challenge is expired
pub fn is_challenge_expired(challenge: &Challenge) -> bool {
    current_timestamp() >= challenge.exp
}

/// Get current timestamp (Unix seconds)
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let machine_id = Uuid::new_v4();
        let challenge = generate_challenge(machine_id, None);

        assert_eq!(challenge.entity_id, machine_id);
        assert_eq!(challenge.entity_type, EntityType::Machine);
        assert_eq!(challenge.purpose, "machine_auth");
        assert_eq!(challenge.aud, DEFAULT_AUDIENCE);
        assert!(!challenge.used);
        assert!(challenge.exp > challenge.iat);
        assert_eq!(challenge.exp - challenge.iat, CHALLENGE_EXPIRY_SECONDS);
    }

    #[test]
    fn test_canonicalize_challenge() {
        let machine_id = Uuid::new_v4();
        let challenge = Challenge {
            challenge_id: Uuid::new_v4(),
            entity_id: machine_id,
            entity_type: EntityType::Machine,
            purpose: "machine_auth".to_string(),
            aud: DEFAULT_AUDIENCE.to_string(),
            iat: 1700000000,
            exp: 1700000060,
            nonce: [0x42; 32],
            used: false,
        };

        let canonical = canonicalize_challenge(&challenge);

        // Verify structure
        assert_eq!(canonical.len(), 130);
        assert_eq!(canonical[0], 0x01); // Version
        assert_eq!(&canonical[1..17], challenge.challenge_id.as_bytes());
        assert_eq!(&canonical[17..33], challenge.entity_id.as_bytes());
        assert_eq!(canonical[33], EntityType::Machine as u8);
    }

    #[test]
    fn test_challenge_expiry() {
        let machine_id = Uuid::new_v4();
        let mut challenge = generate_challenge(machine_id, None);

        // Fresh challenge should not be expired
        assert!(!is_challenge_expired(&challenge));

        // Set expiry to past
        challenge.exp = current_timestamp() - 10;
        assert!(is_challenge_expired(&challenge));
    }

    #[test]
    fn test_canonicalize_deterministic() {
        let machine_id = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap();
        let challenge_id = Uuid::parse_str("660f9511-f3ac-52e5-b827-557766551111").unwrap();

        let challenge = Challenge {
            challenge_id,
            entity_id: machine_id,
            entity_type: EntityType::Machine,
            purpose: "machine_auth".to_string(),
            aud: "zero-auth.cypher.io".to_string(),
            iat: 1700000000,
            exp: 1700000060,
            nonce: [0x01; 32],
            used: false,
        };

        let canonical1 = canonicalize_challenge(&challenge);
        let canonical2 = canonicalize_challenge(&challenge);

        // Same input should produce same output
        assert_eq!(canonical1, canonical2);
    }
}
