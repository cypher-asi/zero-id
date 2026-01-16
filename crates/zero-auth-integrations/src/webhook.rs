//! Webhook signing and delivery implementation.

use crate::types::*;
use crate::{Error, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::Duration;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Sign webhook payload with HMAC-SHA256
///
/// # Format
/// Signature covers: `{event_id}.{timestamp}.{json_payload}`
///
/// # Arguments
/// * `event` - Revocation event
/// * `webhook_secret` - HMAC secret
///
/// # Returns
/// * Signature in format: `sha256=<hex>`
pub fn sign_webhook(event: &RevocationEvent, webhook_secret: &[u8; 32]) -> Result<String> {
    // Serialize event to JSON
    let json_payload = serde_json::to_string(event)
        .map_err(|e: serde_json::Error| Error::Serialization(e.to_string()))?;

    // Build signing payload: event_id.timestamp.json
    let payload = format!(
        "{}.{}.{}",
        event.event_id,
        event.timestamp,
        json_payload
    );

    // Compute HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(webhook_secret)
        .map_err(|e| Error::Other(format!("HMAC initialization failed: {}", e)))?;
    mac.update(payload.as_bytes());
    let result = mac.finalize();

    // Format as sha256=<hex>
    Ok(format!("sha256={}", hex::encode(result.into_bytes())))
}

/// Verify webhook signature (constant-time)
///
/// # Arguments
/// * `event` - Revocation event
/// * `signature` - Signature from X-ZeroAuth-Signature header
/// * `webhook_secret` - HMAC secret
///
/// # Returns
/// * true if signature is valid
pub fn verify_webhook_signature(
    event: &RevocationEvent,
    signature: &str,
    webhook_secret: &[u8; 32],
) -> bool {
    // Compute expected signature
    let expected = match sign_webhook(event, webhook_secret) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    // Constant-time comparison
    signature.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Deliver webhook with retry logic
pub async fn deliver_webhook(
    event: &RevocationEvent,
    webhook_config: &WebhookConfig,
) -> Result<DeliveryStatus> {
    // Sign payload
    let signature = sign_webhook(event, &webhook_config.secret)?;

    // Build HTTP client with timeout
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    // Send webhook POST request
    let response = client
        .post(&webhook_config.url)
        .header("Content-Type", "application/json")
        .header("X-ZeroAuth-Event-Id", event.event_id.to_string())
        .header("X-ZeroAuth-Signature", signature)
        .header("X-ZeroAuth-Timestamp", event.timestamp.to_string())
        .header("X-ZeroAuth-Sequence", event.sequence.to_string())
        .header("X-ZeroAuth-Event-Type", event.event_type.event_name())
        .json(event)
        .send()
        .await?;

    // Check response status
    let status = response.status();

    if status.is_success() {
        Ok(DeliveryStatus::Success)
    } else if status.is_client_error() {
        Ok(DeliveryStatus::ClientError)
    } else {
        Ok(DeliveryStatus::ServerError)
    }
}

/// Calculate next retry delay (exponential backoff)
///
/// # Formula
/// delay = BASE_DELAY * 2^(attempt - 1)
///
/// # Example
/// - Attempt 1: 60 seconds
/// - Attempt 2: 120 seconds (2 min)
/// - Attempt 3: 240 seconds (4 min)
/// - Attempt 4: 480 seconds (8 min)
/// - Attempt 5: 960 seconds (16 min)
/// - Attempt 6: 1920 seconds (32 min)
/// - Attempt 7: 3840 seconds (64 min)
pub fn calculate_retry_delay(attempt: u32) -> u64 {
    const BASE_DELAY_SECONDS: u64 = 60;
    BASE_DELAY_SECONDS * 2u64.pow(attempt.saturating_sub(1))
}

/// Check if webhook should be abandoned
///
/// # Abandonment Criteria
/// - After 7 attempts (max retries)
/// - Or after 7 days since first attempt
pub fn should_abandon_webhook(attempt: u32, first_attempt_at: u64, current_time: u64) -> bool {
    const MAX_ATTEMPTS: u32 = 7;
    const MAX_RETENTION_SECONDS: u64 = 7 * 24 * 3600; // 7 days

    attempt >= MAX_ATTEMPTS || (current_time - first_attempt_at) >= MAX_RETENTION_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn create_test_event() -> RevocationEvent {
        RevocationEvent {
            event_id: Uuid::new_v4(),
            event_type: EventType::MachineRevoked,
            namespace_id: Uuid::new_v4(),
            identity_id: Uuid::new_v4(),
            machine_id: Some(Uuid::new_v4()),
            session_id: None,
            sequence: 12345,
            timestamp: 1705320000,
            reason: "Test revocation".to_string(),
        }
    }

    #[test]
    fn test_webhook_signing() {
        let event = create_test_event();
        let secret = [0u8; 32];

        let signature = sign_webhook(&event, &secret).unwrap();
        assert!(signature.starts_with("sha256="));
        assert_eq!(signature.len(), 71); // "sha256=" + 64 hex chars
    }

    #[test]
    fn test_webhook_signature_verification() {
        let event = create_test_event();
        let secret = [0u8; 32];

        let signature = sign_webhook(&event, &secret).unwrap();
        assert!(verify_webhook_signature(&event, &signature, &secret));
    }

    #[test]
    fn test_webhook_signature_verification_fails_wrong_secret() {
        let event = create_test_event();
        let secret1 = [0u8; 32];
        let secret2 = [1u8; 32];

        let signature = sign_webhook(&event, &secret1).unwrap();
        assert!(!verify_webhook_signature(&event, &signature, &secret2));
    }

    #[test]
    fn test_webhook_signature_verification_fails_tampered_event() {
        let event = create_test_event();
        let secret = [0u8; 32];

        let signature = sign_webhook(&event, &secret).unwrap();

        // Tamper with event
        let mut tampered_event = event.clone();
        tampered_event.reason = "Tampered reason".to_string();

        assert!(!verify_webhook_signature(&tampered_event, &signature, &secret));
    }

    #[test]
    fn test_retry_delay_calculation() {
        assert_eq!(calculate_retry_delay(1), 60);      // 1 min
        assert_eq!(calculate_retry_delay(2), 120);     // 2 min
        assert_eq!(calculate_retry_delay(3), 240);     // 4 min
        assert_eq!(calculate_retry_delay(4), 480);     // 8 min
        assert_eq!(calculate_retry_delay(5), 960);     // 16 min
        assert_eq!(calculate_retry_delay(6), 1920);    // 32 min
        assert_eq!(calculate_retry_delay(7), 3840);    // 64 min
    }

    #[test]
    fn test_should_abandon_webhook_max_attempts() {
        let first_attempt = 1705320000;
        let current_time = first_attempt + 3600; // 1 hour later

        assert!(!should_abandon_webhook(1, first_attempt, current_time));
        assert!(!should_abandon_webhook(6, first_attempt, current_time));
        assert!(should_abandon_webhook(7, first_attempt, current_time));
        assert!(should_abandon_webhook(8, first_attempt, current_time));
    }

    #[test]
    fn test_should_abandon_webhook_max_retention() {
        let first_attempt = 1705320000;
        let seven_days = 7 * 24 * 3600;
        let current_time = first_attempt + seven_days;

        assert!(should_abandon_webhook(1, first_attempt, current_time));
        assert!(should_abandon_webhook(3, first_attempt, current_time));
    }

    #[test]
    fn test_event_type_names() {
        assert_eq!(EventType::MachineRevoked.event_name(), "machine.revoked");
        assert_eq!(EventType::SessionRevoked.event_name(), "session.revoked");
        assert_eq!(EventType::IdentityFrozen.event_name(), "identity.frozen");
        assert_eq!(EventType::IdentityDisabled.event_name(), "identity.disabled");
    }
}
