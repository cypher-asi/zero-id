//! Identity Core type definitions.

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zero_auth_crypto::MachineKeyCapabilities;

/// Identity status
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    Active = 0x01,
    Disabled = 0x02,
    Frozen = 0x03,
    Deleted = 0x04,
}

/// Identity record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Identity {
    pub identity_id: Uuid,
    pub identity_signing_public_key: [u8; 32],
    pub status: IdentityStatus,
    pub created_at: u64,
    pub updated_at: u64,
    pub frozen_at: Option<u64>,
    pub frozen_reason: Option<String>,
}

/// Machine Key record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineKey {
    pub machine_id: Uuid,
    pub identity_id: Uuid,
    pub namespace_id: Uuid,
    pub signing_public_key: [u8; 32],
    pub encryption_public_key: [u8; 32],
    pub capabilities: MachineKeyCapabilities,
    pub epoch: u64,
    pub created_at: u64,
    pub expires_at: Option<u64>,
    pub last_used_at: Option<u64>,
    pub device_name: String,
    pub device_platform: String,
    pub revoked: bool,
    pub revoked_at: Option<u64>,
}

/// Namespace record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Namespace {
    pub namespace_id: Uuid,
    pub name: String,
    pub created_at: u64,
    pub owner_identity_id: Uuid,
    pub active: bool,
}

/// Namespace role
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamespaceRole {
    Owner = 0x01,
    Admin = 0x02,
    Member = 0x03,
}

/// Identity namespace membership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityNamespaceMembership {
    pub identity_id: Uuid,
    pub namespace_id: Uuid,
    pub role: NamespaceRole,
    pub joined_at: u64,
}

/// Create identity request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateIdentityRequest {
    pub identity_id: Uuid,
    pub identity_signing_public_key: [u8; 32],
    pub machine_key: MachineKey,
    pub authorization_signature: Vec<u8>,
    pub namespace_name: Option<String>,
    pub created_at: u64,
}

/// Approval for sensitive operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub machine_id: Uuid,
    pub signature: Vec<u8>,
    pub timestamp: u64,
}

/// Rotation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationRequest {
    pub identity_id: Uuid,
    pub new_identity_signing_public_key: [u8; 32],
    pub approvals: Vec<Approval>,
    pub new_machines: Vec<MachineKey>,
}

/// Freeze reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FreezeReason {
    SecurityIncident,
    SuspiciousActivity,
    UserRequested,
    Administrative,
}

impl std::fmt::Display for FreezeReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            FreezeReason::SecurityIncident => "security_incident",
            FreezeReason::SuspiciousActivity => "suspicious_activity",
            FreezeReason::UserRequested => "user_requested",
            FreezeReason::Administrative => "administrative",
        };
        write!(f, "{}", s)
    }
}

/// Revocation event type
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    MachineRevoked = 0x01,
    SessionRevoked = 0x02,
    IdentityFrozen = 0x03,
    IdentityDisabled = 0x04,
}

/// Revocation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEvent {
    pub event_id: Uuid,
    pub event_type: EventType,
    pub namespace_id: Uuid,
    pub identity_id: Uuid,
    pub machine_id: Option<Uuid>,
    pub session_id: Option<Uuid>,
    pub sequence: u64,
    pub timestamp: u64,
    pub reason: String,
}

// Re-export current_timestamp from zero-auth-crypto
pub use zero_auth_crypto::current_timestamp;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_status_values() {
        assert_eq!(IdentityStatus::Active as u8, 0x01);
        assert_eq!(IdentityStatus::Disabled as u8, 0x02);
        assert_eq!(IdentityStatus::Frozen as u8, 0x03);
        assert_eq!(IdentityStatus::Deleted as u8, 0x04);
    }

    #[test]
    fn test_namespace_role_values() {
        assert_eq!(NamespaceRole::Owner as u8, 0x01);
        assert_eq!(NamespaceRole::Admin as u8, 0x02);
        assert_eq!(NamespaceRole::Member as u8, 0x03);
    }

    #[test]
    fn test_freeze_reason_to_string() {
        assert_eq!(
            FreezeReason::SecurityIncident.to_string(),
            "security_incident"
        );
        assert_eq!(
            FreezeReason::SuspiciousActivity.to_string(),
            "suspicious_activity"
        );
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts > 1700000000); // Should be after 2023
    }
}
