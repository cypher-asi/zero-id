//! Type definitions for integrations subsystem.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Integration service registration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationService {
    /// Unique service ID
    pub service_id: Uuid,
    
    /// Human-readable service name
    pub service_name: String,
    
    /// SHA-256 fingerprint of client certificate
    pub client_cert_fingerprint: [u8; 32],
    
    /// Namespace filter (empty = all namespaces)
    pub namespace_filter: Vec<Uuid>,
    
    /// Permitted scopes
    pub scopes: Vec<Scope>,
    
    /// Webhook configuration (optional)
    pub webhook_config: Option<WebhookConfig>,
    
    /// Created timestamp
    pub created_at: u64,
    
    /// Last used timestamp
    pub last_used_at: Option<u64>,
    
    /// Whether service is revoked
    pub revoked: bool,
    
    /// Revoked timestamp
    pub revoked_at: Option<u64>,
}

/// Service scope (permissions)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u16)]
pub enum Scope {
    /// Receive machine revoked events
    EventsMachineRevoked = 0x0001,
    
    /// Receive session revoked events
    EventsSessionRevoked = 0x0002,
    
    /// Receive identity frozen events
    EventsIdentityFrozen = 0x0004,
    
    /// Token introspection
    AuthIntrospect = 0x0008,
}

/// Webhook configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookConfig {
    /// Webhook URL
    pub url: String,
    
    /// HMAC secret for webhook signing
    pub secret: [u8; 32],
    
    /// Whether webhook is enabled
    pub enabled: bool,
}

/// Revocation event
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RevocationEvent {
    /// Unique event ID
    pub event_id: Uuid,
    
    /// Event type
    pub event_type: EventType,
    
    /// Namespace ID
    pub namespace_id: Uuid,
    
    /// Identity ID
    pub identity_id: Uuid,
    
    /// Machine ID (for machine revoked events)
    pub machine_id: Option<Uuid>,
    
    /// Session ID (for session revoked events)
    pub session_id: Option<Uuid>,
    
    /// Monotonic sequence number per namespace
    pub sequence: u64,
    
    /// Event timestamp (Unix seconds)
    pub timestamp: u64,
    
    /// Human-readable reason
    pub reason: String,
}

/// Event type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum EventType {
    /// Machine key revoked
    MachineRevoked = 0x01,
    
    /// Session revoked
    SessionRevoked = 0x02,
    
    /// Identity frozen
    IdentityFrozen = 0x03,
    
    /// Identity disabled
    IdentityDisabled = 0x04,
}

impl EventType {
    /// Get event type name for SSE
    pub fn event_name(&self) -> &'static str {
        match self {
            EventType::MachineRevoked => "machine.revoked",
            EventType::SessionRevoked => "session.revoked",
            EventType::IdentityFrozen => "identity.frozen",
            EventType::IdentityDisabled => "identity.disabled",
        }
    }
}

/// Webhook delivery log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookDeliveryLog {
    /// Unique delivery ID
    pub delivery_id: Uuid,
    
    /// Service ID
    pub service_id: Uuid,
    
    /// Event ID
    pub event_id: Uuid,
    
    /// Attempt number (1-indexed)
    pub attempt: u32,
    
    /// Delivery status
    pub status: DeliveryStatus,
    
    /// Last attempt timestamp
    pub attempted_at: u64,
    
    /// Next attempt timestamp (for retries)
    pub next_attempt_at: Option<u64>,
    
    /// Abandoned timestamp (max retries reached)
    pub abandoned_at: Option<u64>,
    
    /// HTTP status code (if available)
    pub http_status: Option<u16>,
    
    /// Error message (if failed)
    pub error_message: Option<String>,
}

/// Webhook delivery status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum DeliveryStatus {
    /// Queued for delivery
    Queued = 0x01,
    
    /// Successfully delivered
    Success = 0x02,
    
    /// Client error (4xx)
    ClientError = 0x03,
    
    /// Server error (5xx)
    ServerError = 0x04,
    
    /// Retrying after failure
    Retrying = 0x05,
    
    /// Abandoned (max retries reached)
    Abandoned = 0x06,
}

/// Service registration request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterServiceRequest {
    /// Service name
    pub service_name: String,
    
    /// Client certificate fingerprint
    pub client_cert_fingerprint: [u8; 32],
    
    /// Namespace filter (empty = all)
    pub namespace_filter: Vec<Uuid>,
    
    /// Requested scopes
    pub scopes: Vec<Scope>,
    
    /// Webhook configuration (optional)
    pub webhook_config: Option<WebhookConfig>,
}

/// Certificate structure (simplified for now)
#[derive(Debug, Clone)]
pub struct Certificate {
    /// DER-encoded certificate bytes
    pub der_bytes: Vec<u8>,
    
    /// Not-after timestamp (Unix seconds)
    pub not_after: u64,
    
    /// Not-before timestamp (Unix seconds)
    pub not_before: u64,
}

impl Certificate {
    /// Get certificate fingerprint (SHA-256)
    pub fn fingerprint(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.der_bytes);
        hasher.finalize().into()
    }
}
