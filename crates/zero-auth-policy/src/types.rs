//! Policy engine type definitions.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Identity status for policy evaluation
///
/// Note: This mirrors the IdentityStatus in identity-core to avoid
/// circular dependencies. The caller must convert when building PolicyContext.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdentityStatus {
    Active = 0x01,
    Disabled = 0x02,
    Frozen = 0x03,
    Deleted = 0x04,
}

/// Policy evaluation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    // Identity & Auth
    pub identity_id: Uuid,
    pub machine_id: Option<Uuid>,
    pub namespace_id: Uuid,
    pub auth_method: AuthMethod,
    pub mfa_verified: bool,

    // Operation
    pub operation: Operation,
    pub resource: Option<Resource>,

    // Request Context
    pub ip_address: String,
    pub user_agent: String,
    pub timestamp: u64,

    // Reputation
    pub reputation_score: i32, // -100 to +100
    pub recent_failed_attempts: u32,

    // Entity States (populated by caller via context enrichment)
    /// Identity status - if None, check is skipped
    pub identity_status: Option<IdentityStatus>,
    /// Whether the machine key has been revoked
    pub machine_revoked: Option<bool>,
    /// Machine key capabilities as bitflags
    pub machine_capabilities: Option<u32>,
    /// Whether the namespace is active
    pub namespace_active: Option<bool>,
}

/// Reputation record for persistent storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationRecord {
    pub identity_id: Uuid,
    pub score: i32,
    pub successful_attempts: u32,
    pub failed_attempts: u32,
    pub last_updated: u64,
}

/// Rate limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// IP rate limit window in seconds
    pub ip_window_seconds: u64,
    /// Maximum requests per IP window
    pub ip_max_requests: u32,
    /// Identity rate limit window in seconds
    pub identity_window_seconds: u64,
    /// Maximum requests per identity window
    pub identity_max_requests: u32,
    /// Failure tracking window in seconds
    pub failure_window_seconds: u64,
    /// Maximum failed attempts before lockout
    pub failure_max_attempts: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            ip_window_seconds: 60,
            ip_max_requests: 100,
            identity_window_seconds: 3600,
            identity_max_requests: 1000,
            failure_window_seconds: 900, // 15 minutes
            failure_max_attempts: 5,
        }
    }
}

/// Policy decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDecision {
    pub verdict: Verdict,
    pub required_factors: Vec<AuthFactor>,
    pub required_approvals: u8,
    pub rate_limit: Option<RateLimit>,
    pub audit_tags: Vec<String>,
    pub reason: String,
}

/// Policy verdict
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow = 0x01,
    Deny = 0x02,
    RequireAdditionalAuth = 0x03,
    RequireApproval = 0x04,
    RateLimited = 0x05,
}

/// Authentication method
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    MachineKey = 0x01,
    EmailPassword = 0x02,
    OAuth = 0x03,
    EvmWallet = 0x04,
}

/// Authentication factor
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthFactor {
    Password = 0x01,
    MfaTotp = 0x02,
    MfaBackupCode = 0x03,
    MachineKey = 0x04,
    WalletSignature = 0x05,
    EmailVerification = 0x06,
}

/// Operation types
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Operation {
    // Authentication
    Login = 0x0100,
    RefreshToken = 0x0101,

    // Identity Management
    CreateIdentity = 0x0200,
    DisableIdentity = 0x0201,
    FreezeIdentity = 0x0202,
    UnfreezeIdentity = 0x0203,

    // Machine Keys
    EnrollMachine = 0x0300,
    RevokeMachine = 0x0301,

    // Neural Key
    RotateNeuralKey = 0x0400,
    RecoverNeuralKey = 0x0401,
    InitiateRecovery = 0x0402,

    // Credentials
    ChangePassword = 0x0500,
    ResetPassword = 0x0501,
    AttachEmail = 0x0502,
    AttachWallet = 0x0503,

    // MFA
    EnableMfa = 0x0600,
    DisableMfa = 0x0601,
    VerifyMfa = 0x0602,

    // Sessions
    RevokeSession = 0x0700,
    RevokeAllSessions = 0x0701,
}

/// Resource being accessed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Resource {
    Identity(Uuid),
    Machine(Uuid),
    Session(Uuid),
    Namespace(Uuid),
}

/// Rate limit info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    pub window_seconds: u64,
    pub max_attempts: u32,
    pub remaining: u32,
    pub reset_at: u64,
}

/// Machine key capability bitflags (mirrors zero-auth-crypto::MachineKeyCapabilities)
pub mod capabilities {
    /// Can authenticate (sign challenges)
    pub const AUTHENTICATE: u32 = 0x01;
    /// Can sign messages
    pub const SIGN: u32 = 0x02;
    /// Can decrypt messages
    pub const DECRYPT: u32 = 0x04;
    /// Can enroll new machines
    pub const ENROLL: u32 = 0x08;
    /// Can revoke other machines
    pub const REVOKE: u32 = 0x10;
    /// Can approve sensitive operations
    pub const APPROVE: u32 = 0x20;
}

impl Operation {
    /// Check if operation is high-risk
    pub fn is_high_risk(&self) -> bool {
        matches!(
            self,
            Operation::DisableIdentity
                | Operation::FreezeIdentity
                | Operation::RotateNeuralKey
                | Operation::DisableMfa
                | Operation::RevokeAllSessions
        )
    }

    /// Check if operation requires MFA
    pub fn requires_mfa(&self) -> bool {
        matches!(
            self,
            Operation::DisableIdentity
                | Operation::RotateNeuralKey
                | Operation::DisableMfa
                | Operation::ChangePassword
                | Operation::RevokeAllSessions
        )
    }

    /// Get required approval count
    pub fn required_approvals(&self) -> u8 {
        match self {
            Operation::RotateNeuralKey => 2,
            Operation::UnfreezeIdentity => 2,
            _ => 0,
        }
    }

    /// Get required machine capabilities for this operation
    ///
    /// Returns a bitflag of required capabilities. If the machine doesn't
    /// have all required capabilities, the operation should be denied.
    pub fn required_capabilities(&self) -> u32 {
        use capabilities::*;
        match self {
            // Authentication operations
            Operation::Login | Operation::RefreshToken => AUTHENTICATE,

            // Identity management
            Operation::CreateIdentity => AUTHENTICATE | SIGN,
            Operation::DisableIdentity => AUTHENTICATE | SIGN,
            Operation::FreezeIdentity => AUTHENTICATE | SIGN,
            Operation::UnfreezeIdentity => AUTHENTICATE | SIGN | APPROVE,

            // Machine key operations
            Operation::EnrollMachine => AUTHENTICATE | SIGN | ENROLL,
            Operation::RevokeMachine => AUTHENTICATE | SIGN | REVOKE,

            // Neural key operations (highly sensitive)
            Operation::RotateNeuralKey => AUTHENTICATE | SIGN | APPROVE,
            Operation::RecoverNeuralKey => AUTHENTICATE | SIGN | APPROVE,
            Operation::InitiateRecovery => AUTHENTICATE,

            // Credential operations
            Operation::ChangePassword => AUTHENTICATE | SIGN,
            Operation::ResetPassword => AUTHENTICATE,
            Operation::AttachEmail => AUTHENTICATE | SIGN,
            Operation::AttachWallet => AUTHENTICATE | SIGN,

            // MFA operations
            Operation::EnableMfa => AUTHENTICATE | SIGN,
            Operation::DisableMfa => AUTHENTICATE | SIGN,
            Operation::VerifyMfa => AUTHENTICATE,

            // Session operations
            Operation::RevokeSession => AUTHENTICATE | SIGN,
            Operation::RevokeAllSessions => AUTHENTICATE | SIGN | REVOKE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_operation_is_high_risk() {
        assert!(Operation::RotateNeuralKey.is_high_risk());
        assert!(Operation::DisableIdentity.is_high_risk());
        assert!(!Operation::Login.is_high_risk());
        assert!(!Operation::EnrollMachine.is_high_risk());
    }

    #[test]
    fn test_operation_requires_mfa() {
        assert!(Operation::RotateNeuralKey.requires_mfa());
        assert!(Operation::ChangePassword.requires_mfa());
        assert!(!Operation::Login.requires_mfa());
        assert!(!Operation::EnrollMachine.requires_mfa());
    }

    #[test]
    fn test_operation_required_approvals() {
        assert_eq!(Operation::RotateNeuralKey.required_approvals(), 2);
        assert_eq!(Operation::UnfreezeIdentity.required_approvals(), 2);
        assert_eq!(Operation::Login.required_approvals(), 0);
    }

    #[test]
    fn test_operation_required_capabilities() {
        use capabilities::*;

        // Login only requires AUTHENTICATE
        assert_eq!(Operation::Login.required_capabilities(), AUTHENTICATE);

        // EnrollMachine requires AUTHENTICATE | SIGN | ENROLL
        let enroll_caps = Operation::EnrollMachine.required_capabilities();
        assert!(enroll_caps & AUTHENTICATE != 0);
        assert!(enroll_caps & SIGN != 0);
        assert!(enroll_caps & ENROLL != 0);

        // RevokeMachine requires AUTHENTICATE | SIGN | REVOKE
        let revoke_caps = Operation::RevokeMachine.required_capabilities();
        assert!(revoke_caps & AUTHENTICATE != 0);
        assert!(revoke_caps & SIGN != 0);
        assert!(revoke_caps & REVOKE != 0);

        // RotateNeuralKey requires APPROVE
        let rotate_caps = Operation::RotateNeuralKey.required_capabilities();
        assert!(rotate_caps & APPROVE != 0);
    }

    #[test]
    fn test_identity_status_values() {
        assert_eq!(IdentityStatus::Active as u8, 0x01);
        assert_eq!(IdentityStatus::Disabled as u8, 0x02);
        assert_eq!(IdentityStatus::Frozen as u8, 0x03);
        assert_eq!(IdentityStatus::Deleted as u8, 0x04);
    }

    #[test]
    fn test_rate_limit_config_default() {
        let config = RateLimitConfig::default();
        assert_eq!(config.ip_window_seconds, 60);
        assert_eq!(config.ip_max_requests, 100);
        assert_eq!(config.identity_window_seconds, 3600);
        assert_eq!(config.identity_max_requests, 1000);
        assert_eq!(config.failure_window_seconds, 900);
        assert_eq!(config.failure_max_attempts, 5);
    }
}
