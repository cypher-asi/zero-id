//! Policy engine type definitions.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
}
