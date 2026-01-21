//! Policy evaluator logic.

use crate::types::*;

/// Policy evaluator for authorization decisions
pub struct PolicyEvaluator;

impl PolicyEvaluator {
    /// Evaluate a policy context and return a decision
    ///
    /// Evaluation order (as specified in 07-policy-engine.md § 5.1):
    /// 1. Identity frozen check (highest priority)
    /// 2. Identity status check
    /// 3. Machine revocation check
    /// 4. Namespace status check
    /// 5. Capability checks
    /// 6. MFA requirements
    /// 7. Approval requirements
    /// 8. Reputation checks
    /// 9. Rate limiting
    pub fn evaluate(context: &PolicyContext) -> PolicyDecision {
        let mut audit_tags = vec![
            format!("operation:{:?}", context.operation),
            format!("auth_method:{:?}", context.auth_method),
        ];

        // 1. Identity frozen check (highest priority)
        if let Some(IdentityStatus::Frozen) = context.identity_status {
            audit_tags.push("identity_frozen".to_string());
            return Self::deny("Identity is frozen", audit_tags);
        }

        // 2. Identity status check
        if let Some(status) = context.identity_status {
            if status != IdentityStatus::Active {
                audit_tags.push(format!("identity_status:{:?}", status));
                return Self::deny(&format!("Identity is {:?}", status), audit_tags);
            }
        }

        // 3. Machine revocation check
        if context.machine_revoked == Some(true) {
            audit_tags.push("machine_revoked".to_string());
            return Self::deny("Machine key has been revoked", audit_tags);
        }

        // 4. Namespace status check
        if context.namespace_active == Some(false) {
            audit_tags.push("namespace_inactive".to_string());
            return Self::deny("Namespace is not active", audit_tags);
        }

        // 5. Capability checks
        if let Some(machine_caps) = context.machine_capabilities {
            let required_caps = context.operation.required_capabilities();
            if (machine_caps & required_caps) != required_caps {
                let missing = Self::describe_missing_capabilities(machine_caps, required_caps);
                audit_tags.push(format!("missing_capabilities:{}", missing));
                return Self::deny(
                    &format!("Insufficient machine capabilities: missing {}", missing),
                    audit_tags,
                );
            }
        }

        // 6. MFA requirements
        if context.operation.requires_mfa() && !context.mfa_verified {
            audit_tags.push("mfa_required".to_string());
            return PolicyDecision {
                verdict: Verdict::RequireAdditionalAuth,
                required_factors: vec![AuthFactor::MfaTotp],
                required_approvals: 0,
                rate_limit: None,
                audit_tags,
                reason: "MFA verification required for this operation".to_string(),
            };
        }

        // 7. Approval requirements
        let required_approvals = context.operation.required_approvals();
        if required_approvals > 0 {
            audit_tags.push(format!("approvals_required:{}", required_approvals));
            return PolicyDecision {
                verdict: Verdict::RequireApproval,
                required_factors: Vec::new(),
                required_approvals,
                rate_limit: None,
                audit_tags,
                reason: format!("{} approvals required", required_approvals),
            };
        }

        // 8. Reputation checks
        if context.reputation_score < -50 {
            audit_tags.push("low_reputation".to_string());
            return Self::deny("Low reputation score", audit_tags);
        }

        // 9. Rate limiting (based on recent failed attempts)
        if context.recent_failed_attempts >= 5 {
            audit_tags.push("rate_limited".to_string());
            return PolicyDecision {
                verdict: Verdict::RateLimited,
                required_factors: Vec::new(),
                required_approvals: 0,
                rate_limit: None,
                audit_tags,
                reason: "Too many recent failed attempts".to_string(),
            };
        }

        // All checks passed
        PolicyDecision {
            verdict: Verdict::Allow,
            required_factors: Vec::new(),
            required_approvals: 0,
            rate_limit: None,
            audit_tags,
            reason: "Policy evaluation passed".to_string(),
        }
    }

    /// Create a deny decision with the given reason
    fn deny(reason: &str, audit_tags: Vec<String>) -> PolicyDecision {
        PolicyDecision {
            verdict: Verdict::Deny,
            required_factors: Vec::new(),
            required_approvals: 0,
            rate_limit: None,
            audit_tags,
            reason: reason.to_string(),
        }
    }

    /// Describe missing capabilities as a human-readable string
    fn describe_missing_capabilities(have: u32, need: u32) -> String {
        use capabilities::*;
        let missing = need & !have;
        let mut names = Vec::new();

        if missing & AUTHENTICATE != 0 {
            names.push("AUTHENTICATE");
        }
        if missing & SIGN != 0 {
            names.push("SIGN");
        }
        if missing & DECRYPT != 0 {
            names.push("DECRYPT");
        }
        if missing & ENROLL != 0 {
            names.push("ENROLL");
        }
        if missing & REVOKE != 0 {
            names.push("REVOKE");
        }
        if missing & APPROVE != 0 {
            names.push("APPROVE");
        }

        if names.is_empty() {
            "none".to_string()
        } else {
            names.join(", ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_context() -> PolicyContext {
        PolicyContext {
            identity_id: uuid::Uuid::new_v4(),
            machine_id: Some(uuid::Uuid::new_v4()),
            namespace_id: uuid::Uuid::new_v4(),
            auth_method: AuthMethod::MachineKey,
            mfa_verified: true,
            operation: Operation::Login,
            resource: None,
            ip_address: "127.0.0.1".to_string(),
            user_agent: "test-agent".to_string(),
            timestamp: 1705320000,
            reputation_score: 0,
            recent_failed_attempts: 0,
            // Entity states - None means check is skipped
            identity_status: Some(IdentityStatus::Active),
            machine_revoked: Some(false),
            machine_capabilities: Some(capabilities::AUTHENTICATE | capabilities::SIGN),
            namespace_active: Some(true),
        }
    }

    #[test]
    fn test_basic_allow() {
        let context = create_test_context();
        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.reason, "Policy evaluation passed");
    }

    #[test]
    fn test_frozen_identity_denied() {
        let mut context = create_test_context();
        context.identity_status = Some(IdentityStatus::Frozen);

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("frozen"));
        assert!(decision.audit_tags.contains(&"identity_frozen".to_string()));
    }

    #[test]
    fn test_disabled_identity_denied() {
        let mut context = create_test_context();
        context.identity_status = Some(IdentityStatus::Disabled);

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("Disabled"));
    }

    #[test]
    fn test_deleted_identity_denied() {
        let mut context = create_test_context();
        context.identity_status = Some(IdentityStatus::Deleted);

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("Deleted"));
    }

    #[test]
    fn test_revoked_machine_denied() {
        let mut context = create_test_context();
        context.machine_revoked = Some(true);

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("revoked"));
        assert!(decision.audit_tags.contains(&"machine_revoked".to_string()));
    }

    #[test]
    fn test_inactive_namespace_denied() {
        let mut context = create_test_context();
        context.namespace_active = Some(false);

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("Namespace"));
        assert!(decision.audit_tags.contains(&"namespace_inactive".to_string()));
    }

    #[test]
    fn test_insufficient_capabilities_denied() {
        let mut context = create_test_context();
        context.operation = Operation::EnrollMachine; // Requires AUTHENTICATE | SIGN | ENROLL
        context.machine_capabilities = Some(capabilities::AUTHENTICATE); // Missing SIGN and ENROLL

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("capabilities"));
        assert!(decision.reason.contains("SIGN") || decision.reason.contains("ENROLL"));
    }

    #[test]
    fn test_sufficient_capabilities_allowed() {
        let mut context = create_test_context();
        context.operation = Operation::EnrollMachine;
        context.machine_capabilities = Some(
            capabilities::AUTHENTICATE | capabilities::SIGN | capabilities::ENROLL,
        );

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[test]
    fn test_mfa_required() {
        let mut context = create_test_context();
        context.operation = Operation::ChangePassword; // Requires MFA
        context.mfa_verified = false;
        // Give sufficient capabilities
        context.machine_capabilities = Some(capabilities::AUTHENTICATE | capabilities::SIGN);

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::RequireAdditionalAuth);
        assert!(decision.required_factors.contains(&AuthFactor::MfaTotp));
    }

    #[test]
    fn test_approvals_required() {
        let mut context = create_test_context();
        context.operation = Operation::UnfreezeIdentity; // Requires 2 approvals
        context.mfa_verified = true;
        // Give sufficient capabilities including APPROVE
        context.machine_capabilities = Some(
            capabilities::AUTHENTICATE | capabilities::SIGN | capabilities::APPROVE,
        );

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::RequireApproval);
        assert_eq!(decision.required_approvals, 2);
    }

    #[test]
    fn test_low_reputation_denied() {
        let mut context = create_test_context();
        context.reputation_score = -60;

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("reputation"));
    }

    #[test]
    fn test_too_many_failed_attempts() {
        let mut context = create_test_context();
        context.recent_failed_attempts = 10;

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::RateLimited);
    }

    #[test]
    fn test_evaluation_order_frozen_takes_priority() {
        let mut context = create_test_context();
        // Set multiple deny conditions
        context.identity_status = Some(IdentityStatus::Frozen);
        context.machine_revoked = Some(true);
        context.namespace_active = Some(false);
        context.reputation_score = -100;

        let decision = PolicyEvaluator::evaluate(&context);

        // Frozen check should take priority
        assert_eq!(decision.verdict, Verdict::Deny);
        assert!(decision.reason.contains("frozen"));
    }

    #[test]
    fn test_none_entity_states_skip_checks() {
        let mut context = create_test_context();
        // Set all entity states to None - checks should be skipped
        context.identity_status = None;
        context.machine_revoked = None;
        context.machine_capabilities = None;
        context.namespace_active = None;

        let decision = PolicyEvaluator::evaluate(&context);

        // Should pass because checks are skipped when state is None
        assert_eq!(decision.verdict, Verdict::Allow);
    }

    #[test]
    fn test_all_checks_pass() {
        let mut context = create_test_context();
        context.identity_status = Some(IdentityStatus::Active);
        context.machine_revoked = Some(false);
        context.namespace_active = Some(true);
        context.machine_capabilities = Some(capabilities::AUTHENTICATE | capabilities::SIGN);
        context.mfa_verified = true;
        context.reputation_score = 50;
        context.recent_failed_attempts = 0;

        let decision = PolicyEvaluator::evaluate(&context);

        assert_eq!(decision.verdict, Verdict::Allow);
        assert_eq!(decision.reason, "Policy evaluation passed");
    }

    #[test]
    fn test_describe_missing_capabilities() {
        // Missing SIGN and ENROLL
        let have = capabilities::AUTHENTICATE;
        let need = capabilities::AUTHENTICATE | capabilities::SIGN | capabilities::ENROLL;

        let description = PolicyEvaluator::describe_missing_capabilities(have, need);

        assert!(description.contains("SIGN"));
        assert!(description.contains("ENROLL"));
        assert!(!description.contains("AUTHENTICATE"));
    }
}
