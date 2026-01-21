//! RocksDB column family definitions.
//!
//! As specified in 01-overview.md § 9.1

/// Identity records: identity_id → Identity
pub const CF_IDENTITIES: &str = "identities";

/// Machine keys: machine_id → MachineKey
pub const CF_MACHINE_KEYS: &str = "machine_keys";

/// Machine keys by identity index: (identity_id, machine_id) → ()
pub const CF_MACHINE_KEYS_BY_IDENTITY: &str = "machine_keys_by_identity";

/// Machine keys by namespace index: (namespace_id, machine_id) → ()
pub const CF_MACHINE_KEYS_BY_NAMESPACE: &str = "machine_keys_by_namespace";

/// Namespaces: namespace_id → Namespace
pub const CF_NAMESPACES: &str = "namespaces";

/// Identity namespace memberships: (identity_id, namespace_id) → Membership
pub const CF_IDENTITY_NAMESPACE_MEMBERSHIPS: &str = "identity_namespace_memberships";

/// Namespaces by identity index: (identity_id, namespace_id) → ()
pub const CF_NAMESPACES_BY_IDENTITY: &str = "namespaces_by_identity";

/// Authentication credentials: (identity_id, cred_type) → Credential
pub const CF_AUTH_CREDENTIALS: &str = "auth_credentials";

/// MFA secrets: identity_id → EncryptedMfaSecret
pub const CF_MFA_SECRETS: &str = "mfa_secrets";

/// Challenges: challenge_id → Challenge (TTL: 5 min)
pub const CF_CHALLENGES: &str = "challenges";

/// Used nonces: nonce_hex → expiry_timestamp (TTL: challenge TTL + 60s)
pub const CF_USED_NONCES: &str = "used_nonces";

/// OAuth/OIDC states: state_id → OAuthState (TTL: 10 min)
pub const CF_OAUTH_STATES: &str = "oauth_states";

/// OAuth/OIDC links: (provider, provider_user_id) → OAuthLink
pub const CF_OAUTH_LINKS: &str = "oauth_links";

/// OAuth/OIDC links by identity: (identity_id, provider) → link_id
pub const CF_OAUTH_LINKS_BY_IDENTITY: &str = "oauth_links_by_identity";

/// Wallet credentials: wallet_address → WalletCredential
pub const CF_WALLET_CREDENTIALS: &str = "wallet_credentials";

/// Wallet credentials by identity: (identity_id, wallet_address) → ()
pub const CF_WALLET_CREDENTIALS_BY_IDENTITY: &str = "wallet_credentials_by_identity";

/// OIDC nonces: nonce → created_at (TTL: 10 min)
pub const CF_OIDC_NONCES: &str = "oidc_nonces";

/// JWKS cache: provider → JwksKeySet (TTL: 1 hour)
pub const CF_JWKS_CACHE: &str = "jwks_cache";

/// Sessions: session_id → Session
pub const CF_SESSIONS: &str = "sessions";

/// Sessions by identity: (identity_id, session_id) → ()
pub const CF_SESSIONS_BY_IDENTITY: &str = "sessions_by_identity";

/// Sessions by token hash: token_hash → session_id
pub const CF_SESSIONS_BY_TOKEN_HASH: &str = "sessions_by_token_hash";

/// Refresh tokens: token_hash → RefreshToken
pub const CF_REFRESH_TOKENS: &str = "refresh_tokens";

/// Refresh tokens by family: (token_family_id, generation) → token_hash
pub const CF_REFRESH_TOKENS_BY_FAMILY: &str = "refresh_tokens_by_family";

/// JWT signing keys: key_id → JwtSigningKey
pub const CF_SIGNING_KEYS: &str = "signing_keys";

/// Integration services: service_id → IntegrationService
pub const CF_INTEGRATION_SERVICES: &str = "integration_services";

/// Integration services by cert: cert_fingerprint → service_id
pub const CF_INTEGRATION_SERVICES_BY_CERT: &str = "integration_services_by_cert";

/// Revocation events: (namespace_id, sequence) → RevocationEvent
pub const CF_REVOCATION_EVENTS: &str = "revocation_events";

/// Processed event IDs: event_id → processed_at (TTL: 1 hour)
pub const CF_PROCESSED_EVENT_IDS: &str = "processed_event_ids";

/// Webhook delivery log: (service_id, event_id) → DeliveryStatus
pub const CF_WEBHOOK_DELIVERY_LOG: &str = "webhook_delivery_log";

/// Reputation records: identity_id → ReputationRecord
pub const CF_REPUTATION: &str = "reputation";

/// Get all column family names
pub fn all_column_families() -> Vec<&'static str> {
    vec![
        CF_IDENTITIES,
        CF_MACHINE_KEYS,
        CF_MACHINE_KEYS_BY_IDENTITY,
        CF_MACHINE_KEYS_BY_NAMESPACE,
        CF_NAMESPACES,
        CF_IDENTITY_NAMESPACE_MEMBERSHIPS,
        CF_NAMESPACES_BY_IDENTITY,
        CF_AUTH_CREDENTIALS,
        CF_MFA_SECRETS,
        CF_CHALLENGES,
        CF_USED_NONCES,
        CF_OAUTH_STATES,
        CF_OAUTH_LINKS,
        CF_OAUTH_LINKS_BY_IDENTITY,
        CF_WALLET_CREDENTIALS,
        CF_WALLET_CREDENTIALS_BY_IDENTITY,
        CF_OIDC_NONCES,
        CF_JWKS_CACHE,
        CF_SESSIONS,
        CF_SESSIONS_BY_IDENTITY,
        CF_SESSIONS_BY_TOKEN_HASH,
        CF_REFRESH_TOKENS,
        CF_REFRESH_TOKENS_BY_FAMILY,
        CF_SIGNING_KEYS,
        CF_INTEGRATION_SERVICES,
        CF_INTEGRATION_SERVICES_BY_CERT,
        CF_REVOCATION_EVENTS,
        CF_PROCESSED_EVENT_IDS,
        CF_WEBHOOK_DELIVERY_LOG,
        CF_REPUTATION,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_column_families_non_empty() {
        let cfs = all_column_families();
        assert!(!cfs.is_empty());
    }

    #[test]
    fn test_no_duplicate_column_families() {
        let cfs = all_column_families();
        let mut unique = std::collections::HashSet::new();

        for cf in &cfs {
            assert!(unique.insert(cf), "Duplicate column family: {}", cf);
        }
    }
}
