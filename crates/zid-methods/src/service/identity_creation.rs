//! Identity creation service for managed identities.
//!
//! This module handles creating new identities via various authentication methods:
//! - Email + password
//! - OAuth providers (Google, X, Epic Games)
//! - Wallet signatures (Ethereum, Solana)
//!
//! All identities created through these methods are managed tier identities.

use crate::{
    errors::*,
    oauth::types::OAuthUserInfo,
    types::*,
    wallet::{normalize_wallet_address, verify_wallet_signature_typed},
};
use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use rand::rngs::OsRng;
use tracing::info;
use uuid::Uuid;
use zid_crypto::current_timestamp;
use zid_identity_core::{
    CreateManagedIdentityParams, CreateManagedIdentityResult, IdentityCore, IdentityTier,
};
use zid_policy::PolicyEngine;
use zid_storage::Storage;

use super::{
    AuthMethodsService, CF_AUTH_CREDENTIALS, CF_CHALLENGES, CF_OAUTH_LINKS, CF_OAUTH_LINKS_BY_IDENTITY,
    CF_WALLET_CREDENTIALS, CF_WALLET_CREDENTIALS_BY_IDENTITY,
};

/// Column family for auth links
const CF_AUTH_LINKS: &str = "auth_links";
/// Column family for auth links by method
const CF_AUTH_LINKS_BY_METHOD: &str = "auth_links_by_method";
/// Column family for primary auth method
const CF_PRIMARY_AUTH_METHOD: &str = "primary_auth_method";

/// Response from identity creation
#[derive(Debug, Clone)]
pub struct IdentityCreationResponse {
    /// Created identity ID
    pub identity_id: Uuid,
    /// Machine ID for authentication
    pub machine_id: Uuid,
    /// Namespace ID (same as identity_id)
    pub namespace_id: Uuid,
    /// Identity tier (always Managed for these creation methods)
    pub tier: IdentityTier,
    /// Warning message about upgrading
    pub warning: Option<String>,
}

impl<I, P, S> AuthMethodsService<I, P, S>
where
    I: IdentityCore + 'static,
    P: PolicyEngine + 'static,
    S: Storage + 'static,
{
    // ========================================================================
    // Email Identity Creation
    // ========================================================================

    /// Create a new identity via email + password
    ///
    /// # Arguments
    /// * `email` - Email address (will be normalized to lowercase)
    /// * `password` - Password (will be hashed with Argon2id)
    /// * `namespace_name` - Optional namespace name
    ///
    /// # Returns
    /// IdentityCreationResponse with identity info and upgrade warning
    pub async fn create_identity_via_email(
        &self,
        email: String,
        password: String,
        namespace_name: Option<String>,
    ) -> Result<IdentityCreationResponse> {
        let email_lower = email.to_lowercase().trim().to_string();
        info!("Creating identity via email: {}", email_lower);

        // Check if email already exists
        let method_key = format!("email:{}", email_lower);
        if self.storage.exists(CF_AUTH_LINKS_BY_METHOD, &method_key).await? {
            return Err(AuthMethodsError::Other(
                "Email already linked to an identity".to_string(),
            ));
        }

        // Hash password
        let password_hash = self.hash_password(&password)?;

        // Create managed identity
        let response = self
            .create_managed_identity_internal(
                *self.service_master_key,
                "email".to_string(),
                email_lower.clone(),
                namespace_name,
            )
            .await?;

        // Store email credential
        let credential = EmailCredential {
            identity_id: response.identity.identity_id,
            email: email_lower.clone(),
            password_hash,
            created_at: current_timestamp(),
            updated_at: current_timestamp(),
            email_verified: false,
            verification_token: Some(Uuid::new_v4().to_string()),
        };

        self.storage
            .put(CF_AUTH_CREDENTIALS, &email_lower, &credential)
            .await?;

        // Store auth link
        self.store_auth_link(
            response.identity.identity_id,
            AuthMethodType::Email,
            &email_lower,
            true,
            false, // Not verified yet
        )
        .await?;

        info!(
            "Email identity created: {} for {}",
            response.identity.identity_id, email_lower
        );

        Ok(IdentityCreationResponse {
            identity_id: response.identity.identity_id,
            machine_id: response.machine_id,
            namespace_id: response.namespace_id,
            tier: response.identity.tier,
            warning: Some("Consider upgrading to self-sovereign identity for enhanced security".to_string()),
        })
    }

    // ========================================================================
    // OAuth Identity Creation
    // ========================================================================

    /// Create a new identity via OAuth provider
    ///
    /// This is called after OAuth callback when no existing identity is linked.
    ///
    /// # Arguments
    /// * `provider` - OAuth provider
    /// * `user_info` - User info from OAuth provider
    /// * `namespace_name` - Optional namespace name
    pub async fn create_identity_via_oauth(
        &self,
        provider: OAuthProvider,
        user_info: &OAuthUserInfo,
        namespace_name: Option<String>,
    ) -> Result<IdentityCreationResponse> {
        info!(
            "Creating identity via OAuth: {:?} for {}",
            provider, user_info.id
        );

        let method_id = user_info.id.clone();

        // Check if already linked
        // Key format must match store_auth_link: "{auth_method_type}:{method_id}"
        let auth_method_type = match provider {
            OAuthProvider::Google => AuthMethodType::OAuthGoogle,
            OAuthProvider::X => AuthMethodType::OAuthX,
            OAuthProvider::EpicGames => AuthMethodType::OAuthEpic,
        };
        let method_key = format!("{}:{}", auth_method_type.as_str(), method_id);
        if self.storage.exists(CF_AUTH_LINKS_BY_METHOD, &method_key).await? {
            return Err(AuthMethodsError::Other(
                "OAuth account already linked to an identity".to_string(),
            ));
        }

        let method_type = format!("oauth:{}", provider.as_str());

        // Create managed identity
        let response = self
            .create_managed_identity_internal(
                *self.service_master_key,
                method_type.clone(),
                method_id.clone(),
                namespace_name,
            )
            .await?;
        let identity_id = response.identity.identity_id;

        // Store OAuth link
        let link = crate::oauth::types::OAuthLink {
            link_id: Uuid::new_v4(),
            identity_id,
            provider,
            provider_user_id: user_info.id.clone(),
            provider_email: user_info.email.clone(),
            email_verified: None,
            display_name: user_info.name.clone(),
            linked_at: current_timestamp(),
            last_auth_at: current_timestamp(),
            revoked: false,
            revoked_at: None,
        };

        let link_key = format!("{}:{}", provider.as_str(), user_info.id);
        self.storage.put(CF_OAUTH_LINKS, &link_key, &link).await?;

        // Store index
        let identity_index_key = format!("{}:{}", identity_id, provider.as_str());
        self.storage
            .put(CF_OAUTH_LINKS_BY_IDENTITY, &identity_index_key, &user_info.id)
            .await?;

        // Store auth link
        let auth_method_type = match provider {
            OAuthProvider::Google => AuthMethodType::OAuthGoogle,
            OAuthProvider::X => AuthMethodType::OAuthX,
            OAuthProvider::EpicGames => AuthMethodType::OAuthEpic,
        };

        self.store_auth_link(identity_id, auth_method_type, &method_id, true, true)
            .await?;

        info!(
            "OAuth identity created: {} via {:?}",
            identity_id, provider
        );

        Ok(IdentityCreationResponse {
            identity_id,
            machine_id: response.machine_id,
            namespace_id: response.namespace_id,
            tier: response.identity.tier,
            warning: Some("Consider upgrading to self-sovereign identity for enhanced security".to_string()),
        })
    }

    // ========================================================================
    // Wallet Identity Creation
    // ========================================================================

    /// Initiate wallet identity creation - returns challenge to sign
    ///
    /// # Arguments
    /// * `wallet_type` - Type of wallet (Ethereum, Solana, etc.)
    /// * `address` - Wallet address
    ///
    /// # Returns
    /// Challenge ID and message to sign
    pub async fn initiate_wallet_identity_creation(
        &self,
        wallet_type: WalletType,
        address: String,
    ) -> Result<(Uuid, String)> {
        let normalized_address = normalize_wallet_address(wallet_type, &address)?;
        info!(
            "Initiating wallet identity creation: {:?} {}",
            wallet_type, normalized_address
        );

        // Check if wallet already linked
        // Key format must match store_auth_link: "{auth_method_type}:{method_id}"
        let auth_method_type = wallet_type.to_auth_method_type();
        let method_key = format!("{}:{}", auth_method_type.as_str(), normalized_address);
        if self.storage.exists(CF_AUTH_LINKS_BY_METHOD, &method_key).await? {
            return Err(AuthMethodsError::Other(
                "Wallet already linked to an identity".to_string(),
            ));
        }

        // Create challenge
        let challenge = zid_crypto::Challenge::new_for_wallet(&normalized_address);
        let challenge_id = challenge.id();

        // Store challenge
        self.storage
            .put(CF_CHALLENGES, &challenge_id, &challenge)
            .await?;

        // Build message to sign
        let message = serde_json::to_string(&challenge)
            .map_err(|e| AuthMethodsError::Other(format!("Challenge serialization failed: {}", e)))?;

        Ok((challenge_id, message))
    }

    /// Complete wallet identity creation - verify signature and create identity
    ///
    /// # Arguments
    /// * `wallet_type` - Type of wallet
    /// * `address` - Wallet address
    /// * `challenge_id` - Challenge ID from initiation
    /// * `signature` - Signature of the challenge message
    /// * `namespace_name` - Optional namespace name
    pub async fn complete_wallet_identity_creation(
        &self,
        wallet_type: WalletType,
        address: String,
        challenge_id: Uuid,
        signature: Vec<u8>,
        namespace_name: Option<String>,
    ) -> Result<IdentityCreationResponse> {
        let normalized_address = normalize_wallet_address(wallet_type, &address)?;
        info!(
            "Completing wallet identity creation: {:?} {}",
            wallet_type, normalized_address
        );

        // Get and validate challenge
        let challenge: zid_crypto::Challenge = self
            .storage
            .get(CF_CHALLENGES, &challenge_id)
            .await?
            .ok_or(AuthMethodsError::ChallengeNotFound(challenge_id))?;

        // Delete challenge (one-time use)
        self.storage.delete(CF_CHALLENGES, &challenge_id).await?;

        // Verify signature
        let message = serde_json::to_string(&challenge)
            .map_err(|e| AuthMethodsError::Other(format!("Challenge serialization failed: {}", e)))?;

        verify_wallet_signature_typed(wallet_type, &normalized_address, message.as_bytes(), &signature)?;

        // Create managed identity
        let method_type = format!("wallet:{}", wallet_type.as_str());
        let response = self
            .create_managed_identity_internal(
                *self.service_master_key,
                method_type.clone(),
                normalized_address.clone(),
                namespace_name,
            )
            .await?;
        let identity_id = response.identity.identity_id;

        // Store wallet credential
        let credential = WalletCredential {
            identity_id,
            wallet_type,
            wallet_address: normalized_address.clone(),
            public_key: if wallet_type == WalletType::Solana {
                // For Solana, address is the public key
                let bytes = bs58::decode(&normalized_address)
                    .into_vec()
                    .ok()
                    .and_then(|v| {
                        if v.len() == 32 {
                            let mut arr = [0u8; 32];
                            arr.copy_from_slice(&v);
                            Some(arr)
                        } else {
                            None
                        }
                    });
                bytes
            } else {
                None
            },
            chain: wallet_type.as_str().to_string(),
            created_at: current_timestamp(),
            last_used_at: current_timestamp(),
            revoked: false,
            revoked_at: None,
        };

        self.storage
            .put(CF_WALLET_CREDENTIALS, &normalized_address, &credential)
            .await?;

        // Store index
        let identity_index_key = format!("{}:{}", identity_id, normalized_address);
        self.storage
            .put(CF_WALLET_CREDENTIALS_BY_IDENTITY, &identity_index_key, &())
            .await?;

        // Store auth link
        let auth_method_type = wallet_type.to_auth_method_type();
        self.store_auth_link(identity_id, auth_method_type, &normalized_address, true, true)
            .await?;

        info!(
            "Wallet identity created: {} via {:?} {}",
            identity_id, wallet_type, normalized_address
        );

        Ok(IdentityCreationResponse {
            identity_id,
            machine_id: response.machine_id,
            namespace_id: response.namespace_id,
            tier: response.identity.tier,
            warning: Some("Consider upgrading to self-sovereign identity for enhanced security".to_string()),
        })
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Create managed identity via identity core trait
    async fn create_managed_identity_internal(
        &self,
        service_master_key: [u8; 32],
        method_type: String,
        method_id: String,
        namespace_name: Option<String>,
    ) -> Result<CreateManagedIdentityResult> {
        let params = CreateManagedIdentityParams {
            service_master_key,
            method_type,
            method_id,
            namespace_name,
        };

        self.identity_core
            .create_managed_identity(params)
            .await
            .map_err(|e| AuthMethodsError::Other(e.to_string()))
    }

    /// Hash password using Argon2id
    fn hash_password(&self, password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        let hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e: argon2::password_hash::Error| AuthMethodsError::PasswordHash(e.to_string()))?;

        Ok(hash.to_string())
    }

    /// Store auth link record
    async fn store_auth_link(
        &self,
        identity_id: Uuid,
        method_type: AuthMethodType,
        method_id: &str,
        is_primary: bool,
        verified: bool,
    ) -> Result<()> {
        let link = AuthLinkRecord {
            identity_id,
            method_type,
            method_id: method_id.to_string(),
            linked_at: current_timestamp(),
            is_primary,
            verified,
            last_used_at: Some(current_timestamp()),
        };

        // Store by identity
        let link_key = format!("{}:{:?}", identity_id, method_type);
        self.storage.put(CF_AUTH_LINKS, &link_key, &link).await?;

        // Store by method (for lookup)
        let method_key = format!("{}:{}", method_type.as_str(), method_id);
        self.storage
            .put(CF_AUTH_LINKS_BY_METHOD, &method_key, &identity_id)
            .await?;

        // Store primary method if applicable
        if is_primary {
            self.storage
                .put(CF_PRIMARY_AUTH_METHOD, &identity_id, &method_type)
                .await?;
        }

        Ok(())
    }

    /// Get auth method count for an identity
    pub async fn get_auth_method_count(&self, identity_id: Uuid) -> Result<usize> {
        let mut count = 0;

        // Check email
        let email_key = format!("{}:{:?}", identity_id, AuthMethodType::Email);
        if self.storage.exists(CF_AUTH_LINKS, &email_key).await? {
            count += 1;
        }

        // Check OAuth providers
        for method_type in [
            AuthMethodType::OAuthGoogle,
            AuthMethodType::OAuthX,
            AuthMethodType::OAuthEpic,
        ] {
            let key = format!("{}:{:?}", identity_id, method_type);
            if self.storage.exists(CF_AUTH_LINKS, &key).await? {
                count += 1;
            }
        }

        // Check wallets
        for method_type in [AuthMethodType::WalletEvm, AuthMethodType::WalletSolana] {
            let key = format!("{}:{:?}", identity_id, method_type);
            if self.storage.exists(CF_AUTH_LINKS, &key).await? {
                count += 1;
            }
        }

        Ok(count)
    }
}
