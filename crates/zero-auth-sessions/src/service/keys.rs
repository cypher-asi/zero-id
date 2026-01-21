//! JWT signing key management for the session service.

use crate::{errors::*, types::*};
use ed25519_dalek::SigningKey;
use zero_auth_crypto::derive_jwt_signing_seed;
use zero_auth_identity_core::IdentityCore;
use zero_auth_storage::{column_families::*, Storage};

use super::{generate_random_bytes, EventPublisher, SessionService};

impl<S: Storage, I: IdentityCore, E: EventPublisher> SessionService<S, I, E> {
    /// Generate a new JWT signing key from service master key
    pub(super) async fn generate_signing_key(&self, epoch: u64) -> Result<JwtSigningKey> {
        let seed = derive_jwt_signing_seed(&self.service_master_key, epoch)?;

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let key_id = generate_random_bytes::<16>();

        // Encrypt the private key before storing
        let nonce = zero_auth_crypto::generate_nonce()?;
        let private_key_encrypted = zero_auth_crypto::encrypt_jwt_signing_key(
            &self.service_master_key,
            &seed,
            &nonce,
            &key_id,
            epoch,
        )?;

        Ok(JwtSigningKey {
            key_id,
            epoch,
            private_key_encrypted,
            private_key_nonce: nonce,
            public_key: verifying_key.to_bytes(),
            created_at: current_timestamp(),
            expires_at: None,
            status: KeyStatus::Active,
        })
    }

    /// Store signing key in database
    pub(super) async fn store_signing_key(&self, key: &JwtSigningKey) -> Result<()> {
        self.storage.put(CF_SIGNING_KEYS, &key.key_id, key).await?;

        Ok(())
    }

    /// Load all signing keys from database
    pub(super) async fn load_signing_keys(&self) -> Result<Vec<JwtSigningKey>> {
        // Scan the signing keys column family to get all stored keys
        let prefix = String::new();
        let keys = self
            .storage
            .get_by_prefix::<String, JwtSigningKey>(CF_SIGNING_KEYS, &prefix)
            .await?;

        // Extract just the values
        let signing_keys: Vec<JwtSigningKey> = keys.into_iter().map(|(_, v)| v).collect();

        Ok(signing_keys)
    }

    /// Rotate signing key - create new key and mark old as rotating
    pub(super) async fn rotate_signing_key_internal(&self) -> Result<String> {
        // Get current key
        let current_kid = self.current_key_id.read().await.clone();
        let keys = self.signing_keys.read().await;
        let current_key = keys
            .get(&current_kid)
            .ok_or_else(|| SessionError::Other("No active signing key".to_string()))?;

        let new_epoch = current_key.epoch + 1;
        drop(keys);

        // Generate new key
        let new_key = self.generate_signing_key(new_epoch).await?;
        let new_kid = format!("key_epoch_{}", new_key.epoch);

        // Store new key
        self.store_signing_key(&new_key).await?;

        // Update current key to rotating status
        let mut keys = self.signing_keys.write().await;
        if let Some(old_key) = keys.get_mut(&current_kid) {
            old_key.status = KeyStatus::Rotating;
            old_key.expires_at = Some(current_timestamp() + 3600);
            self.store_signing_key(old_key).await?;
        }

        // Add new key
        keys.insert(new_kid.clone(), new_key);

        // Update current key ID
        let mut current_key_id = self.current_key_id.write().await;
        *current_key_id = new_kid.clone();

        Ok(new_kid)
    }
}
