//! Storage trait definitions.

use crate::errors::Result;
use async_trait::async_trait;
use serde::{de::DeserializeOwned, Serialize};

/// Storage interface for key-value operations
///
/// This trait abstracts the underlying storage implementation (RocksDB)
/// to enable testing with mock implementations.
#[async_trait]
pub trait Storage: Send + Sync {
    /// Get a value by key from a column family
    ///
    /// # Returns
    ///
    /// `Ok(Some(value))` if key exists, `Ok(None)` if not found
    async fn get<K, V>(&self, cf: &str, key: &K) -> Result<Option<V>>
    where
        K: Serialize + Send + Sync,
        V: DeserializeOwned;

    /// Put a key-value pair into a column family
    async fn put<K, V>(&self, cf: &str, key: &K, value: &V) -> Result<()>
    where
        K: Serialize + Send + Sync,
        V: Serialize + Send + Sync;

    /// Delete a key from a column family
    async fn delete<K>(&self, cf: &str, key: &K) -> Result<()>
    where
        K: Serialize + Send + Sync;

    /// Check if a key exists in a column family
    async fn exists<K>(&self, cf: &str, key: &K) -> Result<bool>
    where
        K: Serialize + Send + Sync;

    /// Get multiple values by prefix (range query)
    ///
    /// Returns all key-value pairs where keys start with the given prefix.
    async fn get_by_prefix<K, V>(&self, cf: &str, prefix: &K) -> Result<Vec<(Vec<u8>, V)>>
    where
        K: Serialize + Send + Sync,
        V: DeserializeOwned;

    /// Create a new batch for atomic operations
    fn batch(&self) -> Box<dyn Batch>;

    /// Begin a transaction (for multi-CF atomic operations)
    async fn begin_transaction(&self) -> Result<Box<dyn Batch>>;
}

/// Batch interface for atomic operations
///
/// Batches allow multiple operations to be performed atomically.
///
/// Note: This trait works with pre-serialized bytes to maintain object safety.
/// Use the `put_serialized` and `delete_serialized` helper methods, or serialize
/// your keys/values before calling the raw methods.
///
/// Batches only need to be `Send` (not `Sync`) since they are used within a single
/// task context and not shared across threads.
#[async_trait]
pub trait Batch: Send {
    /// Put a pre-serialized key-value pair in the batch
    ///
    /// For type-safe usage, use `BatchExt::put` instead.
    fn put_raw(&mut self, cf: &str, key: Vec<u8>, value: Vec<u8>) -> Result<()>;

    /// Delete a pre-serialized key in the batch
    ///
    /// For type-safe usage, use `BatchExt::delete` instead.
    fn delete_raw(&mut self, cf: &str, key: Vec<u8>) -> Result<()>;

    /// Commit the batch atomically
    async fn commit(self: Box<Self>) -> Result<()>;

    /// Rollback the batch (drop without committing)
    fn rollback(self: Box<Self>);
}

/// Extension trait providing type-safe methods for Batch
///
/// This trait provides generic methods that serialize keys and values before
/// calling the raw methods on Batch.
pub trait BatchExt: Batch {
    /// Put a key-value pair in the batch (type-safe)
    fn put<K, V>(&mut self, cf: &str, key: &K, value: &V) -> Result<()>
    where
        K: Serialize,
        V: Serialize,
    {
        let key_bytes = serialize_key(key)?;
        let value_bytes = serialize_value(value)?;
        self.put_raw(cf, key_bytes, value_bytes)
    }

    /// Delete a key in the batch (type-safe)
    fn delete<K>(&mut self, cf: &str, key: &K) -> Result<()>
    where
        K: Serialize,
    {
        let key_bytes = serialize_key(key)?;
        self.delete_raw(cf, key_bytes)
    }
}

/// Automatically implement BatchExt for all types that implement Batch
impl<T: Batch + ?Sized> BatchExt for T {}

/// Helper function to serialize a key
pub(crate) fn serialize_key<K: Serialize>(key: &K) -> Result<Vec<u8>> {
    bincode::serialize(key).map_err(|e| crate::errors::StorageError::Serialization(e.to_string()))
}

/// Helper function to serialize a value
pub(crate) fn serialize_value<V: Serialize>(value: &V) -> Result<Vec<u8>> {
    bincode::serialize(value).map_err(|e| crate::errors::StorageError::Serialization(e.to_string()))
}

/// Helper function to deserialize a value
pub(crate) fn deserialize_value<V: DeserializeOwned>(bytes: &[u8]) -> Result<V> {
    bincode::deserialize(bytes)
        .map_err(|e| crate::errors::StorageError::Deserialization(e.to_string()))
}
