//! RocksDB storage implementation.

use crate::{
    column_families::all_column_families,
    errors::{Result, StorageError},
    traits::{deserialize_value, serialize_key, serialize_value, Batch, Storage},
};
use async_trait::async_trait;
use rocksdb::{Options, WriteBatch, DB};
use serde::{de::DeserializeOwned, Serialize};
use std::{path::Path, sync::Arc};
use tracing::debug;

/// RocksDB storage implementation
pub struct RocksDbStorage {
    db: Arc<DB>,
}

impl RocksDbStorage {
    /// Open RocksDB database at the specified path
    ///
    /// Creates all required column families if they don't exist.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        // Open database with all column families
        let db = DB::open_cf(&opts, &path, all_column_families())
            .map_err(|e| StorageError::Database(e.to_string()))?;

        debug!("Opened RocksDB at {:?}", path.as_ref());

        Ok(Self { db: Arc::new(db) })
    }

    /// Open RocksDB database for testing (in-memory or temp directory)
    ///
    /// This is public for use in other crates' test modules.
    pub fn open_test() -> Result<Self> {
        let temp_dir = tempfile::TempDir::new().map_err(StorageError::IoError)?;
        Self::open(temp_dir.path())
    }

    /// Get column family handle
    fn cf_handle(&self, cf: &str) -> Result<&rocksdb::ColumnFamily> {
        self.db
            .cf_handle(cf)
            .ok_or_else(|| StorageError::InvalidColumnFamily(cf.to_string()))
    }
}

#[async_trait]
impl Storage for RocksDbStorage {
    async fn get<K, V>(&self, cf: &str, key: &K) -> Result<Option<V>>
    where
        K: Serialize + Send + Sync,
        V: DeserializeOwned,
    {
        let cf_handle = self.cf_handle(cf)?;
        let key_bytes = serialize_key(key)?;

        let result = self
            .db
            .get_cf(cf_handle, &key_bytes)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        match result {
            Some(bytes) => {
                let value = deserialize_value(&bytes)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    async fn put<K, V>(&self, cf: &str, key: &K, value: &V) -> Result<()>
    where
        K: Serialize + Send + Sync,
        V: Serialize + Send + Sync,
    {
        let cf_handle = self.cf_handle(cf)?;
        let key_bytes = serialize_key(key)?;
        let value_bytes = serialize_value(value)?;

        self.db
            .put_cf(cf_handle, &key_bytes, &value_bytes)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    async fn delete<K>(&self, cf: &str, key: &K) -> Result<()>
    where
        K: Serialize + Send + Sync,
    {
        let cf_handle = self.cf_handle(cf)?;
        let key_bytes = serialize_key(key)?;

        self.db
            .delete_cf(cf_handle, &key_bytes)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(())
    }

    async fn exists<K>(&self, cf: &str, key: &K) -> Result<bool>
    where
        K: Serialize + Send + Sync,
    {
        let cf_handle = self.cf_handle(cf)?;
        let key_bytes = serialize_key(key)?;

        let result = self
            .db
            .get_cf(cf_handle, &key_bytes)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(result.is_some())
    }

    async fn get_by_prefix<K, V>(&self, cf: &str, prefix: &K) -> Result<Vec<(Vec<u8>, V)>>
    where
        K: Serialize + Send + Sync,
        V: DeserializeOwned,
    {
        let cf_handle = self.cf_handle(cf)?;
        let prefix_bytes = serialize_key(prefix)?;

        let mut results = Vec::new();

        // Use iterator with From mode to seek to the prefix position
        // This works without needing a prefix extractor configured
        let iter = self
            .db
            .iterator_cf(cf_handle, rocksdb::IteratorMode::From(&prefix_bytes, rocksdb::Direction::Forward));

        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;

            // Check if key still has prefix
            if key.starts_with(&prefix_bytes) {
                let deserialized_value = deserialize_value(&value)?;
                results.push((key.to_vec(), deserialized_value));
            } else {
                // Keys are sorted, so once we're past the prefix, we're done
                break;
            }
        }

        Ok(results)
    }

    async fn scan_all<V>(&self, cf: &str) -> Result<Vec<(Vec<u8>, V)>>
    where
        V: DeserializeOwned,
    {
        let cf_handle = self.cf_handle(cf)?;

        let mut results = Vec::new();
        let iter = self.db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);

        for item in iter {
            let (key, value) = item.map_err(|e| StorageError::Database(e.to_string()))?;
            let deserialized_value = deserialize_value(&value)?;
            results.push((key.to_vec(), deserialized_value));
        }

        Ok(results)
    }

    fn batch(&self) -> Box<dyn Batch> {
        Box::new(RocksDbBatch {
            db: Arc::clone(&self.db),
            write_batch: WriteBatch::default(),
        })
    }

    async fn begin_transaction(&self) -> Result<Box<dyn Batch>> {
        // For RocksDB, transactions are the same as batches
        Ok(self.batch())
    }
}

/// RocksDB batch implementation
pub struct RocksDbBatch {
    db: Arc<DB>,
    write_batch: WriteBatch,
}

#[async_trait]
impl Batch for RocksDbBatch {
    fn put_raw(&mut self, cf: &str, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let cf_handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| StorageError::InvalidColumnFamily(cf.to_string()))?;

        self.write_batch.put_cf(cf_handle, &key, &value);

        Ok(())
    }

    fn delete_raw(&mut self, cf: &str, key: Vec<u8>) -> Result<()> {
        let cf_handle = self
            .db
            .cf_handle(cf)
            .ok_or_else(|| StorageError::InvalidColumnFamily(cf.to_string()))?;

        self.write_batch.delete_cf(cf_handle, &key);

        Ok(())
    }

    async fn commit(self: Box<Self>) -> Result<()> {
        self.db
            .write(self.write_batch)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        debug!("Batch committed successfully");
        Ok(())
    }

    fn rollback(self: Box<Self>) {
        // WriteBatch is dropped, no commit
        debug!("Batch rolled back");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::BatchExt;
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestData {
        id: Uuid,
        name: String,
        value: u64,
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let storage = RocksDbStorage::open_test().unwrap();
        let key = Uuid::new_v4();
        let data = TestData {
            id: key,
            name: "test".to_string(),
            value: 42,
        };

        // Put
        storage.put("identities", &key, &data).await.unwrap();

        // Get
        let result: Option<TestData> = storage.get("identities", &key).await.unwrap();
        assert_eq!(result, Some(data));
    }

    #[tokio::test]
    async fn test_get_nonexistent() {
        let storage = RocksDbStorage::open_test().unwrap();
        let key = Uuid::new_v4();

        let result: Option<TestData> = storage.get("identities", &key).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_exists() {
        let storage = RocksDbStorage::open_test().unwrap();
        let key = Uuid::new_v4();
        let data = TestData {
            id: key,
            name: "test".to_string(),
            value: 42,
        };

        assert!(!storage.exists("identities", &key).await.unwrap());

        storage.put("identities", &key, &data).await.unwrap();

        assert!(storage.exists("identities", &key).await.unwrap());
    }

    #[tokio::test]
    async fn test_delete() {
        let storage = RocksDbStorage::open_test().unwrap();
        let key = Uuid::new_v4();
        let data = TestData {
            id: key,
            name: "test".to_string(),
            value: 42,
        };

        storage.put("identities", &key, &data).await.unwrap();

        assert!(storage.exists("identities", &key).await.unwrap());

        storage.delete("identities", &key).await.unwrap();

        assert!(!storage.exists("identities", &key).await.unwrap());
    }

    #[tokio::test]
    async fn test_batch_commit() {
        let storage = RocksDbStorage::open_test().unwrap();

        let key1 = Uuid::new_v4();
        let key2 = Uuid::new_v4();

        let data1 = TestData {
            id: key1,
            name: "test1".to_string(),
            value: 1,
        };
        let data2 = TestData {
            id: key2,
            name: "test2".to_string(),
            value: 2,
        };

        let mut batch = storage.batch();
        batch.put("identities", &key1, &data1).unwrap();
        batch.put("identities", &key2, &data2).unwrap();
        batch.commit().await.unwrap();

        let result1: Option<TestData> = storage.get("identities", &key1).await.unwrap();
        let result2: Option<TestData> = storage.get("identities", &key2).await.unwrap();

        assert_eq!(result1, Some(data1));
        assert_eq!(result2, Some(data2));
    }

    #[tokio::test]
    async fn test_batch_rollback() {
        let storage = RocksDbStorage::open_test().unwrap();

        let key = Uuid::new_v4();
        let data = TestData {
            id: key,
            name: "test".to_string(),
            value: 42,
        };

        let mut batch = storage.batch();
        batch.put("identities", &key, &data).unwrap();
        batch.rollback();

        let result: Option<TestData> = storage.get("identities", &key).await.unwrap();
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_get_by_prefix() {
        let storage = RocksDbStorage::open_test().unwrap();

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();

        let key1 = (id1, Uuid::new_v4());
        let key2 = (id1, Uuid::new_v4());
        let key3 = (id2, Uuid::new_v4());

        storage
            .put("machine_keys_by_identity", &key1, &())
            .await
            .unwrap();
        storage
            .put("machine_keys_by_identity", &key2, &())
            .await
            .unwrap();
        storage
            .put("machine_keys_by_identity", &key3, &())
            .await
            .unwrap();

        let results: Vec<(Vec<u8>, ())> = storage
            .get_by_prefix("machine_keys_by_identity", &id1)
            .await
            .unwrap();

        assert_eq!(results.len(), 2);
    }
}
