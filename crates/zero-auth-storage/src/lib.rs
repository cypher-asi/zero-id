//! # zero-auth-storage
//!
//! Storage abstraction layer for zero-auth using RocksDB.
//!
//! This crate provides the storage interface and RocksDB implementation
//! as specified in the architecture documents.

#![warn(clippy::all)]

pub mod column_families;
pub mod errors;
pub mod traits;
pub mod rocksdb_impl;

pub use column_families::*;
pub use errors::{StorageError, Result};
pub use traits::{Storage, Batch};
pub use rocksdb_impl::RocksDbStorage;
