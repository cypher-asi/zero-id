//! # zero-auth-storage
//!
//! Storage abstraction layer for zero-auth using RocksDB.
//!
//! This crate provides the storage interface and RocksDB implementation
//! as specified in the architecture documents.

#![warn(clippy::all)]

pub mod column_families;
pub mod errors;
pub mod rocksdb_impl;
pub mod traits;

pub use column_families::*;
pub use errors::{Result, StorageError};
pub use rocksdb_impl::RocksDbStorage;
pub use traits::{Batch, Storage};
