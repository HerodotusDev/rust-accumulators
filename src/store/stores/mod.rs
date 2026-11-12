//! Ready-made [`Store`](crate::store::Store) implementations.

/// An in-memory key-value store
#[cfg(feature = "memory")]
pub mod memory;
/// A SQLite-backed key-value store
#[cfg(feature = "sqlite")]
pub mod sqlite;
