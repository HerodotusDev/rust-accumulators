//! Ready-made [`Store`](crate::store::Store) implementations.

/// An in-memory key-value store
#[cfg(feature = "memory")]
pub mod memory;
/// A SQLite-backed key-value store (native targets only — sqlx sqlite
/// does not compile on wasm; feature-unification turning `sqlite` on for a
/// wasm build is silently ignored rather than a build error)
#[cfg(all(feature = "sqlite", not(target_family = "wasm")))]
pub mod sqlite;
