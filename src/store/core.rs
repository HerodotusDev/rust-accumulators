use async_trait::async_trait;
use std::{collections::HashMap, fmt::Debug, num::ParseIntError};
use thiserror::Error;

/// An error that can occur when using a store
#[derive(Error, Debug)]
pub enum StoreError {
    /// Failed to get a value from the store
    #[error("Fail to get value from store")]
    GetError,
    /// Failed to set a value in the store
    #[error("Fail to set value in store")]
    SetError,
    /// Failed to delete a value from the store
    #[error("Fail to delete value from store")]
    DeleteError,
    /// Failed to get many values from the store
    #[error("Fail to get many values from store")]
    GetManyError,
    /// Failed to set many values in the store
    #[error("Fail to set many values in store")]
    SetManyError,
    /// Failed to delete many values from the store
    #[error("Fail to delete many values from store")]
    DeleteManyError,
    /// An underlying SQLite error
    #[cfg(all(feature = "sqlite", not(target_family = "wasm")))]
    #[error("SQLite error: {0}")]
    SQLite(#[from] sqlx::Error),
    /// Failed to parse a stored value
    #[error("Parse error: {0}")]
    Parse(#[from] ParseIntError),
    /// A wrapped error from an arbitrary error type
    #[error("Custom error: {0:?}")]
    Custom(Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// Define common behavior for all stores
#[async_trait]
pub trait Store: Send + Sync + Debug {
    /// Helper function to get the store identifier - useful for debugging
    fn id(&self) -> String;
    /// Get a value from the store
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] if the value cannot be retrieved.
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Get many values from the store
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] if the values cannot be retrieved.
    async fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>, StoreError>;

    /// Set a value in the store
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] if the value cannot be written.
    async fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;

    /// Set many values in the store
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] if the values cannot be written.
    async fn set_many(&self, entries: HashMap<String, String>) -> Result<(), StoreError>;

    /// Delete a value from the store
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] if the value cannot be deleted.
    async fn delete(&self, key: &str) -> Result<(), StoreError>;

    /// Delete many values from the store
    ///
    /// # Errors
    ///
    /// Returns a [`StoreError`] if the values cannot be deleted.
    async fn delete_many(&self, keys: Vec<&str>) -> Result<(), StoreError>;
}
