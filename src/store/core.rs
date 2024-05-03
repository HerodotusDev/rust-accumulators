use async_trait::async_trait;
use std::{collections::HashMap, fmt::Debug, num::ParseIntError};
use thiserror::Error;

/// An error that can occur when using a store
#[derive(Error, Debug)]
pub enum StoreError {
    #[error(
        "
   Fail to get value from store"
    )]
    GetError,
    #[error("Fail to set value in store")]
    SetError,
    #[error("Fail to delete value from store")]
    DeleteError,
    #[error("Fail to get many values from store")]
    GetManyError,
    #[error("Fail to set many values in store")]
    SetManyError,
    #[error("Fail to delete many values from store")]
    DeleteManyError,
    #[error("SQLite error: {0}")]
    SQLite(#[from] sqlx::Error),
    #[error("Parse error: {0}")]
    Parse(#[from] ParseIntError),
}

/// Define common behavior for all stores
#[async_trait]
pub trait Store: Send + Sync + Debug {
    /// Helper function to get the store identifier - useful for debugging
    fn id(&self) -> String;
    /// Get a value from the store
    async fn get(&self, key: &str) -> Result<Option<String>, StoreError>;

    /// Get many values from the store
    async fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>, StoreError>;

    /// Set a value in the store
    async fn set(&self, key: &str, value: &str) -> Result<(), StoreError>;

    /// Set many values in the store
    async fn set_many(&self, entries: HashMap<String, String>) -> Result<(), StoreError>;

    /// Delete a value from the store
    async fn delete(&self, key: &str) -> Result<(), StoreError>;

    /// Delete many values from the store
    async fn delete_many(&self, keys: Vec<&str>) -> Result<(), StoreError>;
}
