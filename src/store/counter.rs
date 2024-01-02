use std::sync::Arc;

use super::{Store, StoreError};

/// A counter that is stored in a store
///
/// It is used to keep track of the number of times for specific keys are used
#[derive(Debug)]
pub struct InStoreCounter {
    /// The store that the counter is stored in
    pub store: Arc<dyn Store>,

    /// The key of the counter
    pub key: String,
}

impl InStoreCounter {
    /// Create a new counter
    pub fn new(store: Arc<dyn Store>, key: String) -> Self {
        Self { store, key }
    }

    /// Get the count of the key
    pub async fn get(&self) -> Result<usize, StoreError> {
        self.store
            .get(&self.key)
            .await
            .map_err(|_| StoreError::GetError)?
            .unwrap_or("0".to_string())
            .parse::<usize>()
            .map_err(StoreError::Parse)
    }

    /// Set the count of the key
    pub async fn set(&self, count: usize) -> Result<(), StoreError> {
        self.store.set(&self.key, &count.to_string()).await?;
        Ok(())
    }

    /// Increment the count of the key
    pub async fn increment(&self) -> Result<usize, StoreError> {
        let current_count = self.get().await?;
        let new_count = current_count + 1;
        self.set(new_count).await?;
        Ok(new_count)
    }
}
