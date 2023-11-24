use std::sync::Arc;

use super::Store;
use anyhow::Result;

pub struct InStoreCounter {
    pub store: Arc<dyn Store>,
    pub key: String,
}

impl InStoreCounter {
    pub fn new(store: Arc<dyn Store>, key: String) -> Self {
        Self { store, key }
    }

    pub async fn get(&self) -> usize {
        let current_count = self
            .store
            .get(&self.key)
            .await
            .expect("Failed to get count")
            .unwrap_or("0".to_string());
        current_count
            .parse::<usize>()
            .expect("Failed to parse count")
    }

    pub async fn set(&self, count: usize) -> Result<()> {
        self.store.set(&self.key, &count.to_string()).await?;
        Ok(())
    }

    pub async fn increment(&self) -> Result<usize> {
        let current_count = self.get().await;
        let new_count = current_count + 1;
        self.set(new_count).await?;
        Ok(new_count)
    }
}
