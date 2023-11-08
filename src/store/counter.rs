use std::rc::Rc;

use super::Store;
use anyhow::Result;

pub struct InStoreCounter {
    pub store: Rc<dyn Store>,
    pub key: String,
}

impl InStoreCounter {
    pub fn new(store: Rc<dyn Store>, key: String) -> Self {
        Self { store, key }
    }

    pub fn get(&self) -> usize {
        let current_count = self
            .store
            .get(&self.key)
            .expect("Failed to get count")
            .unwrap_or("0".to_string());
        current_count
            .parse::<usize>()
            .expect("Failed to parse count")
    }

    pub fn set(&self, count: usize) -> Result<()> {
        self.store.set(&self.key, &count.to_string())?;
        Ok(())
    }

    pub fn increment(&self) -> Result<usize> {
        let current_count = self.get();
        let new_count = current_count + 1;
        self.set(new_count)?;
        Ok(new_count)
    }
}
