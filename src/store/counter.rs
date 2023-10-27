use std::sync::Arc;

use super::IStore;
use rusqlite::Result;

pub struct InStoreCounter {
    store: Arc<dyn IStore>,
    key: String,
}

impl InStoreCounter {
    // constructor
    pub fn new(store: &Arc<dyn IStore>, key: String) -> Self {
        Self {
            store: Arc::clone(store),
            key,
        }
    }

    // get
    pub fn get(&self) -> Result<String> {
        Ok(self.store.get(&self.key).unwrap().unwrap())
    }

    // set
    pub fn set(&self, count: usize) -> Result<()> {
        self.store.set(&self.key, &count.to_string()).unwrap();
        Ok(())
    }

    // increment
    pub fn increment(&self) -> Result<usize> {
        let current_count: usize = self.get().unwrap().parse().unwrap();
        let new_count = current_count + 1;
        self.set(new_count);
        Ok(new_count)
    }
}
