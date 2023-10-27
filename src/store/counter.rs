use super::IStore;
use rusqlite::Result;
use std::sync::{Arc, Mutex};

pub struct InStoreCounter {
    store: Arc<Mutex<dyn IStore>>,
    key: String,
}

impl InStoreCounter {
    // constructor
    pub fn new(store: &Arc<Mutex<dyn IStore>>, key: String) -> Self {
        Self {
            store: Arc::clone(store),
            key,
        }
    }

    // get
    pub fn get(&self) -> Result<String> {
        let store = self.store.lock().unwrap();
        Ok(store.get(&self.key)?.unwrap())
    }

    // set
    pub fn set(&self, count: usize) -> Result<()> {
        let mut store = self.store.lock().unwrap();
        store.set(&self.key, &count.to_string())?;
        Ok(())
    }

    // increment
    pub fn increment(&self) -> Result<usize> {
        let mut store = self.store.lock().unwrap();
        let current_count: usize = store.get(&self.key)?.unwrap().parse().unwrap();
        let new_count = current_count + 1;
        self.set(new_count)?;
        Ok(new_count)
    }
}
