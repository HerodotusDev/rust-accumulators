use std::rc::Rc;

use super::Store;
use anyhow::Result;

pub struct InStoreCounter {
    key: String,
}

impl InStoreCounter {
    pub fn new(key: String) -> Self {
        Self { key }
    }

    pub fn get(&self, store: Rc<dyn Store>) -> usize {
        let current_count = store.get(&self.key).unwrap().unwrap_or("0".to_string());
        current_count.parse::<usize>().unwrap()
    }

    pub fn set(&self, store: Rc<dyn Store>, count: usize) -> Result<()> {
        store.set(&self.key, &count.to_string())?;
        Ok(())
    }

    pub fn increment(&self, store: Rc<dyn Store>) -> Result<usize> {
        let current_count = self.get(store.clone());
        let new_count = current_count + 1;
        self.set(store.clone(), new_count)?;
        Ok(new_count)
    }
}
