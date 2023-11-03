use std::rc::Rc;

use super::Store;
use anyhow::Result;

pub struct InStoreCounter<S> {
    store: Rc<S>,
    key: String,
}

impl<S> InStoreCounter<S>
where
    S: Store,
{
    // constructor
    pub fn new(store: Rc<S>, key: String) -> Self {
        Self { store, key }
    }

    pub fn get(&self) -> usize {
        let current_count = self
            .store
            .get(&self.key)
            .unwrap()
            .unwrap_or("0".to_string());
        current_count.parse::<usize>().unwrap()
    }

    // set
    pub fn set(&self, count: usize) -> Result<()> {
        self.store.set(&self.key, &count.to_string())?;
        Ok(())
    }

    // increment
    pub fn increment(&self) -> Result<usize> {
        let current_count = self.get();
        let new_count = current_count + 1;
        self.set(new_count)?;
        Ok(new_count)
    }
}
