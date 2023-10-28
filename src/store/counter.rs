use std::rc::Rc;

use super::IStore;
use rusqlite::Error as RusqliteError;
use rusqlite::Result;

pub struct InStoreCounter<S> {
    store: Rc<S>,
    key: String,
}

impl<S> InStoreCounter<S>
where
    S: IStore,
{
    // constructor
    pub fn new(store: Rc<S>, key: String) -> Self {
        Self { store, key }
    }

    pub fn get(&self) -> Result<usize, RusqliteError> {
        let current_count: usize = match self.store.get(&self.key)? {
            Some(val) => val.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
            None => return Err(rusqlite::Error::QueryReturnedNoRows),
        };
        Ok(current_count)
    }

    // set
    pub fn set(&self, count: usize) -> Result<()> {
        self.store.set(&self.key, &count.to_string())?;
        Ok(())
    }

    // increment
    pub fn increment(&self) -> Result<usize, rusqlite::Error> {
        let current_count: usize = match self.store.get(&self.key)? {
            Some(val) => val.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
            None => return Err(rusqlite::Error::QueryReturnedNoRows),
        };
        let new_count = current_count + 1;
        self.set(new_count)?;
        Ok(new_count)
    }
}
