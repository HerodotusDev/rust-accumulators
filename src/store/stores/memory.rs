use std::collections::HashMap;

use anyhow::Result;
use parking_lot::RwLock;

use crate::store::Store;

pub struct InMemoryStore {
    store: RwLock<HashMap<String, String>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

impl Store for InMemoryStore {
    fn get(&self, key: &str) -> Result<Option<String>> {
        let store = self.store.read();
        Ok(store.get(key).cloned())
    }

    fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>> {
        let store = self.store.read();
        let result = keys
            .into_iter()
            .filter_map(|key| store.get(key).map(|value| (key.to_string(), value.clone())))
            .collect();
        Ok(result)
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        let mut store = self.store.write();
        store.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn set_many(&self, entries: HashMap<String, String>) -> Result<()> {
        let mut store = self.store.write();
        for (key, value) in entries {
            store.insert(key, value);
        }
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut store = self.store.write();
        store.remove(key);
        Ok(())
    }

    fn delete_many(&self, keys: Vec<&str>) -> Result<()> {
        let mut store = self.store.write();
        for key in keys {
            store.remove(key);
        }
        Ok(())
    }
}
