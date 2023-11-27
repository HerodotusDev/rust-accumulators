use std::collections::HashMap;

use anyhow::Result;
use async_trait::async_trait;
use parking_lot::RwLock;

use crate::store::Store;

#[derive(Debug)]
pub struct InMemoryStore {
    pub store: RwLock<HashMap<String, String>>,
}

impl Default for InMemoryStore {
    fn default() -> Self {
        Self {
            store: RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl Store for InMemoryStore {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        let store = self.store.read();
        Ok(store.get(key).cloned())
    }

    async fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>> {
        let store = self.store.read();
        let result = keys
            .into_iter()
            .filter_map(|key| store.get(key).map(|value| (key.to_string(), value.clone())))
            .collect();
        Ok(result)
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let mut store = self.store.write();
        store.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn set_many(&self, entries: HashMap<String, String>) -> Result<()> {
        let mut store = self.store.write();
        for (key, value) in entries {
            store.insert(key, value);
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let mut store = self.store.write();
        store.remove(key);
        Ok(())
    }

    async fn delete_many(&self, keys: Vec<&str>) -> Result<()> {
        let mut store = self.store.write();
        for key in keys {
            store.remove(key);
        }
        Ok(())
    }
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn clear(&self) {
        let mut store = self.store.write();
        store.clear();
    }
}
