use std::{collections::HashMap, sync::Arc};

use super::IStore;

pub struct InStoreTable {
    store: Arc<dyn IStore>,
    key: String,
}

impl InStoreTable {
    pub fn new(store: &Arc<dyn IStore>, key: String) -> Self {
        Self {
            store: Arc::clone(store),
            key,
        }
    }

    fn get_full_key(&self, suffix: Option<String>) -> String {
        format!("{}{}", self.key, suffix.unwrap_or_default())
    }

    pub async fn get(&self, suffix: Option<String>) -> Option<String> {
        self.store.get(self.get_full_key(suffix).as_str()).unwrap()
    }

    pub async fn get_many<T: ToString>(&self, suffixes: Vec<T>) -> HashMap<String, String> {
        let keys: Vec<String> = suffixes
            .iter()
            .map(|s| self.get_full_key(Some(s.to_string())))
            .collect();
        let keys_ref: Vec<&str> = keys.iter().map(AsRef::as_ref).collect();
        let mut result_map = self.store.get_many(keys_ref);

        let mut keyless = HashMap::new();
        for suffix in &suffixes {
            let full_key = self.get_full_key(Some(suffix.to_string()));
            if let Some(value) = result_map.as_mut().unwrap().get(&full_key) {
                let keyless_key: String = full_key.split(':').skip(2).collect::<Vec<_>>().join(":");
                keyless.insert(keyless_key, value.clone());
            }
        }

        keyless
    }
    pub fn set(&mut self, value: &str, suffix: Option<String>) {
        self.store.set(self.get_full_key(suffix).as_str(), value);
    }

    pub fn set_many(&mut self, entries: Vec<(String, String)>) {
        let mut store_entries: HashMap<&str, &str> = HashMap::new();

        for (k, v) in entries.iter() {
            let full_key = self.get_full_key(Some(k.clone()));
            store_entries.insert(full_key.as_str(), v);
        }

        self.store.set_many(store_entries);
    }
}
