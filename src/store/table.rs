use std::sync::Mutex;
use std::{collections::HashMap, sync::Arc};

use super::IStore;

pub struct InStoreTable {
    store: Arc<Mutex<dyn IStore>>,
    key: String,
}

impl InStoreTable {
    pub fn new(store: &Arc<Mutex<dyn IStore>>, key: String) -> Self {
        Self {
            store: Arc::clone(store),
            key,
        }
    }

    fn get_full_key(&self, suffix: Option<String>) -> String {
        format!("{}{}", self.key, suffix.unwrap_or_default())
    }

    pub async fn get(&self, suffix: Option<String>) -> Option<String> {
        let store = self.store.lock().unwrap();
        store.get(&self.get_full_key(suffix)).unwrap()
    }

    pub async fn get_many<T: ToString>(&self, suffixes: Vec<T>) -> HashMap<String, String> {
        let keys: Vec<String> = suffixes
            .iter()
            .map(|s| self.get_full_key(Some(s.to_string())))
            .collect();
        let keys_ref: Vec<&str> = keys.iter().map(AsRef::as_ref).collect();
        let store = self.store.lock().unwrap();
        let result_map = store.get_many(keys_ref).unwrap();

        let mut keyless = HashMap::new();
        for suffix in &suffixes {
            let full_key = self.get_full_key(Some(suffix.to_string()));
            if let Some(value) = result_map.get(&full_key) {
                let keyless_key: String = full_key.split(':').skip(2).collect::<Vec<_>>().join(":");
                keyless.insert(keyless_key, value.clone());
            }
        }

        keyless
    }
    pub fn set(&self, value: &str, suffix: Option<String>) {
        let mut store = self.store.lock().unwrap();
        store.set(self.get_full_key(suffix).as_str(), value);
    }

    pub fn set_many(&self, entries: HashMap<String, String>) {
        let mut store = self.store.lock().unwrap();
        store.set_many(entries).unwrap();
    }
}
