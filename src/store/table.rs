use std::rc::Rc;
use std::sync::Mutex;
use std::{collections::HashMap, sync::Arc};

use super::IStore;

pub struct InStoreTable<S> {
    store: Rc<S>,
    key: String,
}

impl<S> InStoreTable<S>
where
    S: IStore,
{
    pub fn new(store: Rc<S>, key: String) -> Self {
        Self { store, key }
    }

    fn get_full_key(&self, suffix: Option<String>) -> String {
        format!("{}{}", self.key, suffix.unwrap_or_default())
    }

    pub async fn get(&self, suffix: Option<String>) -> Option<String> {
        self.store.get(&self.get_full_key(suffix)).unwrap()
    }

    pub async fn get_many<T: ToString>(&self, suffixes: Vec<T>) -> HashMap<String, String> {
        let keys: Vec<String> = suffixes
            .iter()
            .map(|s| self.get_full_key(Some(s.to_string())))
            .collect();
        let keys_ref: Vec<&str> = keys.iter().map(AsRef::as_ref).collect();
        let result_map = self.store.get_many(keys_ref).unwrap();

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
        self.store.set(self.get_full_key(suffix).as_str(), value);
    }

    pub fn set_many(&self, entries: HashMap<String, String>) {
        self.store.set_many(entries).unwrap();
    }
}
