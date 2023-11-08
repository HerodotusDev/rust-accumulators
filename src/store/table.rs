use std::collections::HashMap;
use std::rc::Rc;

use super::Store;

pub enum SubKey {
    String(String),
    Usize(usize),
    None,
}

pub struct InStoreTable {
    pub key: String,
    pub get_full_key: fn(&InStoreTable, SubKey) -> String,
}

impl InStoreTable {
    pub fn new(key: String) -> Self {
        Self {
            key,
            get_full_key: Self::default_get_full_key,
        }
    }

    fn default_get_full_key(&self, sub_key: SubKey) -> String {
        let new_sub_key = match sub_key {
            SubKey::String(sub_key) => sub_key,
            SubKey::Usize(sub_key) => sub_key.to_string(),
            SubKey::None => "".to_string(),
        };
        format!("{}{}", self.key, new_sub_key)
    }

    pub fn get(&self, store: Rc<dyn Store>, sub_key: SubKey) -> Option<String> {
        let full_key = (self.get_full_key)(self, sub_key);
        store.get(&full_key).unwrap_or_default()
    }

    pub fn get_many(
        &self,
        store: Rc<dyn Store>,
        sub_keyes: Vec<SubKey>,
    ) -> HashMap<String, String> {
        let keys_str: Vec<String> = sub_keyes
            .into_iter()
            .map(|sub_key| (self.get_full_key)(self, sub_key))
            .collect();

        let keys_ref: Vec<&str> = keys_str.iter().map(AsRef::as_ref).collect();

        let fetched = store.get_many(keys_ref).unwrap_or_default(); // Assuming get_many is async and returns a Result

        let mut keyless = HashMap::new();
        for (key, value) in fetched.iter() {
            let new_key: String = if key.contains(':') {
                key.split(':').skip(2).collect::<Vec<&str>>().join(":")
            } else {
                key.clone()
            };
            keyless.insert(new_key, value.clone());
        }

        keyless
    }

    pub fn set(&self, store: Rc<dyn Store>, value: &str, sub_key: SubKey) {
        store
            .set((self.get_full_key)(self, sub_key).as_str(), value)
            .expect("Failed to set value")
    }

    pub fn set_many(&self, store: Rc<dyn Store>, entries: HashMap<String, String>) {
        let mut store_entries = HashMap::new();
        for (key, value) in entries.into_iter() {
            let full_key = (self.get_full_key)(self, SubKey::String(key)); // Assume get_full_key is another function
            store_entries.insert(full_key, value.clone());
        }
        store
            .set_many(store_entries)
            .expect("Failed to set many values");
    }
}
