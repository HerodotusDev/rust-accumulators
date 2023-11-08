use std::collections::HashMap;
use std::fmt::Display;
use std::rc::Rc;

use super::Store;

pub struct InStoreTable {
    pub key: String,
}

impl InStoreTable {
    pub fn new(key: String) -> Self {
        Self { key }
    }

    fn get_full_key<T: ToString + Display>(&self, sub_key: Option<T>) -> String {
        let new_sub_key = match sub_key {
            Some(sub_key) => sub_key.to_string(),
            None => "".to_string(),
        };
        format!("{}{}", self.key, new_sub_key)
    }

    pub fn get<T: ToString + Display>(
        &self,
        store: Rc<dyn Store>,
        sub_key: Option<T>,
    ) -> Option<String> {
        let full_key = &self.get_full_key(sub_key);
        store.get(full_key).unwrap_or_default()
    }

    pub fn get_many<T: ToString + Display>(
        &self,
        store: Rc<dyn Store>,
        sub_keyes: Vec<T>,
    ) -> HashMap<String, String> {
        let keys_str: Vec<String> = sub_keyes
            .iter()
            .map(|sub_key| self.get_full_key(Some(sub_key)))
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

    pub fn set<T: ToString + Display>(
        &self,
        store: Rc<dyn Store>,
        value: &str,
        sub_key: Option<T>,
    ) {
        store
            .set(self.get_full_key(sub_key).as_str(), value)
            .expect("Failed to set value")
    }

    pub fn set_many(&self, store: Rc<dyn Store>, entries: HashMap<String, String>) {
        let mut store_entries = HashMap::new();
        for (key, value) in entries.iter() {
            let full_key = self.get_full_key(Some(key.to_string())); // Assume get_full_key is another function
            store_entries.insert(full_key, value.clone());
        }
        store
            .set_many(store_entries)
            .expect("Failed to set many values");
    }
}
