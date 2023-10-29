use std::collections::HashMap;
use std::rc::Rc;

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
        format!("{}{}", self.key, suffix.unwrap_or("".to_string()))
    }

    pub fn get(&self, suffix: Option<String>) -> Option<String> {
        self.store.get(&self.get_full_key(suffix)).unwrap()
    }

    pub fn get_many(&self, suffixes: Vec<String>) -> HashMap<String, String> {
        let keys_str: Vec<String> = suffixes
            .iter()
            .map(|suffix| self.get_full_key(Some(suffix.to_string())))
            .collect();

        let keys_ref: Vec<&str> = keys_str.iter().map(AsRef::as_ref).collect();

        let fetched = self.store.get_many(keys_ref).unwrap(); // Assuming get_many is async and returns a Result

        let mut keyless = HashMap::new();
        for (key, value) in fetched.iter() {
            let new_key: String = if key.contains(":") {
                key.split(":").skip(2).collect::<Vec<&str>>().join(":")
            } else {
                key.clone()
            };
            println!("newkey:{} old key:{} value:{}", new_key, key, value);
            keyless.insert(new_key, value.clone());
        }

        keyless
    }
    pub fn set(&self, value: &str, suffix: Option<String>) {
        self.store.set(self.get_full_key(suffix).as_str(), value);
    }

    pub fn set_many(&self, entries: HashMap<String, String>) {
        let mut store_entries = HashMap::new();
        for (key, value) in entries.iter() {
            let full_key = self.get_full_key(Some(key.to_string())); // Assume get_full_key is another function
            store_entries.insert(full_key, value.clone());
        }
        self.store.set_many(store_entries).unwrap();
    }
}
