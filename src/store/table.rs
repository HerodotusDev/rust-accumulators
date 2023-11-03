use std::collections::HashMap;
use std::fmt::Display;
use std::rc::Rc;

use super::IStore;

pub trait ToKey {
    fn to_key(&self) -> String;
}

impl ToKey for String {
    fn to_key(&self) -> String {
        self.clone()
    }
}

impl ToKey for usize {
    fn to_key(&self) -> String {
        self.to_string()
    }
}

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

    fn get_full_key<T: ToKey + Display>(&self, suffix: Option<T>) -> String {
        let new_suffix = match suffix {
            Some(suffix) => suffix.to_key(),
            None => "".to_string(),
        };
        format!("{}{}", self.key.to_key(), new_suffix)
    }

    pub fn get<T: ToKey>(&self, suffix: Option<T>) -> Option<String> {
        let new_suffix = match suffix {
            Some(suffix) => Some(suffix.to_key()),
            None => None,
        };
        let full_key = &self.get_full_key(new_suffix);
        self.store.get(full_key).unwrap_or_default()
    }

    pub fn get_many<T: ToKey>(&self, suffixes: Vec<T>) -> HashMap<String, String> {
        let keys_str: Vec<String> = suffixes
            .iter()
            .map(|suffix| self.get_full_key(Some(suffix.to_key())))
            .collect();

        let keys_ref: Vec<&str> = keys_str.iter().map(AsRef::as_ref).collect();

        let fetched = self.store.get_many(keys_ref).unwrap_or_default(); // Assuming get_many is async and returns a Result

        let mut keyless = HashMap::new();
        for (key, value) in fetched.iter() {
            let new_key: String = if key.contains(":") {
                key.split(":").skip(2).collect::<Vec<&str>>().join(":")
            } else {
                key.clone()
            };
            keyless.insert(new_key, value.clone());
        }

        keyless
    }
    pub fn set<T: ToKey + Display>(&self, value: &str, suffix: Option<T>) {
        let _ = self.store.set(self.get_full_key(suffix).as_str(), value);
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
