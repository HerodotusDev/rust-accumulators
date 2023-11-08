use std::collections::HashMap;
use std::hash::Hash;
use std::rc::Rc;

use super::Store;

pub enum SubKey {
    String(String),
    Usize(usize),
    None,
}

impl ToString for SubKey {
    fn to_string(&self) -> String {
        match self {
            SubKey::String(sub_key) => sub_key.clone(),
            SubKey::Usize(sub_key) => sub_key.to_string(),
            SubKey::None => "".to_string(),
        }
    }
}

impl PartialEq for SubKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_string() == other.to_string()
    }
}

impl Eq for SubKey {}

impl Hash for SubKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_string().hash(state);
    }
}

pub type GetFullKeyAndStoreFn = fn(&InStoreTable, SubKey) -> (Rc<dyn Store>, String);
pub type GetFullKeysAndStoresFn =
    fn(&InStoreTable, Vec<SubKey>) -> Vec<(Rc<dyn Store>, Vec<String>)>;

pub struct InStoreTable {
    /// Always use this store for setters
    ///
    /// For getters use the store provided by the get_full_key... functions
    pub store: Rc<dyn Store>,
    /// Always use this key for setters
    ///
    /// For getters use the key provided by the get_full_key... functions
    pub key: String,
    /// This function is used to get the full key and store for a given sub_key
    ///
    /// The default implementation is to use the store and key provided by the InStoreTable
    pub get_full_key_and_store: GetFullKeyAndStoreFn,
    /// This function is used to get the full keys and stores for a given list of sub_keys
    ///
    /// The default implementation is to use the store and key provided by the InStoreTable
    pub get_full_keys_and_stores: GetFullKeysAndStoresFn,
}

impl InStoreTable {
    pub fn new(store: Rc<dyn Store>, key: String) -> Self {
        Self {
            store,
            key,
            get_full_key_and_store: Self::default_get_full_key_and_store,
            get_full_keys_and_stores: Self::default_get_full_keys_and_stores,
        }
    }

    pub fn get_full_key(key: &str, sub_key: &str) -> String {
        format!("{}{}", key, sub_key)
    }

    fn default_get_full_key_and_store(&self, sub_key: SubKey) -> (Rc<dyn Store>, String) {
        let new_sub_key = sub_key.to_string();
        (
            self.store.clone(),
            InStoreTable::get_full_key(&self.key, &new_sub_key),
        )
    }

    fn default_get_full_keys_and_stores(
        &self,
        sub_keys: Vec<SubKey>,
    ) -> Vec<(Rc<dyn Store>, Vec<String>)> {
        let sub_keys: Vec<String> = sub_keys
            .into_iter()
            .map(|sub_key| InStoreTable::get_full_key(&self.key, &sub_key.to_string()))
            .collect();
        vec![(self.store.clone(), sub_keys)]
    }

    pub fn get(&self, sub_key: SubKey) -> Option<String> {
        let (store, full_key) = (self.get_full_key_and_store)(self, sub_key);
        store.get(&full_key).unwrap_or_default()
    }

    pub fn get_many(&self, sub_keyes: Vec<SubKey>) -> HashMap<String, String> {
        let requested_len = sub_keyes.len();
        let stores_and_keys = (self.get_full_keys_and_stores)(self, sub_keyes);

        let mut keyless = HashMap::new();

        for store_and_keys in stores_and_keys {
            let (store, keys) = store_and_keys;
            let keys_ref: Vec<&str> = keys.iter().map(AsRef::as_ref).collect();
            let fetched = store.get_many(keys_ref).unwrap_or_default(); // Assuming get_many is async and returns a Result

            for (key, value) in fetched.iter() {
                let new_key: String = if key.contains(':') {
                    key.split(':').skip(2).collect::<Vec<&str>>().join(":")
                } else {
                    key.clone()
                };
                keyless.insert(new_key, value.clone());
            }
        }

        assert!(keyless.len() == requested_len, "Some keys were not found");
        keyless
    }

    pub fn set(&self, value: &str, sub_key: SubKey) {
        let (store, key) = (self.get_full_key_and_store)(self, sub_key);

        store.set(&key, value).expect("Failed to set value")
    }

    pub fn set_many(&self, entries: HashMap<SubKey, String>) {
        let mut store_entries = HashMap::new();

        for (key, value) in entries.into_iter() {
            let full_key = InStoreTable::get_full_key(&self.key, &key.to_string());
            store_entries.insert(full_key, value.clone());
        }

        self.store
            .set_many(store_entries)
            .expect("Failed to set many values");
    }
}
