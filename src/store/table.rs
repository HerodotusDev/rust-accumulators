use super::{Store, StoreError};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use thiserror::Error;

type StoreArc = Arc<dyn Store>;
type KeyList = Vec<String>;
type StoreKeysPair = (StoreArc, KeyList);
type StoreKeysList = Vec<StoreKeysPair>;

/// A sub key that is used to get a value from a store
#[derive(Debug, Clone, PartialEq, Eq)]
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

impl Hash for SubKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_string().hash(state);
    }
}

/// A function that is used to get the full key and store for a given sub_key
pub type GetFullKeyAndStoreFn =
    fn(&InStoreTable, SubKey) -> Result<(Arc<dyn Store>, String), InStoreTableError>;
/// A function that is used to get the full keys and stores for a given list of sub_keys
pub type GetFullKeysAndStoresFn =
    fn(&InStoreTable, Vec<SubKey>) -> Result<Vec<(Arc<dyn Store>, Vec<String>)>, InStoreTableError>;

#[cfg(feature = "stacked_mmr")]
#[derive(Debug, Clone)]
pub struct SubMMR {
    pub size: usize,
    pub key: String,
    pub store: Arc<dyn Store>,
}

/// An error that can occur when using an InStoreTable
#[derive(Error, Debug)]
pub enum InStoreTableError {
    #[error("Some keys were not found")]
    NotFound,
    #[error("Store error: {0}")]
    Store(#[from] StoreError),
    #[error("Could not decode store key")]
    CouldNotDecodeStoreKey,
    #[error("Sub MMRs are not set")]
    SubMMRsNotSet,
}

/// A table that is stored in a store
#[derive(Debug, Clone)]
pub struct InStoreTable {
    /// Always use this store for setters
    ///
    /// For getters use the store provided by the get_full_key... functions
    pub store: Arc<dyn Store>,
    /// Always use this key for setters
    ///
    /// For getters use the key provided by the get_full_key... functions
    pub key: String,
    /// This function is used to get the full key and store for a given sub_key
    ///
    /// The default implementation is to use the store and key provided by the InStoreTable
    pub get_store_and_full_key: GetFullKeyAndStoreFn,
    /// This function is used to get the full keys and stores for a given list of sub_keys
    ///
    /// The default implementation is to use the store and key provided by the InStoreTable
    pub get_stores_and_full_keys: GetFullKeysAndStoresFn,
    #[cfg(feature = "stacked_mmr")]
    pub sub_mmrs: Option<Vec<SubMMR>>,
}

impl InStoreTable {
    /// Create a new table
    pub fn new(store: Arc<dyn Store>, key: String) -> Self {
        Self {
            store,
            key,
            get_store_and_full_key: Self::default_get_store_and_full_key,
            get_stores_and_full_keys: Self::default_get_stores_and_full_keys,
            #[cfg(feature = "stacked_mmr")]
            sub_mmrs: None,
        }
    }

    /// Get the full key for a given sub_key/key
    pub fn get_full_key(key: &str, sub_key: &str) -> String {
        format!("{}{}", key, sub_key)
    }

    /// Get the full key and store for a given sub_key
    pub fn default_get_store_and_full_key(
        &self,
        sub_key: SubKey,
    ) -> Result<(Arc<dyn Store>, String), InStoreTableError> {
        let new_sub_key = sub_key.to_string();
        Ok((
            self.store.clone(),
            InStoreTable::get_full_key(&self.key, &new_sub_key),
        ))
    }

    /// Get the full keys and stores for a given list of sub_keys
    pub fn default_get_stores_and_full_keys(
        &self,
        sub_keys: Vec<SubKey>,
    ) -> Result<StoreKeysList, InStoreTableError> {
        let sub_keys: Vec<String> = sub_keys
            .into_iter()
            .map(|sub_key| InStoreTable::get_full_key(&self.key, &sub_key.to_string()))
            .collect();
        Ok(vec![(self.store.clone(), sub_keys)])
    }

    /// Get the value from full key that retrieved from the sub_key
    pub async fn get(&self, sub_key: SubKey) -> Result<Option<String>, InStoreTableError> {
        let (store, full_key) = (self.get_store_and_full_key)(self, sub_key)?;
        Ok(store.get(&full_key).await.unwrap_or_default())
    }

    /// Get the values from full keys that retrieved from the sub_keys
    pub async fn get_many(
        &self,
        sub_keys: Vec<SubKey>,
    ) -> Result<HashMap<String, String>, InStoreTableError> {
        let requested_len = sub_keys.len();
        let stores_and_keys = (self.get_stores_and_full_keys)(self, sub_keys);

        let mut keyless = HashMap::new();
        for store_and_keys in stores_and_keys? {
            let (store, keys) = store_and_keys;
            let keys_ref: Vec<&str> = keys.iter().map(AsRef::as_ref).collect();
            let fetched = store.get_many(keys_ref).await?;

            for (key, value) in fetched.iter() {
                let new_key: String = if key.contains(':') {
                    key.split(':').skip(2).collect::<Vec<&str>>().join(":")
                } else {
                    key.clone()
                };
                keyless.insert(new_key, value.clone());
            }
        }

        if keyless.len() != requested_len {
            Err(InStoreTableError::NotFound)
        } else {
            Ok(keyless)
        }
    }

    /// Set the value from full key that retrieved from the sub_key
    pub async fn set(&self, value: &str, sub_key: SubKey) -> Result<(), InStoreTableError> {
        let (store, key) = (self.get_store_and_full_key)(self, sub_key)?;
        store.set(&key, value).await?;
        Ok(())
    }

    /// Set the values from full keys that retrieved from the sub_keys
    pub async fn set_many(
        &self,
        entries: HashMap<SubKey, String>,
    ) -> Result<(), InStoreTableError> {
        let mut store_entries = HashMap::new();

        for (key, value) in entries.into_iter() {
            let full_key = InStoreTable::get_full_key(&self.key, &key.to_string());
            store_entries.insert(full_key, value.clone());
        }

        self.store.set_many(store_entries).await?;

        Ok(())
    }
}
