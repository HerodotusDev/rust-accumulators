use super::{Store, StoreError};
use std::collections::HashMap;
use std::fmt::{self, Display, Formatter, Result as FmtResult};
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
    /// A sub key that holds a `String`
    String(String),
    /// A sub key that holds a `usize`
    Usize(usize),
    /// An empty sub key
    None,
}

impl Display for SubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SubKey::String(sub_key) => write!(f, "{sub_key}"),
            SubKey::Usize(sub_key) => write!(f, "{sub_key}"),
            SubKey::None => write!(f, ""),
        }
    }
}

impl Hash for SubKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_string().hash(state);
    }
}

/// A function that is used to get the full key and store for a given `sub_key`
pub type GetFullKeyAndStoreFn =
    fn(&InStoreTable, &SubKey) -> Result<(Arc<dyn Store>, String), InStoreTableError>;
/// A function that is used to get the full keys and stores for a given list of `sub_keys`
pub type GetFullKeysAndStoresFn =
    fn(&InStoreTable, &[SubKey]) -> Result<Vec<(Arc<dyn Store>, Vec<String>)>, InStoreTableError>;

/// A sub MMR that is stored in a store
#[cfg(feature = "stacked_mmr")]
#[derive(Debug, Clone)]
pub struct SubMMR {
    /// The size of the sub MMR
    pub size: usize,
    /// The key of the sub MMR in its store
    pub key: String,
    /// The store that the sub MMR is stored in
    pub store: Arc<dyn Store>,
}

/// Values that were not found in their stores
#[derive(Error, Debug)]
pub struct MissingValues {
    /// A map from store identifiers to the keys that were not found in them
    pub stores_with_missing_keys: HashMap<String, Vec<String>>,
}

impl Display for MissingValues {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let formatted_output = self
            .stores_with_missing_keys
            .iter()
            .map(|(store, keys)| format!("{store}: {}", keys.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");

        write!(f, "{{{formatted_output}}}")
    }
}

/// An error that can occur when using an [`InStoreTable`]
#[derive(Error, Debug)]
pub enum InStoreTableError {
    /// One or more keys were not found in their stores
    #[error("Some keys were not found for stores: {0}")]
    NotFound(#[from] MissingValues),
    /// An error occurred in the underlying store
    #[error("Store error: {0}")]
    Store(#[from] StoreError),
    /// A store key could not be decoded
    #[error("Could not decode store key")]
    CouldNotDecodeStoreKey,
    /// The sub MMRs were not set on the table
    #[error("Sub MMRs are not set")]
    SubMMRsNotSet,
}

/// A table that is stored in a store
#[derive(Debug, Clone)]
pub struct InStoreTable {
    /// Always use this store for setters
    ///
    /// For getters use the store provided by the `get_full_key` functions
    pub store: Arc<dyn Store>,
    /// Always use this key for setters
    ///
    /// For getters use the key provided by the `get_full_key` functions
    pub key: String,
    /// This function is used to get the full key and store for a given `sub_key`
    ///
    /// The default implementation is to use the store and key provided by the [`InStoreTable`]
    pub get_store_and_full_key: GetFullKeyAndStoreFn,
    /// This function is used to get the full keys and stores for a given list of `sub_keys`
    ///
    /// The default implementation is to use the store and key provided by the [`InStoreTable`]
    pub get_stores_and_full_keys: GetFullKeysAndStoresFn,
    /// The sub MMRs that are used by the table
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

    /// Get the full key for a given `key` and `sub_key`
    #[must_use]
    pub fn get_full_key(key: &str, sub_key: &str) -> String {
        format!("{key}{sub_key}")
    }

    /// Get the full key and store for a given `sub_key`
    ///
    /// # Errors
    ///
    /// Returns an [`InStoreTableError`] if the full key cannot be constructed.
    pub fn default_get_store_and_full_key(
        &self,
        sub_key: &SubKey,
    ) -> Result<(Arc<dyn Store>, String), InStoreTableError> {
        let new_sub_key = sub_key.to_string();
        Ok((
            self.store.clone(),
            InStoreTable::get_full_key(&self.key, &new_sub_key),
        ))
    }

    /// Get the full keys and stores for a given list of `sub_keys`
    ///
    /// # Errors
    ///
    /// Returns an [`InStoreTableError`] if the full keys cannot be constructed.
    pub fn default_get_stores_and_full_keys(
        &self,
        sub_keys: &[SubKey],
    ) -> Result<StoreKeysList, InStoreTableError> {
        let sub_keys: Vec<String> = sub_keys
            .iter()
            .map(|sub_key| InStoreTable::get_full_key(&self.key, &sub_key.to_string()))
            .collect();
        Ok(vec![(self.store.clone(), sub_keys)])
    }

    /// Get the value from full key that retrieved from the `sub_key`
    ///
    /// # Errors
    ///
    /// Returns an [`InStoreTableError`] if the store cannot be resolved or the lookup fails.
    pub async fn get(&self, sub_key: &SubKey) -> Result<Option<String>, InStoreTableError> {
        let (store, full_key) = (self.get_store_and_full_key)(self, sub_key)?;
        Ok(store.get(&full_key).await.unwrap_or_default())
    }

    /// Get the values from full keys that retrieved from the `sub_keys`
    ///
    /// # Errors
    ///
    /// Returns [`InStoreTableError::NotFound`] if any key is missing from its store,
    /// or an [`InStoreTableError`] if the lookup fails.
    pub async fn get_many(
        &self,
        sub_keys: &[SubKey],
    ) -> Result<HashMap<String, String>, InStoreTableError> {
        let stores_and_keys = (self.get_stores_and_full_keys)(self, sub_keys)?;

        let mut stores_with_missing_keys = HashMap::new();
        let mut retrieved_sub_keys_as_string = HashMap::new();
        for (store, keys) in stores_and_keys {
            let keys_ref: Vec<&str> = keys.iter().map(AsRef::as_ref).collect();
            let fetched = store.get_many(keys_ref).await?;

            //? Checking for missing keys
            let missing_keys = keys
                .into_iter()
                .filter(|key| !fetched.contains_key(key.as_str()))
                .collect::<Vec<_>>();
            if !missing_keys.is_empty() {
                stores_with_missing_keys.insert(store.id(), missing_keys);
            }

            //? Strapping full key to sub_key format and saving in the final hash map
            for (key, value) in &fetched {
                let new_key: String = if key.contains(':') {
                    key.split(':').skip(2).collect::<Vec<&str>>().join(":")
                } else {
                    key.clone()
                };
                retrieved_sub_keys_as_string.insert(new_key, value.clone());
            }
        }

        if stores_with_missing_keys.is_empty() {
            Ok(retrieved_sub_keys_as_string)
        } else {
            Err(InStoreTableError::NotFound(MissingValues {
                stores_with_missing_keys,
            }))
        }
    }

    /// Set the value from full key that retrieved from the `sub_key`
    ///
    /// # Errors
    ///
    /// Returns an [`InStoreTableError`] if the store cannot be resolved or the write fails.
    pub async fn set(&self, value: &str, sub_key: &SubKey) -> Result<(), InStoreTableError> {
        let (store, key) = (self.get_store_and_full_key)(self, sub_key)?;
        store.set(&key, value).await?;
        Ok(())
    }

    /// Set the values from full keys that retrieved from the `sub_keys`
    ///
    /// # Errors
    ///
    /// Returns an [`InStoreTableError`] if the write fails.
    pub async fn set_many(
        &self,
        entries: HashMap<SubKey, String>,
    ) -> Result<(), InStoreTableError> {
        let mut store_entries = HashMap::new();

        for (key, value) in entries {
            let full_key = InStoreTable::get_full_key(&self.key, &key.to_string());
            store_entries.insert(full_key, value);
        }

        self.store.set_many(store_entries).await?;

        Ok(())
    }
}
