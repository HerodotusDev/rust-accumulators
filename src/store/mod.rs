use anyhow::Result;
use std::collections::HashMap;

pub mod counter;
pub mod table;

#[cfg(feature = "sqlite")]
mod stores;
#[cfg(feature = "sqlite")]
pub use self::stores::sqlite;

pub trait Store {
    fn get(&self, key: &str) -> Result<Option<String>>;
    fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>>;
    fn set(&self, key: &str, value: &str) -> Result<()>;
    fn set_many(&self, entries: HashMap<String, String>) -> Result<()>;
    fn delete(&self, key: &str) -> Result<()>;
    fn delete_many(&self, keys: Vec<&str>) -> Result<()>;
}
