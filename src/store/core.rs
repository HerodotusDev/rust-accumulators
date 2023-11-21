use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;

#[async_trait]
pub trait Store {
    async fn get(&self, key: &str) -> Result<Option<String>>;
    async fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>>;
    async fn set(&self, key: &str, value: &str) -> Result<()>;
    async fn set_many(&self, entries: HashMap<String, String>) -> Result<()>;
    async fn delete(&self, key: &str) -> Result<()>;
    async fn delete_many(&self, keys: Vec<&str>) -> Result<()>;
}
