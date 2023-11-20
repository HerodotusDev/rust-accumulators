use anyhow::Result;

use async_trait::async_trait;
use sqlx::{Pool, Row, Sqlite, SqlitePool};
use std::collections::HashMap;
use tokio::sync::Mutex;

use super::super::Store;

pub struct SQLiteStore {
    db: Mutex<Pool<Sqlite>>,
}

impl SQLiteStore {
    pub async fn new(path: &str) -> Result<Self> {
        let pool = SqlitePool::connect(path).await?;
        let store = SQLiteStore {
            db: Mutex::new(pool),
        };
        store.init().await?;
        Ok(store)
    }

    async fn init(&self) -> Result<()> {
        let pool = self.db.lock().await;
        sqlx::query!(
            r#"CREATE TABLE IF NOT EXISTS store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );"#
        )
        .execute(&*pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Store for SQLiteStore {
    async fn get(&self, key: &str) -> Result<Option<String>> {
        let pool = self.db.lock().await;

        let row = sqlx::query("SELECT value FROM store WHERE key = ?")
            .bind(key)
            .fetch_optional(&*pool)
            .await?;

        // Extract the value from the row, if it exists
        if let Some(row) = row {
            let value: String = row.try_get("value")?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    async fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>> {
        let pool = self.db.lock().await;
        let placeholders = keys.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
        let query_statement = format!(
            "SELECT key, value FROM store WHERE key IN ({})",
            placeholders
        );
        let mut query = sqlx::query(&query_statement);

        for key in &keys {
            query = query.bind(key);
        }

        let rows = query.fetch_all(&*pool).await?;
        let mut map = HashMap::new();
        for row in rows {
            let key: String = row.get("key");
            let value: String = row.get("value");
            map.insert(key, value);
        }

        Ok(map)
    }

    async fn set(&self, key: &str, value: &str) -> Result<()> {
        let pool = self.db.lock().await;
        sqlx::query("INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(&*pool)
            .await?;

        Ok(())
    }

    async fn set_many(&self, entries: HashMap<String, String>) -> Result<()> {
        let pool = self.db.lock().await;

        for (key, value) in entries.iter() {
            sqlx::query("INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)")
                .bind(key)
                .bind(value)
                .execute(&*pool)
                .await?;
        }

        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let pool = self.db.lock().await;
        sqlx::query("DELETE FROM store WHERE key = ?")
            .bind(key)
            .execute(&*pool)
            .await?;

        Ok(())
    }

    async fn delete_many(&self, keys: Vec<&str>) -> Result<()> {
        let pool = self.db.lock().await;
        let placeholders = keys.iter().map(|_| "?").collect::<Vec<_>>().join(", ");

        let query_statement = format!("DELETE FROM store WHERE key IN ({})", placeholders);
        let mut query = sqlx::query(&query_statement);

        for key in &keys {
            query = query.bind(key);
        }

        query.execute(&*pool).await?;

        Ok(())
    }
}
