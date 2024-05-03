use async_trait::async_trait;
use sqlx::Error;
use sqlx::{sqlite::SqliteConnectOptions, Pool, Row, Sqlite, SqlitePool};
use std::collections::HashMap;
use tokio::sync::Mutex;

use crate::store::StoreError;

use super::super::Store;

/// A store that is stored in SQLite
#[derive(Debug)]
pub struct SQLiteStore {
    pub id: Option<String>,
    db: Mutex<Pool<Sqlite>>,
}

impl SQLiteStore {
    pub async fn new(
        path: &str,
        create_file_if_not_exists: Option<bool>,
        id: Option<&str>,
    ) -> Result<Self, Error> {
        let pool = if let Some(create_file_if_not_exists) = create_file_if_not_exists {
            let options = SqliteConnectOptions::new()
                .filename(path)
                .create_if_missing(create_file_if_not_exists);
            SqlitePool::connect_with(options).await?
        } else {
            SqlitePool::connect(path).await?
        };

        let store = SQLiteStore {
            id: id.map(|v| v.to_string()),
            db: Mutex::new(pool),
        };
        store.init().await?;
        Ok(store)
    }

    async fn init(&self) -> Result<(), Error> {
        let pool = self.db.lock().await;
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );"#,
        )
        .execute(&*pool)
        .await?;
        Ok(())
    }
}

#[async_trait]
impl Store for SQLiteStore {
    fn id(&self) -> String {
        self.id.clone().unwrap_or_default()
    }

    async fn get(&self, key: &str) -> Result<Option<String>, StoreError> {
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

    async fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>, StoreError> {
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

    async fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let pool = self.db.lock().await;
        sqlx::query("INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)")
            .bind(key)
            .bind(value)
            .execute(&*pool)
            .await?;

        Ok(())
    }

    async fn set_many(&self, entries: HashMap<String, String>) -> Result<(), StoreError> {
        let pool = self.db.lock().await;
        let mut transaction = pool.begin().await?;

        for (key, value) in entries.iter() {
            sqlx::query("INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)")
                .bind(key)
                .bind(value)
                .execute(&mut *transaction)
                .await?;
        }

        transaction.commit().await?;
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let pool = self.db.lock().await;
        sqlx::query("DELETE FROM store WHERE key = ?")
            .bind(key)
            .execute(&*pool)
            .await?;

        Ok(())
    }

    async fn delete_many(&self, keys: Vec<&str>) -> Result<(), StoreError> {
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
