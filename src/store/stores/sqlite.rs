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

//? SQLite's default maximum number of variables per statement is 999.
//? We use a smaller number to be safe.
const MAX_VARIABLE_NUMBER: usize = 900;

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

        if let Some(row) = row {
            let value: String = row.try_get("value")?;
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    async fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>, StoreError> {
        let pool = self.db.lock().await;
        let mut map = HashMap::new();

        for key_chunk in keys.chunks(MAX_VARIABLE_NUMBER) {
            let placeholders = key_chunk.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let query_statement = format!(
                "SELECT key, value FROM store WHERE key IN ({})",
                placeholders
            );

            let mut query = sqlx::query(&query_statement);

            for key in key_chunk {
                query = query.bind(*key);
            }

            let rows = query.fetch_all(&*pool).await?;
            for row in rows {
                let key: String = row.get("key");
                let value: String = row.get("value");
                map.insert(key, value);
            }
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

        for entry_chunk in entries
            .iter()
            .collect::<Vec<_>>()
            .chunks(MAX_VARIABLE_NUMBER)
        {
            let mut query = String::from("INSERT OR REPLACE INTO store (key, value) VALUES ");
            let placeholders = entry_chunk
                .iter()
                .map(|_| "(?, ?)")
                .collect::<Vec<_>>()
                .join(", ");
            query.push_str(&placeholders);

            let mut sqlx_query = sqlx::query(&query);
            for (key, value) in entry_chunk {
                sqlx_query = sqlx_query.bind(key).bind(value);
            }

            sqlx_query.execute(&mut *transaction).await?;
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

        for key_chunk in keys.chunks(MAX_VARIABLE_NUMBER) {
            let placeholders = key_chunk.iter().map(|_| "?").collect::<Vec<_>>().join(", ");
            let query_statement = format!("DELETE FROM store WHERE key IN ({})", placeholders);

            let mut query = sqlx::query(&query_statement);

            for key in key_chunk {
                query = query.bind(*key);
            }

            query.execute(&*pool).await?;
        }

        Ok(())
    }
}
