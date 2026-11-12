use async_trait::async_trait;
use sqlx::SqliteConnection;
use sqlx::pool::PoolConnection;
use sqlx::{Acquire, Error};
use sqlx::{Pool, Sqlite, SqlitePool, sqlite::SqliteConnectOptions};
use std::collections::HashMap;

use crate::store::StoreError;

use super::super::Store;

/// A store that is stored in SQLite
#[derive(Debug)]
pub struct SQLiteStore {
    /// An optional identifier for the store, useful for debugging
    pub id: Option<String>,
    pool: Pool<Sqlite>,
    atomic_set_many: bool,
}

//? There is no SQLite variable limit to worry about anymore (single json_each bind),
//? but we still chunk to bound statement size and memory usage.
const MAX_BATCH_SIZE: usize = 900;

impl SQLiteStore {
    /// Create a new SQLite store with externally created pool.
    #[must_use]
    pub fn with_pool(pool: Pool<Sqlite>, id: Option<String>) -> Self {
        SQLiteStore {
            id,
            pool,
            atomic_set_many: false,
        }
    }

    /// Create a new SQLite store backed by the database at `path`.
    ///
    /// The store is initialized (the `store` table is created) before being returned.
    ///
    /// # Errors
    ///
    /// Returns a `sqlx::Error` if connecting to the database or initializing
    /// the store fails.
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
            id: id.map(str::to_string),
            pool,
            atomic_set_many: true,
        };
        store.init().await?;
        Ok(store)
    }

    /// Acquire a connection from the pool.
    /// NOTE: if there's no available connection this function will fail after acquire timeout.
    /// Configure it via sqlite options.
    ///
    /// # Errors
    ///
    /// Returns a `sqlx::Error` if no connection could be acquired before the
    /// acquire timeout.
    pub async fn acquire_connection(&self) -> Result<PoolConnection<Sqlite>, Error> {
        self.pool.acquire().await
    }

    /// Initialize the store
    ///
    /// # Errors
    ///
    /// Returns a `sqlx::Error` if the `store` table cannot be created.
    pub async fn init(&self) -> Result<(), Error> {
        let mut conn = self.acquire_connection().await?;
        sqlx::query!(
            r#"CREATE TABLE IF NOT EXISTS store (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );"#
        )
        .execute(&mut *conn)
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
        let mut conn = self.acquire_connection().await?;

        let row = sqlx::query!("SELECT value FROM store WHERE key = ?", key)
            .fetch_optional(&mut *conn)
            .await?;

        Ok(row.map(|row| row.value))
    }

    async fn get_many(&self, keys: Vec<&str>) -> Result<HashMap<String, String>, StoreError> {
        let mut conn = self.acquire_connection().await?;
        let mut map = HashMap::new();

        for key_chunk in keys.chunks(MAX_BATCH_SIZE) {
            let keys_json =
                serde_json::to_string(&key_chunk).map_err(|e| StoreError::Custom(Box::new(e)))?;

            let rows = sqlx::query_as!(
                KvRow,
                r#"SELECT key AS "key!: String", value AS "value!: String" FROM store WHERE key IN (SELECT value FROM json_each(?1))"#,
                keys_json
            )
            .fetch_all(&mut *conn)
            .await?;

            for row in rows {
                map.insert(row.key, row.value);
            }
        }

        Ok(map)
    }

    async fn set(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let mut conn = self.acquire_connection().await?;
        sqlx::query!(
            "INSERT OR REPLACE INTO store (key, value) VALUES (?, ?)",
            key,
            value
        )
        .execute(&mut *conn)
        .await?;

        Ok(())
    }

    async fn set_many(&self, entries: HashMap<String, String>) -> Result<(), StoreError> {
        let mut conn = self.acquire_connection().await?;
        if self.atomic_set_many {
            let mut tx = conn.begin().await?;
            set_many(&mut tx, entries).await?;
            tx.commit().await.map_err(StoreError::SQLite)
        } else {
            set_many(&mut conn, entries).await
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StoreError> {
        let mut conn = self.acquire_connection().await?;
        sqlx::query!("DELETE FROM store WHERE key = ?", key)
            .execute(&mut *conn)
            .await?;

        Ok(())
    }

    async fn delete_many(&self, keys: Vec<&str>) -> Result<(), StoreError> {
        let mut conn = self.acquire_connection().await?;

        for key_chunk in keys.chunks(MAX_BATCH_SIZE) {
            let keys_json =
                serde_json::to_string(&key_chunk).map_err(|e| StoreError::Custom(Box::new(e)))?;

            sqlx::query!(
                r#"DELETE FROM store WHERE key IN (SELECT value FROM json_each(?1))"#,
                keys_json
            )
            .execute(&mut *conn)
            .await?;
        }

        Ok(())
    }
}

struct KvRow {
    key: String,
    value: String,
}

async fn set_many(
    executor: &mut SqliteConnection,
    entries: HashMap<String, String>,
) -> Result<(), StoreError> {
    for entry_chunk in entries.iter().collect::<Vec<_>>().chunks(MAX_BATCH_SIZE) {
        let entries_json = serde_json::to_string(
            &entry_chunk
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect::<HashMap<_, _>>(),
        )
        .map_err(|e| StoreError::Custom(Box::new(e)))?;

        // json_each over a JSON object yields (key, value) rows
        sqlx::query!(
            r#"INSERT OR REPLACE INTO store (key, value) SELECT je.key, je.value FROM json_each(?1) AS je"#,
            entries_json
        )
        .execute(&mut *executor)
        .await?;
    }
    Ok(())
}
