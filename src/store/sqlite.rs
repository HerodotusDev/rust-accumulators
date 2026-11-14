//! SQLite store backend (native targets).
//!
//! Binary blobs end-to-end: the crate's key layout
//! ([`keys`](crate::store::keys)) is stored verbatim as BLOBs, and values are
//! the wire-format records. Reads are one batched `WHERE key IN (…)` query;
//! writes run inside a transaction — the atomicity the
//! [`AsyncStore`] contract requires.
//!
//! This backend implements [`AsyncStore`] only (sqlx is async-only): pair it
//! with [`AsyncMmr`](crate::mmr::AsyncMmr). It deliberately does **not**
//! implement the sync [`Store`](crate::store::Store) trait — a sync MMR
//! handle over SQLite is unconstructible at compile time.
//!
//! The locator is the database path, so stacks built over SQLite carry
//! re-openable metadata. Re-opening is async (`SqliteStore::open_async`);
//! the sync `open_stacked` flow requires a store with a synchronous
//! `Retrievable` impl (see the `stacked` module). In-memory databases
//! (`:memory:`) get a unique locator per instance — they cannot be
//! re-opened, matching SQLite's semantics.

use crate::store::{AsyncStore, Batch, Op, Storage, StoreLocator};
use alloc::vec::Vec;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions};
use std::path::Path;
use std::sync::Arc;

/// An async SQLite-backed key-value store.
#[derive(Clone)]
pub struct SqliteStore {
    pool: Arc<SqlitePool>,
    locator: StoreLocator,
}

impl core::fmt::Debug for SqliteStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SqliteStore(...)")
    }
}

/// Failures of the SQLite backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SqliteError {
    /// Opening, reading or writing the database failed.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl Storage for SqliteStore {
    type Error = SqliteError;
}

impl SqliteStore {
    /// Opens (or creates) the database at `path` and ensures the schema.
    ///
    /// # Errors
    ///
    /// Connection or schema-creation failures.
    pub async fn connect(path: impl AsRef<Path>) -> Result<Self, SqliteError> {
        let path = path.as_ref();
        let path_text = path.to_string_lossy();
        let in_memory = path_text.is_empty() || path_text.contains(":memory:");
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        // Each pooled `:memory:` connection is a private database — the
        // schema would exist on one connection only. A single connection
        // makes an in-memory store behave like a real database.
        let max_connections = if in_memory { 1 } else { 4 };
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .connect_with(options)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS store (
                key BLOB PRIMARY KEY,
                value BLOB NOT NULL
            )",
        )
        .execute(&pool)
        .await?;

        let pool = Arc::new(pool);

        // In-memory databases cannot be re-opened; their locator is unique
        // per instance so two instances never share an identity.
        let locator = if in_memory {
            StoreLocator::from(alloc::format!(
                "memory:{}:{}",
                Arc::as_ptr(&pool) as usize,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ))
        } else {
            StoreLocator::from(alloc::string::ToString::to_string(&*path_text))
        };

        Ok(Self { pool, locator })
    }

    /// Opens an exclusive in-memory database (session-local).
    ///
    /// # Errors
    ///
    /// Connection or schema-creation failures.
    pub async fn in_memory() -> Result<Self, SqliteError> {
        Self::connect(":memory:").await
    }

    /// Re-opens the database named by `locator` — the async counterpart of
    /// the sync [`crate::store::Retrievable::open`] contract, which this
    /// async-only backend cannot provide.
    ///
    /// # Errors
    ///
    /// Connection or schema-creation failures.
    pub async fn open_async(locator: &StoreLocator) -> Result<Self, SqliteError> {
        let bytes = locator.as_bytes();
        let path = std::str::from_utf8(bytes).map_err(|_| {
            SqliteError::Database(sqlx::Error::Configuration("non-utf8 sqlite locator".into()))
        })?;
        Self::connect(path).await
    }
}

impl AsyncStore for SqliteStore {
    async fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        // One batched query; duplicate keys are deduplicated so positional
        // results stay aligned.
        let mut builder: sqlx::QueryBuilder<sqlx::Sqlite> =
            sqlx::QueryBuilder::new("SELECT key, value FROM store WHERE key IN (");
        let mut separated = builder.separated(", ");
        let mut unique: Vec<&[u8]> = Vec::with_capacity(keys.len());
        for key in keys {
            if !unique.contains(key) {
                unique.push(key);
                separated.push_bind(key);
            }
        }
        builder.push(")");
        let rows: Vec<(Vec<u8>, Vec<u8>)> = builder
            .build_query_as()
            .fetch_all(self.pool.as_ref())
            .await?;

        let map: std::collections::HashMap<&[u8], &[u8]> = rows
            .iter()
            .map(|(key, value)| (key.as_slice(), value.as_slice()))
            .collect();
        Ok(keys
            .iter()
            .map(|key| map.get(*key).map(|value| (*value).to_vec()))
            .collect())
    }

    async fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        if batch.is_empty() {
            return Ok(());
        }

        // The atomicity contract: the whole batch commits or none of it does.
        let mut transaction = self.pool.begin().await?;
        for op in batch.ops {
            match op {
                Op::Put { key, value } => {
                    sqlx::query(
                        "INSERT INTO store (key, value) VALUES (?, ?) \
                         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    )
                    .bind(key.as_ref())
                    .bind(value.as_ref())
                    .execute(transaction.as_mut())
                    .await?;
                }
                Op::Delete { key } => {
                    sqlx::query("DELETE FROM store WHERE key = ?")
                        .bind(key.as_ref())
                        .execute(transaction.as_mut())
                        .await?;
                }
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    fn identity(&self) -> usize {
        Arc::as_ptr(&self.pool) as usize
    }

    fn locator(&self) -> Option<StoreLocator> {
        Some(self.locator.clone())
    }

    fn same_store(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pool, &other.pool) || self.locator == other.locator
    }
}
