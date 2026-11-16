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
//! The locator is the database path (raw OS bytes — non-UTF-8 paths survive
//! the round trip), so stacks built over SQLite carry re-openable metadata.
//! Re-opening is async: the store implements
//! [`AsyncRetrievable`](crate::store::AsyncRetrievable) (`open_async` is its
//! inherent spelling), which the async `open_stacked` flow consumes; the
//! sync `open_stacked` requires a synchronous `Retrievable` impl, which this
//! backend deliberately does not provide. In-memory databases (`:memory:`,
//! exact match only) get a unique synthetic `memory:` locator per instance —
//! they cannot be re-opened (and `open_async` rejects `memory:` locators
//! outright), matching SQLite's semantics.

use crate::store::internal::os_path_bytes;
use crate::store::{AsyncStore, Batch, Op, Storage, StoreLocator};
use alloc::vec::Vec;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions, SqliteSynchronous,
};
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

/// Keys per batched `IN (...)` query: two-blob binds stay well under
/// SQLite's per-statement variable limit (`SQLITE_MAX_VARIABLE_NUMBER`).
const MAX_KEYS_PER_QUERY: usize = 900;

/// Rows per multi-row upsert statement (see [`MAX_KEYS_PER_QUERY`]).
const MAX_ROWS_PER_STATEMENT: usize = 450;

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
        // Locator bytes are the raw OS path — non-UTF-8 paths must not be
        // fabricated through a lossy string (the lossy locator would not
        // re-open the real file). `:memory:` detection is an **exact** match
        // (SQLite's own convention): a file literally named
        // `data:memory:copy.db` is a real file, not a database alias.
        let in_memory = path.as_os_str().is_empty() || path.as_os_str() == ":memory:";
        let options = SqliteConnectOptions::new()
            .filename(path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            // WAL + `synchronous = NORMAL`: commits skip the per-commit fsync
            // (only checkpoints sync). Transactions stay atomic and crash-safe
            // — a power loss may roll back the last commits, never corrupt —
            // which matches the store contract (atomicity, not fsync
            // durability).
            .synchronous(SqliteSynchronous::Normal)
            // Writes serialize on SQLite's write lock; pooled connections
            // queue on it instead of failing with `SQLITE_BUSY`. Explicit
            // (sqlx's default is also 5 s) so the behavior survives a sqlx
            // default change.
            .busy_timeout(std::time::Duration::from_secs(5))
            // One blob table, no foreign keys: skip the per-connection FK
            // bookkeeping entirely.
            .foreign_keys(false);
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
        // per instance (a `memory:`-prefixed synthetic id, never a path) so
        // two instances never share an identity. File databases store the
        // raw OS path bytes.
        let locator = if in_memory {
            StoreLocator::from(alloc::format!(
                "memory:{}:{}",
                Arc::as_ptr(&pool) as usize,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_nanos())
            ))
        } else {
            StoreLocator::from_bytes(path.as_os_str().as_encoded_bytes().to_vec())
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
    /// async-only backend cannot provide. Exposed through the
    /// [`AsyncRetrievable`](crate::store::AsyncRetrievable) impl, which is
    /// what the async `open_stacked` flow consumes.
    ///
    /// Locators produced by [`SqliteStore::in_memory`] / `connect(":memory:")`
    /// are synthetic `memory:` ids, not paths — they are rejected here rather
    /// than silently fabricating a *file* named `memory:…` (an in-memory
    /// database cannot be re-opened, matching SQLite's semantics).
    ///
    /// # Errors
    ///
    /// Connection or schema-creation failures; a `memory:`-prefixed locator.
    pub async fn open_async(locator: &StoreLocator) -> Result<Self, SqliteError> {
        let bytes = locator.as_bytes();
        if bytes.starts_with(b"memory:") {
            return Err(SqliteError::Database(sqlx::Error::Configuration(
                "memory: locators are synthetic in-memory ids and cannot be re-opened".into(),
            )));
        }
        // The locator is the raw OS path (possibly non-UTF-8) — rebuild it
        // byte-for-byte instead of going through a string.
        Self::connect(os_path_bytes(bytes)).await
    }
}

impl AsyncStore for SqliteStore {
    async fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        // Chunked batched queries: results are built positionally from the
        // original keys (duplicates fan back from the same row), so the
        // per-chunk dedup below only trims bind counts.
        let mut results: Vec<Option<Vec<u8>>> = Vec::with_capacity(keys.len());
        for chunk in keys.chunks(MAX_KEYS_PER_QUERY) {
            // First-occurrence dedup within the chunk (binds the same key
            // once even when several positions request it).
            let mut unique: Vec<&[u8]> = Vec::with_capacity(chunk.len());
            let mut seen: std::collections::HashSet<&[u8]> = std::collections::HashSet::new();
            for key in chunk {
                if seen.insert(key) {
                    unique.push(key);
                }
            }

            let mut builder: sqlx::QueryBuilder<sqlx::Sqlite> =
                sqlx::QueryBuilder::new("SELECT key, value FROM store WHERE key IN (");
            let mut separated = builder.separated(", ");
            for key in &unique {
                separated.push_bind(key);
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
            results.extend(chunk.iter().map(|key| map.get(*key).map(|v| v.to_vec())));
        }
        Ok(results)
    }

    async fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        if batch.is_empty() {
            return Ok(());
        }

        // The atomicity contract: the whole batch commits or none of it does.
        let mut transaction = self.pool.begin().await?;
        // Consecutive puts coalesce into multi-row upserts and consecutive
        // deletes into multi-row `DELETE … IN` statements (chunked against
        // the bind limit); runs flush before an op of the other kind lands,
        // so op order is preserved — a later delete still lands after the
        // puts it follows.
        let mut put_run: Vec<(&[u8], &[u8])> = Vec::new();
        let mut delete_run: Vec<&[u8]> = Vec::new();
        macro_rules! flush {
            ($transaction:expr, $put_run:expr, $delete_run:expr) => {{
                for chunk in $put_run.chunks(MAX_ROWS_PER_STATEMENT) {
                    let mut builder = sqlx::QueryBuilder::new("INSERT INTO store (key, value) ");
                    builder.push_values(chunk.iter(), |mut b, (key, value)| {
                        b.push_bind(key).push_bind(value);
                    });
                    builder.push(" ON CONFLICT(key) DO UPDATE SET value = excluded.value");
                    builder.build().execute($transaction.as_mut()).await?;
                }
                $put_run.clear();
                for chunk in $delete_run.chunks(MAX_KEYS_PER_QUERY) {
                    let mut builder = sqlx::QueryBuilder::new("DELETE FROM store WHERE key IN (");
                    let mut separated = builder.separated(", ");
                    for key in chunk {
                        separated.push_bind(key);
                    }
                    builder.push(")");
                    builder.build().execute($transaction.as_mut()).await?;
                }
                $delete_run.clear();
            }};
        }
        for op in &batch.ops {
            match op {
                Op::Put { key, value } => {
                    if !delete_run.is_empty() {
                        flush!(transaction, put_run, delete_run);
                    }
                    put_run.push((key.as_ref(), value.as_ref()));
                }
                Op::Delete { key } => {
                    if !put_run.is_empty() {
                        flush!(transaction, put_run, delete_run);
                    }
                    delete_run.push(key.as_ref());
                }
            }
        }
        flush!(transaction, put_run, delete_run);
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

impl crate::store::AsyncRetrievable for SqliteStore {
    fn canonical_locator(&self) -> StoreLocator {
        self.locator.clone()
    }

    async fn open(locator: &StoreLocator) -> Result<Self, Self::Error> {
        Self::open_async(locator).await
    }
}
