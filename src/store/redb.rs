//! Redb store backend (native targets) — an ACID embedded key-value store
//! over copy-on-write B+trees, used here as a single-table byte store.
//!
//! # Atomicity
//!
//! The crate's keys ([`keys`](crate::store::keys)) are stored verbatim in one
//! `(&[u8], &[u8])` table; a [`Batch`] maps 1:1 onto a
//! single redb `WriteTransaction`: every put and delete of the batch lands in
//! that one transaction, and one `commit` makes it atomic. redb transactions
//! are all-or-nothing by construction, so the [`Store::write`] contract (see
//! the [`store`](crate::store) module) is satisfied without extra machinery —
//! a mid-batch failure aborts the transaction and the store is untouched.
//!
//! # Durability posture
//!
//! The default is `Durability::None`: a committed batch is immediately
//! visible to all readers and survives process crashes, but an fsync only
//! lands when a later `Durability::Immediate` commit runs — the same
//! process-crash posture as the other file-backed backends. Accumulator
//! writes are one batch per operation, so `Immediate` costs one fsync per
//! accumulator op; opt into it when batches must survive a power loss, not
//! merely a process crash.
//!
//! # Concurrency
//!
//! redb is MVCC: many readers run concurrently with a single writer, and
//! neither blocks the other. `Database::begin_write` takes `&self` and redb
//! itself serializes writers (a second write transaction blocks until the
//! first commits), so [`RedbStore`] needs no external lock: reads and writes
//! are `&self`, `Clone` shares one `Database` behind an [`Arc`], and cloned
//! handles write concurrently (serialized by redb, invisibly to callers).
//!
//! The locator is the database path (raw OS bytes — non-UTF-8 paths survive
//! the round trip), so stacks built over redb carry re-openable metadata.
//! redb holds an exclusive file lock while a database is open: two live
//! handles cannot name the same file unless they are clones of one handle,
//! which is exactly what [`Store::same_store`] reports (`Arc` identity).
//!
//! # Async surface
//!
//! The engine is synchronous, so the [`AsyncStore`] impl routes every engine
//! call through tokio's blocking pool ([`AsyncStore`] documents the trade) —
//! one open database, two trait views. Re-opening from a locator is
//! offloaded the same way through the [`AsyncRetrievable`] impl.

use crate::store::internal::blocking;
use crate::store::internal::os_path_bytes;
use crate::store::{
    AsyncRetrievable, AsyncStore, Batch, Op, Retrievable, Storage, Store, StoreLocator,
};
use alloc::sync::Arc;
use alloc::vec::Vec;
use redb::{Database, ReadableDatabase, TableDefinition};
use std::path::{Path, PathBuf};

/// The crate's single keyspace: the length-prefixed binary key layout
/// ([`keys`](crate::store::keys)) stored as raw bytes, values are the
/// wire-format records. Length-prefixing makes the layout collision-free, so
/// one table for every accumulator is safe.
const TABLE: TableDefinition<'_, &[u8], &[u8]> = TableDefinition::new("accumulators");

/// Configuration for [`RedbStore`].
///
/// Defaults mirror redb's own sensible defaults; every knob exists to trade
/// something specific — read each setter's docs before overriding.
#[derive(Clone, Debug)]
pub struct RedbConfig {
    /// Database file path. Created when missing or empty, opened when a
    /// valid redb database. This is also the store's locator
    /// ([`Retrievable`]).
    path: PathBuf,
    /// Durability of each committed batch ([`Store::write`]).
    ///
    /// Defaults to `redb::Durability::None`: a committed batch is visible to
    /// all readers and survives process crashes (the OS retains the written
    /// pages), but an fsync only lands when a later `Immediate` commit runs
    /// — the same posture as the other file-backed backends. For power-loss
    /// durability, set `redb::Durability::Immediate` (an fsync per commit —
    /// roughly a thousandfold slowdown for one-batch-per-mutation workloads).
    durability: redb::Durability,
    /// Size (bytes) of redb's in-memory read cache. `None` (the default)
    /// keeps redb's default of 1 GiB — generous for a library; lower it for
    /// memory-constrained processes at the cost of more page reads.
    cache_size: Option<usize>,
    /// Verify the checksum of every page on open, repairing what can be
    /// repaired and reporting corruption as an error instead of trusting a
    /// cleanly-closed file. Costs a full read of the file on every open.
    /// Defaults to `false` (redb still recovers from crashes automatically).
    check_integrity_on_open: bool,
}

impl RedbConfig {
    /// Configuration with redb's defaults for `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            durability: redb::Durability::None,
            cache_size: None,
            check_integrity_on_open: false,
        }
    }

    /// The configured commit durability (see the field docs for the trade).
    #[must_use]
    pub fn durability(&self) -> redb::Durability {
        self.durability
    }

    /// Sets the commit durability (see the field docs for the trade).
    #[must_use]
    pub fn with_durability(mut self, durability: redb::Durability) -> Self {
        self.durability = durability;
        self
    }

    /// Caps redb's in-memory read cache in bytes.
    #[must_use]
    pub fn with_cache_size(mut self, bytes: usize) -> Self {
        self.cache_size = Some(bytes);
        self
    }

    /// Verifies page checksums on every open (see the field docs).
    #[must_use]
    pub fn with_check_integrity_on_open(mut self, enabled: bool) -> Self {
        self.check_integrity_on_open = enabled;
        self
    }
}

/// A redb-backed key-value store.
///
/// Clones share one open database ([`Store::same_store`] is `true` for
/// clones); re-opening from a locator goes through [`Retrievable::open`] or
/// [`RedbStore::open`] and yields an independent handle — which cannot
/// coexist with the original, as redb locks the file while open.
#[derive(Clone)]
pub struct RedbStore {
    db: Arc<Database>,
    config: RedbConfig,
    locator: StoreLocator,
}

impl core::fmt::Debug for RedbStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RedbStore(...)")
    }
}

/// Failures of the redb backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RedbError {
    /// Opening the database file failed (missing, invalid, locked).
    #[error("opening the database failed")]
    Database(#[from] redb::DatabaseError),
    /// Starting a read or write transaction failed.
    #[error("transaction could not be started")]
    Transaction(#[from] redb::TransactionError),
    /// Opening the store's table failed.
    #[error("table access failed")]
    Table(#[from] redb::TableError),
    /// Reading from or writing to a table failed.
    #[error(transparent)]
    Storage(#[from] redb::StorageError),
    /// Committing the write transaction failed.
    #[error("commit failed")]
    Commit(#[from] redb::CommitError),
    /// The configured durability level was rejected by redb.
    #[error("durability could not be applied")]
    Durability(#[from] redb::SetDurabilityError),
    /// Spawning the blocking task failed — the async runtime is shutting
    /// down. The sync [`Store`] surface never produces this.
    #[error("the async runtime rejected the blocking task")]
    Runtime(#[from] tokio::task::JoinError),
}

impl Storage for RedbStore {
    type Error = RedbError;
}

impl RedbStore {
    /// Opens (or creates) the database described by `config`.
    ///
    /// # Errors
    ///
    /// Opening or integrity-check failures (missing file for an invalid
    /// path, corruption, another process holding the file lock).
    pub fn open(config: RedbConfig) -> Result<Self, RedbError> {
        let mut builder = Database::builder();
        if let Some(cache_size) = config.cache_size {
            builder.set_cache_size(cache_size);
        }
        if config.check_integrity_on_open {
            builder.set_check_integrity_on_open(true);
        }
        let db = Arc::new(builder.create(&config.path)?);
        let locator = StoreLocator::from_bytes(config.path.as_os_str().as_encoded_bytes().to_vec());
        Ok(Self {
            db,
            config,
            locator,
        })
    }

    /// Opens (or creates) the database at `path` with default configuration.
    ///
    /// # Errors
    ///
    /// See [`RedbStore::open`].
    pub fn open_path(path: impl AsRef<Path>) -> Result<Self, RedbError> {
        Self::open(RedbConfig::new(path.as_ref().to_path_buf()))
    }
}

impl Store for RedbStore {
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        // One read transaction for the whole batch: MVCC readers never block
        // the writer, and redb's zero-copy guards are materialized into
        // owned values here, before the transaction drops.
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TABLE)?;
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            let guard = table.get(key)?;
            results.push(guard.map(|guard| guard.value().to_vec()));
        }
        Ok(results)
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        if batch.is_empty() {
            return Ok(());
        }

        // The atomicity contract: the whole batch is one write transaction.
        // redb serializes writers itself — begin_write blocks until any
        // other write transaction commits — so no external lock is needed.
        let mut txn = self.db.begin_write()?;
        txn.set_durability(self.config.durability)?;
        {
            let mut table = txn.open_table(TABLE)?;
            // Ops apply in order, so a later delete (or put) over an
            // earlier put in the same batch lands as the final state.
            for op in &batch.ops {
                match op {
                    Op::Put { key, value } => {
                        drop(table.insert(key.as_ref(), value.as_ref())?);
                    }
                    Op::Delete { key } => {
                        drop(table.remove(key.as_ref())?);
                    }
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// The open database handle — clones share it, independent opens cannot
    /// coexist (redb locks the file), so handle identity is store identity.
    fn identity(&self) -> usize {
        Arc::as_ptr(&self.db) as usize
    }

    fn same_store(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.db, &other.db)
    }

    fn locator(&self) -> Option<StoreLocator> {
        Some(self.locator.clone())
    }
}

impl Retrievable for RedbStore {
    /// The database path, as raw OS bytes.
    fn canonical_locator(&self) -> StoreLocator {
        self.locator.clone()
    }

    /// Re-opens the database named by `locator`.
    ///
    /// # Errors
    ///
    /// See [`RedbStore::open`].
    fn open(locator: &StoreLocator) -> Result<Self, Self::Error> {
        // The locator is the raw OS path (possibly non-UTF-8) — rebuild it
        // byte-for-byte via the shared store helper.
        Self::open_path(os_path_bytes(locator.as_bytes()))
    }
}

impl AsyncStore for RedbStore {
    async fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        blocking::offload_read(self.clone(), keys).await
    }

    async fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        blocking::offload_write(self.clone(), batch).await
    }

    fn identity(&self) -> usize {
        Store::identity(self)
    }

    fn same_store(&self, other: &Self) -> bool {
        Store::same_store(self, other)
    }

    fn locator(&self) -> Option<StoreLocator> {
        Store::locator(self)
    }
}

impl AsyncRetrievable for RedbStore {
    fn canonical_locator(&self) -> StoreLocator {
        Retrievable::canonical_locator(self)
    }

    async fn open(locator: &StoreLocator) -> Result<Self, Self::Error> {
        let path = os_path_bytes(locator.as_bytes());
        blocking::offload_result(move || Self::open_path(path)).await
    }
}
