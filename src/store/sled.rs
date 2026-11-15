//! Sled store backend (native targets) — a durable, single-file-directory
//! embedded key-value store over [`sled`](https://docs.rs/sled).
//!
//! # Atomicity
//!
//! [`Store::write`] maps onto
//! [`sled::Tree::apply_batch`], the backend's atomic batch primitive: readers
//! see all updates at one atomic instant, and crash recovery yields either
//! 0% or 100% of the batch. There is no fault-injection seam here because the
//! primitive is atomic by construction — a batch is applied under 2PL over
//! the touched leaves, so a failed `apply_batch` cannot leave a partial
//! state. `sled::Batch` coalesces writes into a map keyed by byte key, so a
//! batch with several operations on one key applies the **last** one —
//! exactly the `Batch` contract's "ordered ops, last wins" semantics.
//!
//! # Durability posture
//!
//! Writes are atomic in memory immediately; flushing to disk follows sled's
//! configured schedule ([`SledConfig::with_flush_every_ms`], default every
//! 200 ms via a background flusher thread). Dropping the last handle to a
//! database
//! flushes before the process detaches, and [`SledStore::flush`] forces a
//! synchronous flush + fsync for callers that need durability *now* (e.g.
//! before reporting a commit as durable). Like every store in this crate, the
//! contract is atomicity — fsync durability per write is opt-in through
//! explicit flushes.
//!
//! # Threading
//!
//! sled 1.0-alpha types are `Send` but currently `!Sync` (epoch-based
//! reclamation internals), so [`SledStore`] serializes access through a
//! `std::sync::Mutex` around the database handle. This keeps the store handle
//! `Send + Sync` (usable from multiple threads, `ErasedStore`, …) at the cost
//! of a mutex acquisition per batched call — noise next to I/O.
//!
//! # Handle and locator semantics
//!
//! sled takes an exclusive directory lock: exactly one live [`SledStore`]
//! exists per database path. Opening the same path while a handle is alive
//! fails with [`SledError::Io`] (`ErrorKind::WouldBlock`); [`Clone`] shares
//! the existing handle (all clones are one database, recognized by
//! [`Store::same_store`] through `Arc` pointer
//! equality). The canonical locator is the raw OS path of the database
//! directory, so [`Retrievable::open`] re-opens a persisted stack's layers —
//! non-UTF-8 paths survive the round trip through the platform's byte
//! encoding, never a lossy string.
//!
//! # Keys
//!
//! The crate's binary keys (see [`keys`](crate::store::keys)) are used
//! verbatim as sled keys — no extra prefix layer. They are already
//! length-prefixed and collision-free, and sled orders keys bytewise
//! (`Ord` of byte slices); the layout's big-endian subkeys make that ordering
//! numerically meaningful should a backend ever need range scans.

use crate::store::internal::os_path_bytes;
use crate::store::{Batch, Op, Retrievable, Storage, Store, StoreLocator};
use alloc::format;
use alloc::vec::Vec;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

/// Failures of the sled backend.
///
/// sled 1.0-alpha reports every failure — open, read, write, flush, lock —
/// as a [`std::io::Error`], so this type has a single wrapping variant.
/// Typical cases: the database directory cannot be created or locked (a
/// second live handle on the same path surfaces as
/// `ErrorKind::WouldBlock`), and I/O errors during reads or batch writes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SledError {
    /// The backend reported an I/O error; the sled cause is the `source`.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// A durable sled-backed key-value store.
///
/// Clones share one database (and one lock) exactly like an `Arc`; see the
/// [module docs](self) for atomicity, durability and locator semantics.
#[derive(Clone)]
pub struct SledStore {
    db: Arc<Mutex<sled::Db>>,
    path: PathBuf,
}

impl core::fmt::Debug for SledStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SledStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl SledStore {
    /// Opens (or creates) the database described by `config`.
    ///
    /// # Errors
    ///
    /// Directory creation or locking failures — including opening a path
    /// that already has a live handle (`ErrorKind::WouldBlock`).
    pub fn open(config: SledConfig) -> Result<Self, SledError> {
        let db: sled::Db = sled::Config::new()
            .path(&config.path)
            .cache_capacity_bytes(config.cache_capacity_bytes)
            .flush_every_ms(
                // `u64` is the crate-facing type; it always fits `usize` on
                // the targets sled runs on, and an absurd interval degrades
                // to "flush as rarely as representable" rather than erroring.
                config
                    .flush_every_ms
                    .map(|ms| usize::try_from(ms).unwrap_or(usize::MAX)),
            )
            .zstd_compression_level(config.zstd_compression_level)
            .open()?;
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            path: config.path,
        })
    }

    /// Opens (or creates) the database directory at `path` with default
    /// configuration.
    ///
    /// # Errors
    ///
    /// Directory creation or locking failures — including opening a path
    /// that already has a live handle (`ErrorKind::WouldBlock`).
    pub fn open_path(path: impl AsRef<Path>) -> Result<Self, SledError> {
        Self::open(SledConfig::new(path))
    }

    /// Flushes all dirty buffers and fsyncs.
    ///
    /// After this returns, every previously applied batch is durable and will
    /// be recovered after a crash. Also called automatically when the last
    /// handle to the database drops.
    ///
    /// # Errors
    ///
    /// I/O failures during the flush.
    pub fn flush(&self) -> Result<(), SledError> {
        self.lock_db().flush()?;
        Ok(())
    }

    /// Locks the database handle, transparently recovering from poisoning.
    ///
    /// No code path holds this lock across a panic point (every sled failure
    /// surfaces as `Err`), so a poisoned lock can only reflect an aborting
    /// panic elsewhere (e.g. allocation failure); the database value itself
    /// remains consistent and usable.
    fn lock_db(&self) -> MutexGuard<'_, sled::Db> {
        self.db.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Configuration for a [`SledStore`].
///
/// Builder-style: chain the setters, then call [`SledStore::open`]. Every
/// knob has sled's own default except the path, which is required.
#[derive(Clone, Debug)]
pub struct SledConfig {
    /// Database directory. Created on open if missing.
    path: PathBuf,
    /// Page cache in bytes. Default: 512 MiB.
    cache_capacity_bytes: usize,
    /// Background flush interval. Default: every 200 ms.
    flush_every_ms: Option<u64>,
    /// zstd compression level for on-disk pages. Default: 3.
    zstd_compression_level: i32,
}

impl SledConfig {
    /// Configuration for the database directory at `path`.
    ///
    /// The directory is created by [`SledStore::open`] if missing.
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            cache_capacity_bytes: 512 * 1024 * 1024,
            flush_every_ms: Some(200),
            zstd_compression_level: 3,
        }
    }

    /// Configuration under a fresh unique directory in the system temp dir.
    ///
    /// A convenience for tests and throwaway stores: the directory is created
    /// by [`SledStore::open`] and **not** removed automatically — wrap the
    /// path in a drop guard that removes it.
    #[must_use]
    pub fn in_temp(label: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self::new(std::env::temp_dir().join(format!(
            "accumulators-sled-{label}-{nanos}-{}-{id}",
            std::process::id()
        )))
    }

    /// Page cache size in bytes.
    ///
    /// Larger caches keep more pages resident for working sets bigger than
    /// the cache (fewer page-ins, more resident memory); the default is
    /// sled's 512 MiB, generous for embedded accumulators.
    #[must_use]
    pub fn with_cache_capacity_bytes(mut self, bytes: usize) -> Self {
        self.cache_capacity_bytes = bytes;
        self
    }

    /// Interval between background flushes, or `None` to disable the
    /// flusher thread entirely (durability then happens only on explicit
    /// [`SledStore::flush`] calls and on drop of the last handle).
    ///
    /// Shorter intervals narrow the crash-durability window at the cost of
    /// write amplification; the default (200 ms) is sled's.
    #[must_use]
    pub fn with_flush_every_ms(mut self, ms: Option<u64>) -> Self {
        self.flush_every_ms = ms;
        self
    }

    /// zstd compression level for pages written to disk (1 = fastest,
    /// higher = smaller files at proportionally slower writes).
    ///
    /// sled 1.0-alpha always compresses with zstd; the level is the only
    /// compression knob. The default (3) is sled's.
    #[must_use]
    pub fn with_zstd_compression_level(mut self, level: i32) -> Self {
        self.zstd_compression_level = level;
        self
    }
}

impl Storage for SledStore {
    type Error = SledError;
}

impl Store for SledStore {
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        let db = self.lock_db();
        keys.iter()
            .map(|&key| Ok(db.get(key)?.map(|value| value.to_vec())))
            .collect()
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        if batch.is_empty() {
            return Ok(());
        }
        // `sled::Batch` is a map keyed by byte key, so later operations on a
        // key overwrite earlier ones — the `Batch` contract's last-wins
        // semantics, preserved verbatim.
        let mut writes = sled::Batch::default();
        for op in batch.ops {
            match op {
                Op::Put { key, value } => writes.insert(key.into_owned(), value.into_owned()),
                Op::Delete { key } => writes.remove(key.into_owned()),
            }
        }
        // Atomic all-or-nothing application; see the module docs.
        self.lock_db().apply_batch(writes)?;
        Ok(())
    }

    fn identity(&self) -> usize {
        // Clones share the `Arc`, so the pointer address is a stable identity
        // of the underlying database (two opens of one path cannot coexist —
        // sled holds an exclusive directory lock — so clones are the only way
        // two handles ever name the same database).
        Arc::as_ptr(&self.db).addr()
    }

    fn same_store(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.db, &other.db)
    }

    fn locator(&self) -> Option<StoreLocator> {
        Some(StoreLocator::from_bytes(
            self.path.as_os_str().as_encoded_bytes().to_vec(),
        ))
    }
}

impl Retrievable for SledStore {
    fn canonical_locator(&self) -> StoreLocator {
        // The locator is the raw OS path of the database directory — never
        // rebuilt through a lossy string, which would name a different file
        // and break re-opening.
        StoreLocator::from_bytes(self.path.as_os_str().as_encoded_bytes().to_vec())
    }

    fn open(locator: &StoreLocator) -> Result<Self, Self::Error> {
        Self::open_path(os_path_bytes(locator.as_bytes()))
    }
}
