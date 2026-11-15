//! `RocksDB`-backed [`Store`] — an embeddable LSM engine for persistent
//! accumulators.
//!
//! # Atomicity
//!
//! Every [`write`](Store::write) builds one `RocksDB` [`WriteBatch`] and
//! commits it with a single write call. `RocksDB` applies a write batch
//! all-or-nothing (observers see the whole batch or none of it, even across
//! a crash recovery), which satisfies the store contract's hard atomicity
//! requirement by construction. Operations apply in batch order, so the
//! crate's last-write-wins semantics within one batch are preserved.
//!
//! # Durability posture
//!
//! By default each batch goes to the write-ahead log with `sync` off —
//! `RocksDB`'s own defaults. The batch is durable against a **process
//! crash** (the WAL is recovered on reopen, and recovery is per-batch, so
//! a torn batch is never partially replayed) but not against an **OS
//! crash or power loss**, where the last WAL frames the OS had not
//! fsynced may be lost — whole batches at a time, never partial ones.
//! The knobs, in increasing durability cost:
//!
//! - [`RocksdbConfig::with_disable_wal`] — skip the WAL entirely: highest
//!   throughput, but a crash can lose recent batches outright. Batch
//!   atomicity within a live session is unaffected.
//! - default — WAL without fsync (durable against process crash).
//! - [`RocksdbConfig::with_sync_writes`] — fsync every batch before the write
//!   returns: durable against power loss, at one disk sync per batch.
//!
//! # Concurrency
//!
//! The handle is `Send + Sync` and `RocksDB` is a multi-threaded engine:
//! concurrent readers never block each other, and concurrent writers are
//! serialized by `RocksDB`'s write group. No external lock is needed —
//! clones of one [`RocksdbStore`] front the same engine concurrently.
//!
//! # Keyspace and column families
//!
//! All data lives in the default column family. The crate's key layout
//! (see [`keys`](crate::store::keys)) is already length-prefixed and
//! collision-free across accumulators and tables, so column families
//! would add per-CF memtable and handle overhead without buying any
//! isolation. Keys and values are opaque bytes; they round-trip
//! verbatim.
//!
//! # Identity and re-opening
//!
//! [`Clone`] shares one database handle (the same-store hint is `Arc`
//! equality), and the locator is the raw database **path** —
//! [`Retrievable::open`] re-opens it, so `RocksDB` stores can back
//! persistent stacked-MMR layers.
//!
//! # Building
//!
//! `librocksdb-sys` runs bindgen at build time, which needs a `libclang`
//! (CI installs `libclang-dev` on ubuntu). On macOS with Apple clang,
//! bindgen may need an explicit target:
//! `BINDGEN_EXTRA_CLANG_ARGS="-target arm64-apple-macos"`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rocksdb::{WriteBatch, WriteOptions};
use thiserror::Error;

use crate::store::internal::os_path_bytes;
use crate::store::{Batch, Op, Retrievable, Storage, Store, StoreLocator};

use alloc::vec::Vec;

/// Configuration for opening a [`RocksdbStore`].
///
/// Every knob trades something concrete; the defaults are chosen for the
/// accumulator workload (small fixed-size hash values, one batch per
/// mutation) rather than `RocksDB`'s generic-purpose defaults.
///
/// [`RocksdbConfig::with_base_options`] is the escape hatch for anything this
/// surface does not expose: when set, tuning starts from a clone of it and
/// the documented knobs are applied **on top**, so they always win.
#[derive(Clone)]
pub struct RocksdbConfig {
    /// Filesystem directory holding the database. Created on open when
    /// [`RocksdbConfig::with_create_if_missing`] is set.
    path: PathBuf,
    /// Create the database directory when missing. `false` makes open fail
    /// on a nonexistent path — the safe posture for re-opening a locator.
    create_if_missing: bool,
    /// Block compression for SST files. Defaults to [`None`](rocksdb::DBCompressionType::None):
    /// accumulator values are fixed-size hashes, which do not compress —
    /// compression only adds CPU. Enable one when storing larger payloads.
    compression: rocksdb::DBCompressionType,
    /// Memtable size before a flush to SST files. Larger values batch more
    /// writes per flush (better write throughput, more memory).
    write_buffer_size: usize,
    /// Cap on open file handles (`-1` = unlimited). `-1` avoids per-read
    /// file-open costs at the cost of file descriptors; lower it in
    /// descriptor-starved processes.
    max_open_files: i32,
    /// fsync every batch before the write returns (see the module-level
    /// durability table). Off by default: the WAL alone already survives
    /// process crashes, and one fsync per batch is expensive.
    sync_writes: bool,
    /// Skip the write-ahead log entirely (see the module-level durability
    /// table). Off by default.
    disable_wal: bool,
    /// Base [`rocksdb::Options`] to tune from before the documented knobs
    /// are applied. `None` starts from `Options::default()`.
    base_options: Option<rocksdb::Options>,
}

impl core::fmt::Debug for RocksdbConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // `rocksdb::Options` is not `Debug`; print its presence, not its guts.
        f.debug_struct("RocksdbConfig")
            .field("path", &self.path)
            .field("create_if_missing", &self.create_if_missing)
            .field("compression", &self.compression)
            .field("write_buffer_size", &self.write_buffer_size)
            .field("max_open_files", &self.max_open_files)
            .field("sync_writes", &self.sync_writes)
            .field("disable_wal", &self.disable_wal)
            .field(
                "base_options",
                &self.base_options.as_ref().map(|_| "<custom>"),
            )
            .finish()
    }
}

impl RocksdbConfig {
    /// Configuration for the database at `path`, with every knob at its
    /// documented default.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            create_if_missing: true,
            compression: rocksdb::DBCompressionType::None,
            write_buffer_size: 64 * 1024 * 1024,
            max_open_files: -1,
            sync_writes: false,
            disable_wal: false,
            base_options: None,
        }
    }

    /// Sets whether a missing database directory is created on open
    /// (default: `true`).
    #[must_use]
    pub fn with_create_if_missing(mut self, create_if_missing: bool) -> Self {
        self.create_if_missing = create_if_missing;
        self
    }

    /// Sets the SST block compression (default: none — hash values are
    /// incompressible).
    #[must_use]
    pub fn with_compression(mut self, compression: rocksdb::DBCompressionType) -> Self {
        self.compression = compression;
        self
    }

    /// Sets the memtable size in bytes before a flush (default: 64 MiB).
    #[must_use]
    pub fn with_write_buffer_size(mut self, write_buffer_size: usize) -> Self {
        self.write_buffer_size = write_buffer_size;
        self
    }

    /// Sets the open-file cap; `-1` keeps every file open (default).
    #[must_use]
    pub fn with_max_open_files(mut self, max_open_files: i32) -> Self {
        self.max_open_files = max_open_files;
        self
    }

    /// Sets whether each batch is fsynced before the write returns
    /// (default: `false` — see the module-level durability table).
    #[must_use]
    pub fn with_sync_writes(mut self, sync_writes: bool) -> Self {
        self.sync_writes = sync_writes;
        self
    }

    /// Sets whether batches bypass the write-ahead log entirely (default:
    /// `false` — see the module-level durability table).
    #[must_use]
    pub fn with_disable_wal(mut self, disable_wal: bool) -> Self {
        self.disable_wal = disable_wal;
        self
    }

    /// Sets the base [`rocksdb::Options`] the documented knobs are applied
    /// on top of — the escape hatch for tuning this surface does not
    /// expose. The documented knobs always win.
    #[must_use]
    pub fn with_base_options(mut self, base_options: rocksdb::Options) -> Self {
        self.base_options = Some(base_options);
        self
    }

    /// Builds the `RocksDB` options for an open: the base (if any), then the
    /// documented knobs, which override it.
    fn to_rocksdb_options(&self) -> rocksdb::Options {
        let mut options = self.base_options.clone().unwrap_or_default();
        options.create_if_missing(self.create_if_missing);
        options.set_compression_type(self.compression);
        options.set_write_buffer_size(self.write_buffer_size);
        options.set_max_open_files(self.max_open_files);
        options
    }

    /// The database directory this configuration opens.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Failure modes of the `RocksDB` store.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RocksdbError {
    /// A `RocksDB` operation (open, read, write, destroy) failed. The inner
    /// error carries `RocksDB`'s own status message.
    #[error("rocksdb operation failed: {0}")]
    Db(#[from] rocksdb::Error),
}

/// Shared engine behind every [`RocksdbStore`] clone.
struct Inner {
    db: rocksdb::DB,
    /// Per-batch durability settings, fixed at open and reused by every
    /// write (`WriteOptions` is borrowed, not consumed, by `write_opt`).
    write_options: WriteOptions,
    path: PathBuf,
}

/// A `RocksDB`-backed key-value store; see the [module docs](self).
///
/// Clones share one engine (`Arc`), so the same-store hint recognizes them
/// and cross-layer batching coalesces over a single handle.
#[derive(Clone)]
pub struct RocksdbStore {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for RocksdbStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RocksdbStore")
            .field("path", &self.inner.path)
            .finish()
    }
}

impl RocksdbStore {
    /// Opens (or creates) the database described by `config`.
    ///
    /// # Errors
    ///
    /// `RocksDB` open failures — a locked database (already open elsewhere in
    /// another *process*), an unwritable path, or a missing database when
    /// [`RocksdbConfig::with_create_if_missing`] is `false`.
    pub fn open(config: RocksdbConfig) -> Result<Self, RocksdbError> {
        let options = config.to_rocksdb_options();
        let db = rocksdb::DB::open(&options, &config.path).map_err(RocksdbError::from)?;

        let mut write_options = WriteOptions::default();
        write_options.set_sync(config.sync_writes);
        write_options.disable_wal(config.disable_wal);

        Ok(Self {
            inner: Arc::new(Inner {
                db,
                write_options,
                path: config.path,
            }),
        })
    }

    /// Opens (or creates) the database directory at `path` with default
    /// configuration.
    ///
    /// # Errors
    ///
    /// See [`RocksdbStore::open`].
    pub fn open_path(path: impl Into<PathBuf>) -> Result<Self, RocksdbError> {
        Self::open(RocksdbConfig::new(path))
    }

    /// Removes the database directory described by `config`.
    ///
    /// All [`RocksdbStore`] handles to the database must be dropped first —
    /// `RocksDB` locks the directory while any handle is live.
    ///
    /// # Errors
    ///
    /// `RocksDB` destroy failures (a live handle, a locked directory).
    pub fn destroy(config: &RocksdbConfig) -> Result<(), RocksdbError> {
        rocksdb::DB::destroy(&config.to_rocksdb_options(), &config.path).map_err(RocksdbError::from)
    }

    /// The database directory this handle fronts.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.inner.path
    }
}

impl Storage for RocksdbStore {
    type Error = RocksdbError;
}

impl Store for RocksdbStore {
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        // `multi_get` over `batched_multi_get_cf`: the contract requires an
        // owned `Vec<u8>` per hit, so the pinned-slice advantage of the
        // batched variant (which also needs a registered CF handle that a
        // plain open never populates) evaporates at this value size — and
        // `multi_get` runs the same MultiGet machinery over the default
        // column family without any handle bookkeeping. Results are
        // positionally aligned by construction.
        let results = self.inner.db.multi_get(keys.iter().copied());
        results
            .into_iter()
            .map(|hit| hit.map_err(RocksdbError::from))
            .collect()
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        // One WriteBatch, one write call: the whole batch is a single
        // atomic RocksDB unit, and operations apply in batch order (last
        // op on a key wins, exactly as the contract specifies).
        let mut write_batch = WriteBatch::default();
        for op in batch.ops {
            match op {
                Op::Put { key, value } => write_batch.put(key.as_ref(), value.as_ref()),
                Op::Delete { key } => write_batch.delete(key.as_ref()),
            }
        }
        self.inner
            .db
            .write_opt(write_batch, &self.inner.write_options)
            .map_err(RocksdbError::from)
    }

    fn identity(&self) -> usize {
        Arc::as_ptr(&self.inner).addr()
    }

    fn same_store(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    fn locator(&self) -> Option<StoreLocator> {
        Some(self.canonical_locator())
    }
}

impl Retrievable for RocksdbStore {
    fn canonical_locator(&self) -> StoreLocator {
        StoreLocator::from_bytes(self.inner.path.as_os_str().as_encoded_bytes().to_vec())
    }

    fn open(locator: &StoreLocator) -> Result<Self, Self::Error> {
        // Re-opening never creates: a locator names an existing store, and
        // a missing one is a backend failure, not a fresh database in
        // disguise. Durability knobs fall back to their documented
        // defaults (compression of already-written SSTs is baked into the
        // files anyway).
        Self::open(
            RocksdbConfig::new(os_path_bytes(locator.as_bytes())).with_create_if_missing(false),
        )
    }
}
