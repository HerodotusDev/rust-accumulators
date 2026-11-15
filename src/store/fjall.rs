//! Fjall store backend (native targets).
//!
//! Fjall is an LSM-tree engine whose [`Database`] houses named keyspaces
//! ("column families"), each an independent LSM-tree. This backend pins the
//! whole accumulator to one keyspace inside one database folder and maps the
//! crate contract onto fjall's primitives:
//!
//! - **Reads** are point [`Keyspace::get`] lookups over the crate's binary
//!   keys, positionally aligned with the request. Missing keys are `None`.
//! - **Writes** go through [`Database::batch`] — fjall's write batch
//!   commits atomically across keyspaces: observers see
//!   the whole batch or none of it (the hard [`Store::write`] contract;
//!   counters, nodes and root can never diverge). No transactional database
//!   is needed for this — the plain `Database` + write batch suffices, so
//!   no extra fjall cargo feature is required.
//! - **Keys** are used verbatim as fjall user keys: the crate's layout
//!   (`[id_len][id][table][subkey BE]`, see [`keys`](crate::store::keys)) is
//!   length-prefixed and therefore collision-free byte soup — no
//!   transformation at the store boundary. Fjall allows keys up to 64 KiB;
//!   the crate's keys peak at ~265 bytes. Values are likewise opaque bytes.
//!
//! # Durability
//!
//! A committed batch is always *consistent* after a crash (the journal
//! recovers atomically), but how far a committed batch survives a power
//! loss is configurable: by default fjall flushes to OS buffers
//! (application-crash safe); set [`FjallConfig::with_durability`] to
//! `PersistMode::SyncData`/`SyncAll` for `fdatasync`/`fsync` posture at
//! every commit's latency cost. [`Database::persist`] remains available on
//! the underlying handle ([`FjallStore::keyspace`] gives access to the
//! keyspace, whose `Deref` target reaches the database through fjall's own
//! API surface; persist via a [`Clone`] of the store's config instead).
//!
//! # Store identity and re-opening
//!
//! `Clone` is a cheap handle sharing the same database and keyspace (fjall
//! handles are internally `Arc`ed) — clones report
//! [`Store::same_store`] `= true`, so stacked-MMR routing coalesces their
//! batches. The canonical locator encodes the database folder path (raw OS
//! bytes) plus the keyspace name
//! (`[path_len: u32 BE][path][keyspace name]`); two locators are equal
//! exactly when they name the same storage. [`Retrievable::open`]
//! reconstructs a store from those bytes with fjall's default tuning —
//! tuning knobs are deliberately not part of store identity.
//!
//! Fjall holds an exclusive lock file per database folder: two live handles
//! onto the same path (in-process or cross-process) cannot coexist — use
//! [`Clone`] for a second handle, and re-open only after the previous store
//! was dropped.

use crate::store::internal::os_path_bytes;
use crate::store::{Batch, Op, Retrievable, Storage, Store, StoreLocator};
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use std::path::{Path, PathBuf};

/// Encodes the canonical locator: `[path_len: u32 BE][path][keyspace name]`.
/// The length prefix makes the (path, keyspace) split total — path bytes may
/// contain anything, including the keyspace name itself.
fn encode_locator(path: &Path, keyspace: &str) -> Result<StoreLocator, FjallError> {
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let path_len = u32::try_from(path_bytes.len()).map_err(|_| FjallError::Locator)?;
    let mut bytes = Vec::with_capacity(4 + path_bytes.len() + keyspace.len());
    bytes.extend_from_slice(&path_len.to_be_bytes());
    bytes.extend_from_slice(path_bytes);
    bytes.extend_from_slice(keyspace.as_bytes());
    Ok(StoreLocator::from_bytes(bytes))
}

/// Decodes a locator produced by [`encode_locator`].
fn decode_locator(bytes: &[u8]) -> Result<(PathBuf, String), FjallError> {
    let path_len_bytes: [u8; 4] = *bytes.first_chunk::<4>().ok_or(FjallError::Locator)?;
    let path_len =
        usize::try_from(u32::from_be_bytes(path_len_bytes)).map_err(|_| FjallError::Locator)?;
    let path = bytes.get(4..4 + path_len).ok_or(FjallError::Locator)?;
    let keyspace = bytes.get(4 + path_len..).ok_or(FjallError::Locator)?;
    let keyspace = String::from_utf8(keyspace.to_vec()).map_err(|_| FjallError::Locator)?;
    Ok((os_path_bytes(path), keyspace))
}

/// Mirrors fjall's own keyspace-name rule (`fjall::keyspace::name`):
/// non-empty, at most 255 bytes. Fjall *panics* on an invalid name, so this
/// check must run before every call into it.
fn validate_keyspace_name(name: &str) -> Result<(), FjallError> {
    if name.is_empty() || name.len() > 255 {
        return Err(FjallError::InvalidKeyspaceName);
    }
    Ok(())
}

/// Failures of the fjall backend.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FjallError {
    /// Opening the database or creating the keyspace failed.
    #[error("opening the fjall database failed")]
    Open(#[source] fjall::Error),
    /// A read or write against the underlying keyspace failed.
    #[error("fjall keyspace operation failed")]
    Backend(#[source] fjall::Error),
    /// The configured keyspace name is invalid: it must be 1–255 bytes
    /// (fjall's rule; an invalid name would panic inside fjall).
    #[error("invalid keyspace name: must be 1-255 bytes")]
    InvalidKeyspaceName,
    /// A locator could not be encoded or decoded: the bytes are not a
    /// well-formed fjall locator. Only reachable through hand-built locators
    /// or absurdly long paths — never through this store's own locators.
    #[error("malformed fjall store locator")]
    Locator,
}

/// Tuning knobs for [`FjallStore::open`]. Every knob defaults to fjall's own
/// default posture.
///
/// Tuning is **not** store identity: only `path` and `keyspace` are
/// canonical (they form the locator), so a store re-opened via
/// [`Retrievable::open`] runs on fjall's default tuning. Per-keyspace
/// options additionally only apply at keyspace *creation* — fjall ignores
/// them when the keyspace already exists.
#[derive(Clone, Debug)]
pub struct FjallConfig {
    /// Database folder — created if missing, recovered if it exists.
    /// Fjall holds an exclusive lock file here, so one live store per path.
    path: PathBuf,

    /// Keyspace name — fjall's column-family analogue, and the unit of
    /// isolation: two keyspaces in one database never see each other's
    /// keys. Must be 1–255 bytes (fjall panics otherwise; this store
    /// reports [`FjallError::InvalidKeyspaceName`] instead).
    keyspace: String,

    /// Block-index cache capacity in bytes. Larger = faster point reads at
    /// the cost of resident memory; fjall recommends ~20–25% of available
    /// memory, more if the working set fits entirely.
    cache_size: Option<u64>,

    /// Background worker threads (flush + compaction). Fewer threads trade
    /// background throughput for a smaller footprint. Fjall panics below 1;
    /// only pass `Some(n)` with `n >= 1`.
    worker_threads: Option<usize>,

    /// Maximum total journal size in bytes across the database — the point
    /// where fjall forces memtable flushes. Lower bounds write-buffer
    /// memory, higher smooths write bursts.
    max_journaling_size: Option<u64>,

    /// Per-keyspace memtable (write buffer) flush threshold in bytes.
    /// Lower = tighter memory, more frequent flushes; higher = fewer,
    /// larger flushes (fjall recommends 8–64 MiB).
    max_memtable_size: Option<u64>,

    /// Data-block compression, pinned across all levels. `None` keeps
    /// fjall's default (LZ4 when the `lz4` cargo feature is enabled,
    /// uncompressed otherwise). Only meaningful at keyspace creation.
    data_block_compression: Option<fjall::CompressionType>,

    /// Durability posture applied to every batch commit. `None` keeps
    /// fjall's default (flush to OS buffers — application-crash safe, not
    /// power-loss safe); `Some(PersistMode::SyncData)`/`SyncAll` adds
    /// `fdatasync`/`fsync` on every commit, buying power-loss durability
    /// with commit latency.
    durability: Option<PersistMode>,

    /// Deletes the whole database folder when the last handle to it drops
    /// (fjall's `temporary` flag). Convenient for ephemeral stores; every
    /// byte in the folder is lost, obviously.
    temporary: bool,
}

impl FjallConfig {
    /// A config with fjall's default tuning for the database at `path`,
    /// using the default keyspace name `"accumulators"`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            keyspace: String::from("accumulators"),
            cache_size: None,
            worker_threads: None,
            max_journaling_size: None,
            max_memtable_size: None,
            data_block_compression: None,
            durability: None,
            temporary: false,
        }
    }

    /// Names the keyspace the accumulator is pinned to.
    #[must_use]
    pub fn with_keyspace(mut self, keyspace: impl Into<String>) -> Self {
        self.keyspace = keyspace.into();
        self
    }

    /// Caps the block-index cache in bytes (see the field docs).
    #[must_use]
    pub fn with_cache_size(mut self, bytes: Option<u64>) -> Self {
        self.cache_size = bytes;
        self
    }

    /// Sets the background worker-thread count (see the field docs).
    #[must_use]
    pub fn with_worker_threads(mut self, threads: Option<usize>) -> Self {
        self.worker_threads = threads;
        self
    }

    /// Sets the total-journal-size threshold (see the field docs).
    #[must_use]
    pub fn with_max_journaling_size(mut self, bytes: Option<u64>) -> Self {
        self.max_journaling_size = bytes;
        self
    }

    /// Sets the per-keyspace memtable flush threshold (see the field docs).
    #[must_use]
    pub fn with_max_memtable_size(mut self, bytes: Option<u64>) -> Self {
        self.max_memtable_size = bytes;
        self
    }

    /// Sets data-block compression, pinned across all levels (see the field
    /// docs).
    #[must_use]
    pub fn with_data_block_compression(
        mut self,
        compression: Option<fjall::CompressionType>,
    ) -> Self {
        self.data_block_compression = compression;
        self
    }

    /// Sets the per-commit durability posture (see the field docs).
    #[must_use]
    pub fn with_durability(mut self, durability: Option<PersistMode>) -> Self {
        self.durability = durability;
        self
    }

    /// Deletes the database folder when the last handle drops (see the
    /// field docs).
    #[must_use]
    pub fn with_temporary(mut self, temporary: bool) -> Self {
        self.temporary = temporary;
        self
    }
}

/// Shared state behind every [`FjallStore`] handle: the database, the pinned
/// keyspace, and the identity/durability data derived from the config.
struct Inner {
    db: Database,
    keyspace: Keyspace,
    locator: StoreLocator,
    durability: Option<PersistMode>,
}

/// A fjall-backed key-value store.
///
/// `Clone` is a cheap handle onto the same database and keyspace (clones
/// report [`Store::same_store`] `= true`). Open through [`FjallConfig`] —
/// or re-open from a locator via [`Retrievable::open`].
#[derive(Clone)]
pub struct FjallStore {
    inner: Arc<Inner>,
}

impl core::fmt::Debug for FjallStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("FjallStore(...)")
    }
}

impl Storage for FjallStore {
    type Error = FjallError;
}

impl FjallStore {
    /// Opens (or creates) the database at `config.path` and pins the store
    /// to `config.keyspace`.
    ///
    /// # Errors
    ///
    /// Invalid keyspace name, locator-encoding overflow, or any underlying
    /// open/creation failure.
    pub fn open(config: FjallConfig) -> Result<Self, FjallError> {
        let FjallConfig {
            path,
            keyspace,
            cache_size,
            worker_threads,
            max_journaling_size,
            max_memtable_size,
            data_block_compression,
            durability,
            temporary,
        } = config;
        validate_keyspace_name(&keyspace)?;

        let mut builder = Database::builder(&path);
        if let Some(cache_size) = cache_size {
            builder = builder.cache_size(cache_size);
        }
        if let Some(worker_threads) = worker_threads {
            builder = builder.worker_threads(worker_threads);
        }
        if let Some(max_journaling_size) = max_journaling_size {
            builder = builder.max_journaling_size(max_journaling_size);
        }
        if temporary {
            builder = builder.temporary(true);
        }
        let db = builder.open().map_err(FjallError::Open)?;

        let locator = encode_locator(&path, &keyspace)?;

        let keyspace = db
            .keyspace(&keyspace, || {
                let mut options = KeyspaceCreateOptions::default();
                if let Some(max_memtable_size) = max_memtable_size {
                    options = options.max_memtable_size(max_memtable_size);
                }
                if let Some(compression) = data_block_compression {
                    options = options.data_block_compression_policy(
                        fjall::config::CompressionPolicy::all(compression),
                    );
                }
                options
            })
            .map_err(FjallError::Open)?;

        Ok(Self {
            inner: Arc::new(Inner {
                db,
                keyspace,
                locator,
                durability,
            }),
        })
    }

    /// Handle to the underlying keyspace — an escape hatch for fjall-only
    /// operations this contract does not surface (prefix scans, range
    /// iteration, statistics).
    #[must_use]
    pub fn keyspace(&self) -> &Keyspace {
        &self.inner.keyspace
    }

    /// Opens (or creates) the database at `path` with the default keyspace
    /// name and default tuning.
    ///
    /// # Errors
    ///
    /// See [`FjallStore::open`].
    pub fn open_path(path: impl Into<PathBuf>) -> Result<Self, FjallError> {
        Self::open(FjallConfig::new(path))
    }
}

impl Store for FjallStore {
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        keys.iter()
            .map(|key| {
                self.inner
                    .keyspace
                    .get(*key)
                    .map(|value| value.map(|value| value.to_vec()))
                    .map_err(FjallError::Backend)
            })
            .collect()
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        if batch.is_empty() {
            return Ok(());
        }

        // The atomicity contract: fjall's write batch commits across
        // keyspaces as one unit — the whole batch lands or none of it does.
        // `Database::batch` already applies fjall's default durability
        // posture; an explicit config override takes precedence.
        let mut write_batch = self.inner.db.batch();
        if let Some(durability) = self.inner.durability {
            write_batch = write_batch.durability(Some(durability));
        }
        for op in &batch.ops {
            match op {
                Op::Put { key, value } => {
                    write_batch.insert(&self.inner.keyspace, key.as_ref(), value.as_ref());
                }
                Op::Delete { key } => {
                    write_batch.remove(&self.inner.keyspace, key.as_ref());
                }
            }
        }
        write_batch.commit().map_err(FjallError::Backend)
    }

    fn identity(&self) -> usize {
        Arc::as_ptr(&self.inner).addr()
    }

    fn locator(&self) -> Option<StoreLocator> {
        Some(self.inner.locator.clone())
    }

    fn same_store(&self, other: &Self) -> bool {
        // Clones share the handle; independently re-opened stores name the
        // same storage through their (path, keyspace) locator.
        Arc::ptr_eq(&self.inner, &other.inner) || self.inner.locator == other.inner.locator
    }
}

impl Retrievable for FjallStore {
    fn canonical_locator(&self) -> StoreLocator {
        self.inner.locator.clone()
    }

    fn open(locator: &StoreLocator) -> Result<Self, Self::Error> {
        let (path, keyspace) = decode_locator(locator.as_bytes())?;
        Self::open(FjallConfig::new(path).with_keyspace(keyspace))
    }
}
