//! Storage abstraction: a minimal, batch-first, byte-oriented key-value
//! contract — two methods over bytes:
//!
//! - [`Store::read`](crate::store::Store::read) — batched point reads, positional results,
//! - [`Store::write`](crate::store::Store::write) — an **atomic** [`Batch`](crate::store::Batch) of puts and deletes.
//!
//! Everything else (namespacing, counters, typed node tables) lives with the
//! accumulator, not the store. This is the smallest surface a new backend
//! (postgres, redis, …) needs to implement, and it maps 1:1 onto each
//! backend's native batch API.
//!
//! # Contracts a store implementation must honor
//!
//! 1. `read` returns results **positionally aligned** with the requested
//!    keys; missing keys are `None`, never errors.
//! 2. `write` applies all operations atomically: observers see either the
//!    full batch or none of it. **This is a hard requirement, not an
//!    optimization** — see "Atomicity (required)" below.
//! 3. Keys and values are opaque bytes to the store; the crate's binary key
//!    layout (see [`keys`](crate::store::keys)) is private to the accumulators.
//!
//! # Atomicity (required)
//!
//! `write` MUST apply the whole batch as one atomic unit. This is not
//! optional and cannot be degraded to best-effort:
//!
//! - An append persists new nodes, counters and root **in one batch**. A
//!   partially-applied batch corrupts the accumulator: counters advance
//!   while nodes are missing, and every proof after that is garbage.
//! - A draft commit persists the whole overlay (nodes, counters, root,
//!   nullifier records) in one batch; partial application silently forks
//!   the MMR's history.
//!
//! Backends without multi-key atomic writes (transactions, write batches,
//! `MULTI/EXEC`) cannot implement this trait faithfully — rocksdb's
//! `WriteBatch`, redb's transactions, SQLite's `BEGIN/COMMIT`, Postgres
//! transactions and Redis `MULTI/EXEC` all qualify. There is deliberately
//! no capability flag or recovery-scan fallback: the guarantees clients can
//! assume are exactly the ones this contract states.
//!
//! # Store identity (optional, batching hint)
//!
//! [`Store::same_store`](crate::store::Store::same_store) lets a backend declare when two instances share the
//! same underlying storage. The stacked-MMR router uses it to coalesce
//! cross-layer reads and writes into one batched call per distinct store;
//! the default `false` is always correct and merely skips the optimization.

use alloc::borrow::Cow;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;

#[cfg(feature = "memory")]
pub mod memory;

#[cfg(feature = "heapless")]
pub mod heapless;

#[cfg(all(feature = "sqlite", not(target_family = "wasm")))]
pub mod sqlite;

#[cfg(all(feature = "sled", not(target_family = "wasm")))]
pub mod sled;

#[cfg(all(feature = "fjall", not(target_family = "wasm")))]
pub mod fjall;

#[cfg(all(feature = "redb", not(target_family = "wasm")))]
pub mod redb;

#[cfg(all(feature = "rocksdb", not(target_family = "wasm")))]
pub mod rocksdb;

/// The error axis of a storage backend, shared by the sync and async
/// contracts.
///
/// Every accumulator error type is generic over `Storage` — not over a
/// concrete store trait — so the sync and async shells share one error enum
/// (e.g. the MMR's `MmrError` names the backend error through
/// `S::Error` either way). A backend implementing both [`Store`] and
/// [`AsyncStore`] necessarily reports the *same* error type through both,
/// which is the invariant users want; there is no wrapper or adapter for
/// error shapes anywhere in the crate.
pub trait Storage {
    /// Backend-specific error type.
    type Error: core::error::Error + Send + Sync + 'static;
}

/// A synchronous key-value store.
///
/// Object safety is not a goal — accumulators are generic over `S: Store`
/// for static dispatch. Async backends implement [`AsyncStore`] instead and
/// plug into the async MMR (`crate::mmr::AsyncMmr`).
///
/// A minimal backend is a batched read and an atomic write — a map behind a
/// lock already satisfies the contract (the lock-protected snapshot makes
/// every write all-or-nothing by construction):
///
/// ```
/// use accumulators::store::{Batch, Op, Store, Storage};
/// use std::borrow::Cow;
/// use std::collections::BTreeMap;
/// use std::sync::Mutex;
///
/// #[derive(Default)]
/// struct MapStore(Mutex<BTreeMap<Vec<u8>, Vec<u8>>>);
///
/// impl Storage for MapStore {
///     type Error = core::convert::Infallible;
/// }
///
/// impl Store for MapStore {
///     fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
///         let map = self.0.lock().unwrap();
///         Ok(keys.iter().map(|k| map.get(*k).cloned()).collect())
///     }
///
///     fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
///         let mut map = self.0.lock().unwrap();
///         for op in batch.ops {
///             match op {
///                 Op::Put { key, value } => {
///                     map.insert(key.into_owned(), value.into_owned());
///                 }
///                 Op::Delete { key } => {
///                     map.remove(&key.into_owned());
///                 }
///             }
///         }
///         Ok(())
///     }
/// }
///
/// let store = MapStore::default();
/// let batch: Batch = [Op::Put {
///     key: Cow::Borrowed(b"key"),
///     value: Cow::Borrowed(b"value"),
/// }]
/// .into_iter()
/// .collect();
/// store.write(batch).unwrap();
/// assert_eq!(store.read(&[b"key"]).unwrap(), vec![Some(b"value".to_vec())]);
/// ```
pub trait Store: Storage {
    /// Batched point read. Results are positionally aligned with `keys`;
    /// `None` for keys not present.
    ///
    /// # Errors
    ///
    /// Backend I/O failures. A missing key is *not* an error.
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error>;

    /// Atomically applies a batch of puts and deletes.
    ///
    /// # Errors
    ///
    /// Backend I/O failures. On error the store is left untouched.
    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error>;

    /// Opaque identity of the underlying storage: two handles with equal
    /// identities name the same bytes. Defaults to the instance's address —
    /// override when clones share data (e.g. an `Arc`-backed map).
    fn identity(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }

    /// Canonical locator when the backend supports re-opening (see
    /// [`Retrievable`]); `None` for session-local backends. Used to persist
    /// stacked-MMR layers.
    fn locator(&self) -> Option<StoreLocator> {
        None
    }

    /// Whether `self` and `other` are two handles onto the same underlying
    /// storage. Pure performance hint for cross-layer batching: the default
    /// (`false`) is always correct and merely keeps groups separate.
    fn same_store(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

/// An asynchronous key-value store (native targets).
///
/// Same contracts as [`Store`]; async variant for runtimes like tokio.
/// Defined with native `async fn` in trait — no `async-trait` boxing.
pub trait AsyncStore: Storage {
    /// Batched point read; see [`Store::read`].
    ///
    /// # Errors
    ///
    /// Backend I/O failures.
    fn read(
        &self,
        keys: &[&[u8]],
    ) -> impl Future<Output = Result<Vec<Option<Vec<u8>>>, Self::Error>> + Send;

    /// Atomic batch write; see [`Store::write`].
    ///
    /// # Errors
    ///
    /// Backend I/O failures.
    fn write(&self, batch: Batch<'_>) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Opaque identity of the underlying storage; see [`Store::identity`].
    fn identity(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }

    /// Canonical locator when the backend supports re-opening; see
    /// [`Store::locator`].
    fn locator(&self) -> Option<StoreLocator> {
        None
    }

    /// Whether `self` and `other` share the same underlying storage; see
    /// [`Store::same_store`].
    fn same_store(&self, other: &Self) -> bool {
        self.identity() == other.identity()
    }
}

/// An atomic unit of storage mutations.
///
/// Constructed by pushing operations, then handed to [`Store::write`].
/// Keys and values are `Cow` so hot paths can write borrowed bytes without
/// cloning, while runtime-built keys and values (the crate's own key encoder
/// returns `Vec<u8>`) fit the same batch.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Batch<'a> {
    /// Ordered operations; applied in order within the atomic write.
    pub ops: Vec<Op<'a>>,
}

impl<'a> Batch<'a> {
    /// An empty batch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a put of borrowed key and value.
    pub fn put(&mut self, key: &'a [u8], value: &'a [u8]) {
        self.ops.push(Op::Put {
            key: Cow::Borrowed(key),
            value: Cow::Borrowed(value),
        });
    }

    /// Adds a put of owned bytes (for values built at runtime).
    pub fn put_owned(&mut self, key: impl Into<Cow<'a, [u8]>>, value: Vec<u8>) {
        self.ops.push(Op::Put {
            key: key.into(),
            value: Cow::Owned(value),
        });
    }

    /// Adds a delete (borrowed or runtime-built key).
    pub fn delete(&mut self, key: impl Into<Cow<'a, [u8]>>) {
        self.ops.push(Op::Delete { key: key.into() });
    }

    /// Whether the batch would do nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
    }
}

impl<'a> Extend<Op<'a>> for Batch<'a> {
    fn extend<I: IntoIterator<Item = Op<'a>>>(&mut self, iter: I) {
        self.ops.extend(iter);
    }
}

impl<'a> FromIterator<Op<'a>> for Batch<'a> {
    fn from_iter<I: IntoIterator<Item = Op<'a>>>(iter: I) -> Self {
        Self {
            ops: iter.into_iter().collect(),
        }
    }
}

/// One operation in a [`Batch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op<'a> {
    /// Store `value` at `key`.
    Put {
        /// Key to write.
        key: Cow<'a, [u8]>,
        /// Value to write.
        value: Cow<'a, [u8]>,
    },
    /// Remove `key`.
    Delete {
        /// Key to remove.
        key: Cow<'a, [u8]>,
    },
}

/// Canonical, persistable descriptor of how to re-open a store.
///
/// Produced by [`Retrievable::canonical_locator`]; its bytes are opaque to the crate.
/// Locators must be **canonical**: two locators are equal if and only if
/// they name the same underlying store — this equality *is* store identity,
/// which the stacked-MMR routing uses to coalesce cross-layer batches.
///
/// # Trust model
///
/// Locators must come from [`Retrievable::canonical_locator`] — a hand-built locator
/// that collides with a real store's canonical encoding silently merges two
/// distinct stores into one routing group (wrong reads, no error). Likewise,
/// the keyspace of a store is trusted to co-tenants: a [`Batch`] may write
/// any key, including another accumulator's.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct StoreLocator(Vec<u8>);

impl StoreLocator {
    /// Wraps raw locator bytes (backend-defined: file path, DSN, directory…).
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the raw locator bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for StoreLocator {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl From<StoreLocator> for Vec<u8> {
    fn from(locator: StoreLocator) -> Self {
        locator.0
    }
}

impl From<&str> for StoreLocator {
    fn from(text: &str) -> Self {
        Self(text.as_bytes().to_vec())
    }
}

impl From<String> for StoreLocator {
    fn from(text: String) -> Self {
        Self(text.into_bytes())
    }
}

/// A store that can be re-opened from its persisted locator.
///
/// **Required for stores used as stacked-MMR layers**: opening a stacked MMR
/// reconstructs every layer's store from the persisted sub-view metadata,
/// which only contains locators. Memory stores participate by exposing a
/// caller-chosen id as their locator (session-scoped stacks).
///
/// Locator equality doubles as store identity: the stacked-MMR router
/// groups requests **per store** at every operation (same-store layers join
/// one batched call, keys deduplicated) and makes exactly one batched call
/// per distinct store per operation.
///
/// # Relationship to [`Store::locator`]
///
/// [`Store::locator`] is the *hint* a store gives when asked (default
/// `None`); [`Retrievable::canonical_locator`] is the *canonical* answer
/// used for persistence. Pinning persists `Store::locator`, so a store
/// implementing both should make the default `locator()` return the same
/// bytes as `canonical_locator()` — override `locator()` whenever the
/// inherited default (`None`) would under-report a re-openable store (the
/// reference `InMemoryStore::shared` (feature `memory`) does exactly this).
pub trait Retrievable: Store + Sized {
    /// The canonical locator of this store instance.
    fn canonical_locator(&self) -> StoreLocator;

    /// Re-opens the store named by `locator`.
    ///
    /// # Errors
    ///
    /// Backend failures (missing file, unreachable server, …).
    fn open(locator: &StoreLocator) -> Result<Self, Self::Error>;
}

/// Type-erased store error: the wrapped backend's error, boxed.
///
/// A newtype because `Box<dyn Error>` does not itself implement `Error`
/// (the std blanket impl requires `E: Sized`).
#[derive(Debug)]
pub struct DynError(pub alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>);

impl core::fmt::Display for DynError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.0, f)
    }
}

impl core::error::Error for DynError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        self.0.source()
    }
}

/// Object-safe core behind [`ErasedStore`].
pub trait DynStore: Send + Sync {
    /// See [`Store::read`].
    ///
    /// # Errors
    ///
    /// Backend I/O failures, boxed.
    fn read_dyn(
        &self,
        keys: &[&[u8]],
    ) -> Result<alloc::vec::Vec<Option<alloc::vec::Vec<u8>>>, DynError>;
    /// See [`Store::write`].
    ///
    /// # Errors
    ///
    /// Backend I/O failures, boxed.
    fn write_dyn(&self, batch: Batch<'_>) -> Result<(), DynError>;
    /// Opaque storage identity; see [`Store::identity`].
    fn identity_dyn(&self) -> usize;
    /// Canonical locator; see [`Store::locator`].
    fn locator_dyn(&self) -> Option<StoreLocator>;
}

impl<S: Store + Send + Sync + 'static> DynStore for S {
    fn read_dyn(
        &self,
        keys: &[&[u8]],
    ) -> Result<alloc::vec::Vec<Option<alloc::vec::Vec<u8>>>, DynError> {
        self.read(keys)
            .map_err(|e| DynError(alloc::boxed::Box::new(e)))
    }

    fn write_dyn(&self, batch: Batch<'_>) -> Result<(), DynError> {
        self.write(batch)
            .map_err(|e| DynError(alloc::boxed::Box::new(e)))
    }

    fn identity_dyn(&self) -> usize {
        Store::identity(self)
    }

    fn locator_dyn(&self) -> Option<StoreLocator> {
        Store::locator(self)
    }
}

/// A type-erased store — the opt-in cost of mixed-type stacks.
///
/// All layers of a stacked MMR share one store *type* `S`. To stack layers
/// backed by different store types (e.g. sqlite history + memory hot layer),
/// wrap **every** layer — top included — in `ErasedStore` and build the
/// stack over `S = ErasedStore`:
///
/// ```
/// use accumulators::ids::AccumulatorId;
/// use accumulators::mmr::{MmrSize, SubView};
/// use accumulators::store::memory::InMemoryStore;
/// use accumulators::store::ErasedStore;
///
/// // Each layer's view is erased individually, then assembled into a stack.
/// let store = InMemoryStore::shared("erased-store-doc");
/// let view: SubView<_, AccumulatorId> =
///     SubView::single(AccumulatorId::ZERO, store, MmrSize::ZERO);
/// let erased: SubView<ErasedStore, _> = view.erased();
/// # let _ = erased;
/// ```
///
/// (An `Mmr::pin()` produces the same view from a live accumulator; see
/// `crate::mmr::SubView::erased` and the `stacked_mmr` feature for the full
/// flow.)
///
/// Costs (all opt-in, per wrapped layer): dynamic dispatch per *batched*
/// operation (noise next to I/O), and errors surfaced as [`DynError`]
/// (match the concrete backend error via `downcast_ref`).
///
/// Erased stacks are **session-local**: an `ErasedStore` cannot be re-opened
/// from a locator (no registry), so persistent stacks require a concrete
/// [`Retrievable`] store type.
#[derive(Clone)]
pub struct ErasedStore(alloc::sync::Arc<dyn DynStore>);

impl ErasedStore {
    /// Erases a concrete store.
    #[must_use]
    pub fn new<S: Store + Send + Sync + 'static>(store: S) -> Self {
        Self(alloc::sync::Arc::new(store))
    }
}

impl core::fmt::Debug for ErasedStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ErasedStore(...)")
    }
}

impl Storage for ErasedStore {
    type Error = DynError;
}

impl Store for ErasedStore {
    fn read(
        &self,
        keys: &[&[u8]],
    ) -> Result<alloc::vec::Vec<Option<alloc::vec::Vec<u8>>>, Self::Error> {
        self.0.read_dyn(keys)
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        self.0.write_dyn(batch)
    }

    fn identity(&self) -> usize {
        self.0.identity_dyn()
    }

    fn same_store(&self, other: &Self) -> bool {
        self.0.identity_dyn() == other.0.identity_dyn()
    }
}

/// Object-safe core behind [`ErasedAsyncStore`].
pub trait DynAsyncStore: Send + Sync {
    /// See [`AsyncStore::read`].
    ///
    /// # Errors
    ///
    /// Backend I/O failures, boxed.
    fn read_dyn<'s>(&'s self, keys: &'s [&'s [u8]]) -> ReadFuture<'s>;
    /// See [`AsyncStore::write`].
    ///
    /// # Errors
    ///
    /// Backend I/O failures, boxed.
    fn write_dyn<'s>(&'s self, batch: Batch<'s>) -> WriteFuture<'s>;
    /// Opaque storage identity; see [`Store::identity`].
    fn identity_dyn(&self) -> usize;
    /// Canonical locator; see [`Store::locator`].
    fn locator_dyn(&self) -> Option<StoreLocator>;
}

/// Boxed future of an erased async batched read.
pub type ReadFuture<'s> = core::pin::Pin<
    alloc::boxed::Box<
        dyn Future<Output = Result<alloc::vec::Vec<Option<alloc::vec::Vec<u8>>>, DynError>>
            + Send
            + 's,
    >,
>;

/// Boxed future of an erased async batched write.
pub type WriteFuture<'s> =
    core::pin::Pin<alloc::boxed::Box<dyn Future<Output = Result<(), DynError>> + Send + 's>>;

impl<S: AsyncStore + Send + Sync + 'static> DynAsyncStore for S {
    fn read_dyn<'s>(&'s self, keys: &'s [&'s [u8]]) -> ReadFuture<'s> {
        alloc::boxed::Box::pin(async move {
            self.read(keys)
                .await
                .map_err(|e| DynError(alloc::boxed::Box::new(e)))
        })
    }

    fn write_dyn<'s>(&'s self, batch: Batch<'s>) -> WriteFuture<'s> {
        alloc::boxed::Box::pin(async move {
            self.write(batch)
                .await
                .map_err(|e| DynError(alloc::boxed::Box::new(e)))
        })
    }

    fn identity_dyn(&self) -> usize {
        AsyncStore::identity(self)
    }

    fn locator_dyn(&self) -> Option<StoreLocator> {
        AsyncStore::locator(self)
    }
}

/// Async counterpart of [`ErasedStore`] — same costs, same session-local
/// limitation.
pub struct ErasedAsyncStore(alloc::sync::Arc<dyn DynAsyncStore>);

impl ErasedAsyncStore {
    /// Erases a concrete async store.
    #[must_use]
    pub fn new<S: AsyncStore + Send + Sync + 'static>(store: S) -> Self {
        Self(alloc::sync::Arc::new(store))
    }
}

impl core::fmt::Debug for ErasedAsyncStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ErasedAsyncStore(...)")
    }
}

impl Storage for ErasedAsyncStore {
    type Error = DynError;
}

impl AsyncStore for ErasedAsyncStore {
    async fn read(
        &self,
        keys: &[&[u8]],
    ) -> Result<alloc::vec::Vec<Option<alloc::vec::Vec<u8>>>, Self::Error> {
        self.0.read_dyn(keys).await
    }

    async fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        self.0.write_dyn(batch).await
    }

    fn locator(&self) -> Option<StoreLocator> {
        self.0.locator_dyn()
    }

    fn identity(&self) -> usize {
        self.0.identity_dyn()
    }

    fn same_store(&self, other: &Self) -> bool {
        self.0.identity_dyn() == other.0.identity_dyn()
    }
}

/// Binary key layout for accumulator metadata and nodes — and the complete
/// persisted-value formats. **This module's docs are the wire spec**; every
/// store backend sees exactly these bytes.
///
/// # Keys
///
/// `[id_len: u8][id: id_len bytes][table: u8][subkey: u64 BE]`
///
/// Length-prefixing makes decoding total (no delimiter parsing, no `:` in id
/// foot-guns); any id content of up to 255 bytes is safe. `subkey` semantics
/// are per-table; metadata tables use `0`.
///
/// # Values
///
/// All multi-byte integers are **big-endian**. Shared record shapes:
///
/// - **hash value** — the canonical [`HashValue`](crate::primitives::HashValue)
///   byte encoding (`LEN` bytes, fixed per hasher). Used by `Nodes`, `Root`
///   and `TreeNode`.
/// - **counter** — `u64` BE, 8 bytes. Used by `LeafCount`, `NodeCount` and
///   `Nullifiers`.
/// - **text record** — `[len: u16 BE][utf-8 bytes]`. Used by `Mode` and the
///   `HasherInfo` config segment.
///
/// Per-table values:
///
/// | Table        | Value                                                                                             |
/// |--------------|---------------------------------------------------------------------------------------------------|
/// | `Nodes`      | hash value                                                                                        |
/// | `LeafCount`  | counter                                                                                            |
/// | `NodeCount`  | counter                                                                                            |
/// | `Root`       | hash value (the cached root)                                                                      |
/// | `HasherInfo` | `[id_tag: u8]` + custom-name segment + config text record (see below)                             |
/// | `Mode`       | text record — the mode's `NAME`                                                                   |
/// | `Nullifiers` | counter — size at nullification, `0` = deep                                                       |
/// | `Subviews`   | `[count: u16 BE]` then per layer, bottom → top: `[id_len: u8][id][pinned_size: u64 BE][locator_len: u16 BE][locator]` |
/// | `Provenance` | `[kind: u8]` (`0` = full history, `1` = peaks-only) +, for peaks-only, `[seed node count: u64 BE]`      |
/// | `TreeNode`   | hash value; subkey is the **1-based heap index** (root `1`, leaf `i` at `2^depth + i`)            |
/// | `TreeMeta`   | `[depth: u8][null leaf: hash value]`                                                              |
///
/// `HasherInfo` id tags (wire format, like [`Table`](keys::Table) discriminants):
/// `0` = Keccak256, `1` = Poseidon, `2` = Pedersen, `3` = Blake2s,
/// `4` = Custom — custom tags are followed by `[name_len: u8][name utf-8]`.
/// The config text record always follows (possibly empty). `open` validates
/// tag, name and config byte-for-byte.
///
/// The `Subviews` list holds only the *pinned sub-layers*; the stacked MMR's
/// own id/store is the key id and the store holding this record. Pin sizes
/// are cross-checked against each layer's own metadata on open.
///
/// The `TreeNode` heap index packs (depth, index-within-level) losslessly in
/// one `u64` — `depth = 63 - leading_zeros(idx)`, position = `idx - 2^depth`
/// — so no composite key packing is ever needed. Capacity is bounded by
/// `u64` heap indexing (2^63 leaves), far beyond practical trees.
pub mod keys {
    use crate::ids::TreeId;
    use alloc::vec::Vec;

    /// Which namespace a key belongs to. Tag byte in the key layout.
    ///
    /// Renaming these variants does not change persisted data; **reordering
    /// or renumbering does** — treat the discriminants as a wire format.
    ///
    /// `#[non_exhaustive]`: the wire format grows as the crate grows (new
    /// tables), so downstream matches must carry a wildcard arm.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    #[non_exhaustive]
    #[repr(u8)]
    pub enum Table {
        /// Node hashes: subkey is the [`u64`] node index.
        Nodes = 0,
        /// Leaf counter: subkey `0`, value is a `u64` BE.
        LeafCount = 1,
        /// Node counter (MMR size): subkey `0`, value is a `u64` BE.
        NodeCount = 2,
        /// Cached root hash: subkey `0`, value is the hash value.
        Root = 3,
        /// Hasher identity + config, persisted at creation: subkey `0`.
        HasherInfo = 4,
        /// Mutability mode, persisted at creation: subkey `0`, value is the
        /// mode's `NAME` string.
        Mode = 5,
        /// Nullifier records
        /// (`Nullifying` mode): subkey is
        /// the leaf index, value is the size at nullification (`u64` BE).
        Nullifiers = 6,
        /// Stacked-MMR sub-view metadata: subkey `0`; value is the encoded
        /// per-layer record list (see the module-level format spec).
        Subviews = 7,
        /// Merkle-tree node hashes: subkey is the 1-based heap index, value
        /// is the canonical [`HashValue`](crate::primitives::HashValue)
        /// encoding (see the module-level format spec).
        TreeNode = 8,
        /// Merkle-tree metadata: subkey `0`, value is
        /// `[depth: u8][null leaf: hash value]`.
        TreeMeta = 9,
        /// MMR provenance (full history vs peaks-only seed): subkey `0`,
        /// value is `[kind: u8]` (`0` = full, `1` = peaks-only) +, for
        /// peaks-only, the seed node count as `u64` BE (see the module-level
        /// format spec). Persisted at creation; every `open` path requires
        /// it — without it a peaks-only MMR would silently reopen as
        /// full-history and its proof floor would be lost.
        Provenance = 10,
    }

    impl Table {
        /// Rebuilds from the wire tag byte. `None` for unknown tags (a
        /// foreign key — skipped, never a parse error).
        #[must_use]
        pub const fn from_repr(tag: u8) -> Option<Self> {
            match tag {
                0 => Some(Self::Nodes),
                1 => Some(Self::LeafCount),
                2 => Some(Self::NodeCount),
                3 => Some(Self::Root),
                4 => Some(Self::HasherInfo),
                5 => Some(Self::Mode),
                6 => Some(Self::Nullifiers),
                7 => Some(Self::Subviews),
                8 => Some(Self::TreeNode),
                9 => Some(Self::TreeMeta),
                10 => Some(Self::Provenance),
                _ => None,
            }
        }
    }

    /// Encodes a full key.
    ///
    /// # Panics
    ///
    /// Panics if the id encodes to more than 255 bytes: the u8 length
    /// prefix is the key wire format, so a longer id cannot be represented
    /// — and silently truncating it would alias one accumulator's keyspace
    /// onto another's (cross-accumulator corruption). A too-long id is a
    /// programming error, not a runtime condition.
    #[must_use]
    pub fn encode<Id: TreeId>(id: &Id, table: Table, subkey: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(1 + 16 + 1 + 8);
        let mut id_bytes = Vec::new();
        id.encode_into(&mut id_bytes);
        assert!(
            u8::try_from(id_bytes.len()).is_ok(),
            "tree id encodes to {} bytes; the key wire format caps ids at 255",
            id_bytes.len()
        );
        #[expect(
            clippy::cast_possible_truncation,
            reason = "checked above: len <= 255 fits u8"
        )]
        key.push(id_bytes.len() as u8);
        key.extend_from_slice(&id_bytes);
        key.push(table as u8);
        key.extend_from_slice(&subkey.to_be_bytes());
        key
    }

    /// Decodes a key into its raw parts — the id's bytes (in encoding order),
    /// the table, and the subkey — or `None` if the key was not produced by
    /// [`encode`] (a foreign key in the store: skipped, never a parse error).
    /// Typed id reconstruction is the caller's job via its own [`TreeId`].
    #[must_use]
    pub fn decode(key: &[u8]) -> Option<(Vec<u8>, Table, u64)> {
        let id_len = *key.first()? as usize;
        let rest = key.get(1 + id_len..)?;
        let table = Table::from_repr(*rest.first()?)?;
        let subkey_bytes: [u8; 8] = rest.get(1..)?.try_into().ok()?;
        Some((
            key[1..=id_len].to_vec(),
            table,
            u64::from_be_bytes(subkey_bytes),
        ))
    }
}

/// Persisted-record codecs shared by the accumulators — the concrete
/// implementations of the value shapes specified in the [`keys`] module
/// docs.
#[cfg(any(feature = "mmr", feature = "merkle_tree"))]
pub(crate) mod record {
    use crate::hashers::{Hasher, HasherId};
    use crate::primitives::HashValue;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Encodes a `u64` counter (8 bytes BE).
    #[cfg(feature = "mmr")]
    #[must_use]
    pub(crate) fn counter(value: u64) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    /// Decodes a `u64` counter.
    #[cfg(feature = "mmr")]
    pub(crate) fn parse_counter(bytes: &[u8]) -> Option<u64> {
        Some(u64::from_be_bytes(bytes.try_into().ok()?))
    }

    /// Encodes a text record (`[len: u16 BE][utf-8]`).
    #[must_use]
    pub(crate) fn text(value: &str) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + value.len());
        // u16 BE length prefix is the text wire format. Callers must check
        // `value.len() <= u16::MAX` first (as `hasher_info` does): a silent
        // cast truncation would corrupt the record and brick later opens.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "u16 length prefix is the text wire format; len < 65536"
        )]
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
        out
    }

    /// Decodes a text record.
    pub(crate) fn parse_text(bytes: &[u8]) -> Option<String> {
        let len_bytes: [u8; 2] = *bytes.first_chunk::<2>()?;
        let len = u16::from_be_bytes(len_bytes) as usize;
        String::from_utf8(bytes.get(2..2 + len)?.to_vec()).ok()
    }

    /// Encodes a hash value of the hasher's output type.
    #[must_use]
    pub(crate) fn hash_value<O: HashValue>(value: &O) -> Vec<u8> {
        value.to_vec()
    }

    /// Encodes the `HasherInfo` record: wire tag + (custom) name + config.
    ///
    /// Returns `None` when the hasher cannot be represented in the wire
    /// format: a custom name over 255 bytes (u8 length prefix) or a config
    /// over 65535 bytes (u16 length prefix). The caller must fail at
    /// creation — silently truncating would persist a record that bricks
    /// every later open with a permanent hasher mismatch.
    #[must_use]
    pub(crate) fn hasher_info<H: Hasher>(hasher: &H) -> Option<Vec<u8>> {
        let config = hasher.config();
        if config.len() > u16::MAX as usize {
            return None;
        }
        let mut out = Vec::new();
        out.push(hasher.id().tag());
        if let HasherId::Custom(name) = hasher.id() {
            out.push(u8::try_from(name.len()).ok()?);
            out.extend_from_slice(name.as_bytes());
        }
        out.extend_from_slice(&text(&config));
        Some(out)
    }

    /// Decodes the `HasherInfo` record into its parts.
    pub(crate) fn parse_hasher_info(bytes: &[u8]) -> Option<(HasherId, String)> {
        let tag = *bytes.first()?;
        let rest = &bytes[1..];
        let (id, rest) = if tag == 4 {
            let name_len = *rest.first()? as usize;
            let name = core::str::from_utf8(rest.get(1..1 + name_len)?).ok()?;
            (HasherId::from_tag(tag, Some(name))?, &rest[1 + name_len..])
        } else {
            (HasherId::from_tag(tag, None)?, rest)
        };
        Some((id, parse_text(rest)?))
    }
}

/// Helpers shared by the native store backends.
#[cfg(all(
    not(target_family = "wasm"),
    any(
        feature = "sqlite",
        feature = "sled",
        feature = "fjall",
        feature = "redb",
        feature = "rocksdb"
    )
))]
pub(crate) mod internal {
    /// Rebuilds raw locator bytes into an OS path.
    ///
    /// Filesystem-backed store locators carry the raw OS path bytes (the
    /// encoding [`std::path::Path::as_os_str`] produces through
    /// `as_encoded_bytes`), so re-opening must rebuild the path
    /// byte-for-byte: routing the bytes through a lossy string would name a
    /// different file and break re-opening.
    ///
    /// On unix and windows the platform provides a byte-level `OsString`
    /// bridge, so the round trip is lossless — non-UTF-8 paths survive. On
    /// other platforms there is no such bridge; there the bytes are decoded
    /// lossily (invalid sequences replaced), and a non-UTF-8 locator cannot
    /// round-trip.
    ///
    /// Used by every native filesystem-backed store: sqlite, sled, fjall,
    /// redb and rocksdb.
    pub(crate) fn os_path_bytes(bytes: &[u8]) -> std::path::PathBuf {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt as _;
            std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec()))
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt as _;
            std::path::PathBuf::from(std::ffi::OsString::from_vec(bytes.to_vec()))
        }
        #[cfg(not(any(unix, windows)))]
        {
            std::path::PathBuf::from(alloc::string::String::from_utf8_lossy(bytes).into_owned())
        }
    }
}
