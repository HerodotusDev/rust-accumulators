//! Storage abstraction: a minimal, batch-first, byte-oriented key-value
//! contract.
//!
//! The v0.5 `Store` trait is `String → String` with seven methods, plus a
//! parallel layer of `InStoreTable` / `InStoreCounter` handles and fn-pointer
//! routing hooks for stacked MMRs. The redesign collapses all of that into
//! two methods over bytes:
//!
//! - [`Store::read`] — batched point reads, positional results,
//! - [`Store::write`] — an **atomic** [`Batch`] of puts and deletes.
//!
//! Everything else (namespacing, counters, typed node tables) lives with the
//! accumulator, not the store. This is the smallest surface a new backend
//! (rocksdb, redb, fjall, postgres, redis, …) needs to implement, and it maps
//! 1:1 onto each backend's native batch API.
//!
//! # Contracts a store implementation must honor
//!
//! 1. `read` returns results **positionally aligned** with the requested
//!    keys; missing keys are `None`, never errors. (The v0.5 contract —
//!    "omit missing keys from the map" — was undocumented and only
//!    inferable from call sites; here it's in the type.)
//! 2. `write` applies all operations atomically: observers see either the
//!    full batch or none of it. **This is a hard requirement, not an
//!    optimization** — see "Atomicity (required)" below.
//! 3. Keys and values are opaque bytes to the store; the crate's binary key
//!    layout (see [`keys`]) is private to the accumulators.
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

use alloc::borrow::Cow;
use alloc::vec::Vec;

/// The error axis of a storage backend, shared by the sync and async
/// contracts.
///
/// Every accumulator error type is generic over `Storage` — not over a
/// concrete store trait — so the sync and async shells share one error enum
/// (e.g. [`crate::design::mmr::MmrError`] names the backend error through
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
/// plug into [`crate::design::mmr::AsyncMmr`].
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
}

/// An atomic unit of storage mutations.
///
/// Constructed by pushing operations, then handed to [`Store::write`].
/// Borrowed keys and values where possible so hot paths can write from
/// stack buffers without cloning; `Cow` slots accept runtime-built keys and
/// values (the crate's own key encoder returns `Vec<u8>`) without a second
/// operation variant per ownership shape.
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

    /// Adds a put with a runtime-built key.
    pub fn put_key_owned(&mut self, key: Vec<u8>, value: &'a [u8]) {
        self.ops.push(Op::Put {
            key: Cow::Owned(key),
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

    /// Adds a delete of a borrowed key.
    pub fn delete(&mut self, key: &'a [u8]) {
        self.ops.push(Op::Delete {
            key: Cow::Borrowed(key),
        });
    }

    /// Adds a delete with a runtime-built key.
    pub fn delete_owned(&mut self, key: Vec<u8>) {
        self.ops.push(Op::Delete {
            key: Cow::Owned(key),
        });
    }

    /// Whether the batch would do nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ops.is_empty()
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
/// Produced by [`Retrievable::locator`]; its bytes are opaque to the crate.
/// Locators must be **canonical**: two locators are equal if and only if
/// they name the same underlying store — this equality *is* store identity,
/// which the stacked-MMR routing uses to coalesce cross-layer batches.
///
/// # Trust model
///
/// Locators must come from [`Retrievable::locator`] — a hand-built locator
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

/// A store that can be re-opened from its persisted locator.
///
/// **Required for stores used as stacked-MMR layers**: opening a stacked MMR
/// reconstructs every layer's store from the persisted sub-view metadata,
/// which only contains locators. Memory stores participate by exposing a
/// caller-chosen id as their locator (session-scoped stacks).
///
/// Locator equality doubles as store identity: the stacked-MMR router
/// resolves identities **once at construction** into a batch plan, then
/// makes exactly one batched call per distinct store per operation —
/// merging same-store groups is therefore strictly no slower than one call
/// per group (see the `stacked` module's batching section).
pub trait Retrievable: Store + Sized {
    /// The canonical locator of this store instance.
    fn locator(&self) -> StoreLocator;

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
}

/// A type-erased store — the opt-in cost of mixed-type stacks.
///
/// All layers of a stacked MMR share one store *type* `S`. To stack layers
/// backed by different store types (e.g. sqlite history + memory hot layer),
/// wrap **every** layer — top included — in `ErasedStore` and build the
/// stack over `S = ErasedStore`:
///
/// ```ignore
/// let subs = vec![sqlite_mmr.pin().erased(), memory_mmr.pin().erased()];
/// Mmr::stack(hasher, ErasedStore::new(memory_store), id, subs)
/// ```
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
/// - **hash value** — the canonical [`HashValue`](crate::design::primitives::HashValue)
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
/// | `TreeNode`   | hash value; subkey is the **1-based heap index** (root `1`, leaf `i` at `2^depth + i`)            |
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
    use crate::design::ids::TreeId;
    use alloc::vec::Vec;

    /// Which namespace a key belongs to. Tag byte in the key layout.
    ///
    /// Renaming these variants does not change persisted data; **reordering
    /// or renumbering does** — treat the discriminants as a wire format.
    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    #[repr(u8)]
    pub enum Table {
        /// Node hashes: subkey is the [`u64`] node index.
        Nodes = 0,
        /// Leaf counter: subkey `0`, value is a `u64` BE.
        LeafCount = 1,
        /// Node counter (MMR size): subkey `0`, value is a `u64` BE.
        NodeCount = 2,
        /// Cached root hash: subkey `0`, value is 32 bytes.
        Root = 3,
        /// Hasher identity + config, persisted at creation: subkey `0`.
        HasherInfo = 4,
        /// Mutability mode, persisted at creation: subkey `0`, value is the
        /// [`crate::design::mmr::Mode::NAME`] string.
        Mode = 5,
        /// Nullifier records
        /// ([`Nullifying`](crate::design::mmr::Nullifying) mode): subkey is
        /// the leaf index, value is the size at nullification (`u64` BE).
        Nullifiers = 6,
        /// Merkle-tree node hashes: subkey is the 1-based heap index, value
        /// is the canonical [`HashValue`](crate::design::primitives::HashValue)
        /// encoding (see the module-level format spec).
        TreeNode = 8,
        /// Stacked-MMR sub-view metadata: subkey `0`; value is the encoded
        /// per-layer record list (see the module-level format spec).
        Subviews = 7,
    }

    /// Encodes a full key.
    #[must_use]
    pub fn encode<Id: TreeId>(id: &Id, table: Table, subkey: u64) -> Vec<u8> {
        let _ = (id, table, subkey);
        todo!()
    }

    /// Decodes a key into its raw parts — the id's bytes (in encoding order),
    /// the table, and the subkey — or `None` if the key was not produced by
    /// [`encode`] (a foreign key in the store: skipped, never a parse error).
    /// Typed id reconstruction is the caller's job via its own [`TreeId`].
    #[must_use]
    pub fn decode(key: &[u8]) -> Option<(Vec<u8>, Table, u64)> {
        let _ = key;
        todo!()
    }
}
