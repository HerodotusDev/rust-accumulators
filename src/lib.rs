//! Cryptographic accumulators with pluggable storage and hashing.
//!
//! **MMRs first**: plain, stacked (branched), draft, and peaks-only variants
//! with first-class self-contained proofs and multiproofs — plus an
//! incremental Merkle tree. Designed so misuse is a *compile error*: kinds
//! and mutability modes are type-state parameters of the MMR handle, and
//! operations that do not exist for a configuration do not exist on the type.
#![cfg_attr(
    feature = "mmr",
    doc = "[`Plain`](mmr::Plain) / [`WithPeaks`](mmr::WithPeaks) /\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "[`Stacked`](mmr::Stacked) kinds and [`AppendOnly`](mmr::AppendOnly) /\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "[`Editable`](mmr::Editable) / [`Nullifying`](mmr::Nullifying) modes are\n"
)]
#![cfg_attr(feature = "mmr", doc = "parameters of [`Mmr`](mmr::Mmr).\n")]
//!
//! # Shape of the crate
//!
//! - [`primitives`] — [`Hash`](primitives::Hash), the
//!   [`HashValue`](primitives::HashValue) trait, the shared 0-based
//!   [`LeafIndex`](primitives::LeafIndex), and the leaf-space bound.
//! - [`hashers`] — the [`Hasher`](hashers::Hasher) trait (infallible pair
//!   hashing, fallible leaf ingestion, persisted config) and built-ins:
//!   `KeccakSolHasher` (Solidity keccak packing), `PoseidonStarkHasher`,
//!   `PedersenStarkHasher`, and the Cairo-flavored `Blake2sStarkHasher`.
//!   Custom hashers are one trait impl away.
//! - [`ids`] — [`AccumulatorId`](ids::AccumulatorId) (uuid v4/v7, ULID, custom bytes) and the
//!   [`TreeId`](ids::TreeId) extension point.
#![cfg_attr(
    feature = "store",
    doc = "- [`store`] — the minimal atomic-batch [`Store`](store::Store) /\n"
)]
#![cfg_attr(
    feature = "store",
    doc = "  [`AsyncStore`](store::AsyncStore) contract, binary key layout,\n"
)]
#![cfg_attr(
    feature = "store",
    doc = "  [`Retrievable`](store::Retrievable) stores and opt-in erasure adapters\n"
)]
#![cfg_attr(feature = "store", doc = "  ([`ErasedStore`](store::ErasedStore) /\n")]
#![cfg_attr(
    feature = "store",
    doc = "  [`ErasedAsyncStore`](store::ErasedAsyncStore)).\n"
)]
#![cfg_attr(
    all(
        feature = "store",
        any(
            feature = "memory",
            feature = "sqlite",
            feature = "sled",
            feature = "fjall",
            feature = "redb",
            feature = "rocksdb",
            feature = "heapless"
        )
    ),
    doc = "  Built-in backends: `memory` (std), `sqlite` (native, async),\n"
)]
#![cfg_attr(
    all(
        feature = "store",
        any(
            feature = "sled",
            feature = "fjall",
            feature = "redb",
            feature = "rocksdb"
        )
    ),
    doc = "  `sled`, `fjall`, `redb`, and `rocksdb` (native),\n"
)]
#![cfg_attr(
    all(feature = "store", feature = "heapless"),
    doc = "  `heapless` (`no_std`, fixed-capacity, allocation-free map) —\n"
)]
#![cfg_attr(
    all(
        feature = "store",
        not(any(
            feature = "memory",
            feature = "sqlite",
            feature = "sled",
            feature = "fjall",
            feature = "redb",
            feature = "rocksdb",
            feature = "heapless"
        ))
    ),
    doc = "  Built-in backends are opt-in via the `memory` and `sqlite` features;\n"
)]
#![cfg_attr(
    feature = "store",
    doc = "  or users plug in redis, … by implementing two methods.\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "- [`mmr`] — the accumulator: sync [`Mmr`](mmr::Mmr) and\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "  [`AsyncMmr`](mmr::AsyncMmr) shells over one pure state core, the\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "  [`layout`](mmr::layout) node-index vocabulary, self-contained\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "  [`Proof`](mmr::Proof)s / deduplicated [`MultiProof`](mmr::MultiProof)s\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "  with standalone verification, pinned sub-views and stacking, and\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "  shallow/deep nullification via [`NullifierSet`](mmr::NullifierSet).\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "  Kind × mode shorthands live as type aliases — [`PlainAppendMmr`](mmr::PlainAppendMmr)\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "  and friends spell the full handle generics once per valid combination.\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "  [`Draft`](mmr::Draft) overlays add in-memory commit / discard /\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "  commit-as-stacked on top of any MMR.\n"
)]
#![cfg_attr(
    feature = "merkle_tree",
    doc = "- [`merkle`] — the incremental Merkle tree: sparse storage, zero-hash\n"
)]
#![cfg_attr(
    feature = "merkle_tree",
    doc = "  ladder (proofs for every index within capacity), persisted metadata.\n"
)]
#![cfg_attr(
    feature = "serde",
    doc = "- [`serde_impls`] — serde support: hex-string hashes and ids, hex-hash\n"
)]
#![cfg_attr(
    feature = "serde",
    doc = "  proofs and multiproofs, and the [`HexHash`](serde_impls::HexHash)\n"
)]
#![cfg_attr(
    feature = "serde",
    doc = "  adapter for foreign hash outputs (e.g. felts).\n"
)]
//!
//! - **`Hash` is `[u8; 32]` behind a newtype** (field hashers use
//!   `starknet_crypto::Felt`): bytes end-to-end, `Copy` semantics, no hex
//!   parse/format per operation.
//! - **Hashing is pairs-only**: [`Hasher::hash_pair`](hashers::Hasher::hash_pair)
//!   is infallible, so
//!   everything downstream of it (bagging, roots, appends) is infallible too.
//!   `Result` exists only where untrusted input arrives
//!   ([`Hasher::hash_leaf`](hashers::Hasher::hash_leaf)).
//! - **Cache in handles, batch at the edges**: peaks are cached, an append is
//!   one atomic batch write, a batch of appends is one write total, a proof
//!   is one batched read.
//! - **Proofs are self-contained** (own peaks + root + size): standalone
//!   verification with no store; a fabricated proof can at worst verify to
//!   `false` — never panic, never falsely pass.
//! - **Sync core, async shell**: all algorithms live in pure functions over
//!   cached state; the sync and async MMR shells differ only in how they
//!   fetch and commit, sharing one generic error enum.
//! - **Store writes are atomic by contract** — partial application would
//!   corrupt accumulators, so it is a hard requirement on every backend.
#![cfg_attr(
    feature = "store",
    doc = "  See [`Store::write`](store::Store::write).\n"
)]
//! # Quick start
//!
//! The default features (`mmr`, `memory`, `keccak_sol`, `uuid_v4`) are a working
//! out-of-the-box MMR:
//!
//! ```
//! use accumulators::hashers::KeccakSolHasher;
//! use accumulators::ids::AccumulatorId;
//! use accumulators::mmr::Mmr;
//! use accumulators::primitives::LeafIndex;
//! use accumulators::store::memory::InMemoryStore;
//!
//! let mut mmr: Mmr<KeccakSolHasher, _> = Mmr::create(
//!     KeccakSolHasher,
//!     InMemoryStore::new(),
//!     AccumulatorId::random_v4(),
//! )
//! .unwrap();
//!
//! mmr.append(b"element 0").unwrap();
//! mmr.append(b"element 1").unwrap();
//!
//! let proof = mmr.proof(LeafIndex::new(0)).unwrap();
//! assert!(mmr.verify(&proof, b"element 0").unwrap());
//! assert!(!mmr.verify(&proof, b"forged").unwrap());
//! ```
//!
//! # Platform support
//!
//! The core is `no_std` + `alloc`. The async surfaces (`AsyncMmr`, the
//! SQLite store), the std-backed memory store, and the allocator-free
//! `heapless` store are opt-in via features (`sqlite`, `memory`,
//! `heapless`); everything builds for `wasm32-unknown-unknown`.
//!
//! Allocation contract: the crate requires `alloc` and allocates where data
//! is unbounded — proof and multiproof construction and verification build
//! sibling paths and deduplicated pools on the heap. The opt-in `heapless`
//! store is the exception at the storage layer: its fixed-capacity map
//! never allocates (see the `heapless` store feature).
//!
//! # Feature flags
//!
//! Accumulators: `mmr`, `stacked_mmr`, `draft_mmr`, `merkle_tree`,
//! `incremental_merkle_tree`. Hashers: `keccak_sol`, `poseidon_stark`, `pedersen_stark`,
//! `blake2s_stark`. Stores: `memory`, `heapless`, `sqlite`, `sled`, `fjall`,
//! `redb`, `rocksdb`. Ids: `uuid_v4`, `uuid_v7`, `ulid`
//! (the time-based constructors additionally need `std`). Serialization:
//! `serde` (hex-string hashes, ids, proofs, multiproofs, and nullifier
//! records). Platform:
//! `std` (implied by the std-backed stores). Default is
//! `["mmr", "memory", "keccak_sol", "uuid_v4"]` — a working out-of-the-box
//! MMR with an in-memory store; `all` enables everything,
//! `--no-default-features` stays the embedded story.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(any(feature = "memory", feature = "sqlite", feature = "std"))]
extern crate std;

extern crate alloc;

/// Hashing abstractions: the [`hashers::Hasher`] trait and built-in hashers.
pub mod hashers;

/// Accumulator identifiers and the [`ids::TreeId`] extension point.
pub mod ids;

/// The incremental Merkle tree.
#[cfg(feature = "merkle_tree")]
pub mod merkle;

/// The Merkle Mountain Range accumulator family.
#[cfg(feature = "mmr")]
pub mod mmr;

/// Zero-cost primitive types shared by every accumulator family.
pub mod primitives;

/// Serde implementations: hex-string hashes and ids, plain-number indexes.
#[cfg(feature = "serde")]
pub mod serde_impls;

/// Storage abstraction: stores, batches, keys, erasure.
#[cfg(feature = "store")]
pub mod store;
