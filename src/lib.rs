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
//!   Keccak256 (the `SolKeccak` alias), Poseidon, Pedersen,
//!   and the Cairo-flavored Blake2s. Custom hashers are one trait impl away.
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
    doc = "  [`Retrievable`](store::Retrievable) stores and opt-in erasure adapters.\n"
)]
#![cfg_attr(
    all(feature = "store", any(feature = "memory", feature = "sqlite")),
    doc = "  Built-in backends: `memory` (std) and `sqlite` (native async);\n"
)]
#![cfg_attr(
    all(feature = "store", not(any(feature = "memory", feature = "sqlite"))),
    doc = "  Built-in backends are opt-in via the `memory` and `sqlite` features;\n"
)]
#![cfg_attr(
    all(feature = "store", any(feature = "memory", feature = "sqlite")),
    doc = "  users plug in rocksdb, redb, fjall, postgres,\n"
)]
#![cfg_attr(
    all(feature = "store", not(any(feature = "memory", feature = "sqlite"))),
    doc = "  and users plug in rocksdb, redb, fjall, postgres,\n"
)]
#![cfg_attr(feature = "store", doc = "  redis, … by implementing two methods.\n")]
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
    doc = "  with standalone verification, pinned sub-views and stacking, in-memory\n"
)]
#![cfg_attr(
    feature = "mmr",
    doc = "  drafts with commit/discard/commit-as-stacked, and shallow/deep\n"
)]
#![cfg_attr(feature = "mmr", doc = "  nullification.\n")]
#![cfg_attr(
    feature = "merkle_tree",
    doc = "- [`merkle`] — the incremental Merkle tree: sparse storage, zero-hash\n"
)]
#![cfg_attr(
    feature = "merkle_tree",
    doc = "  ladder (proofs for every index within capacity), persisted metadata.\n"
)]
//!
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
//!
//! # Platform support
//!
//! The core is `no_std` + `alloc`. The async surfaces (`AsyncMmr`, the
//! SQLite store) and the std-backed memory store are opt-in via features
//! (`sqlite`, `memory`); everything builds for `wasm32-unknown-unknown`.
//!
//! # Feature flags
//!
//! Accumulators: `mmr`, `stacked_mmr`, `draft_mmr`, `merkle_tree`,
//! `incremental_merkle_tree`. Hashers: `keccak`, `poseidon`, `pedersen`,
//! `blake`. Stores: `memory`, `sqlite`. Ids: `uuid_v4`, `uuid_v7`, `ulid`
//! (the time-based constructors additionally need `std`). Platform:
//! `std` (implied by the std-backed stores). Default is
//! `["store", "hasher"]`; `all` enables everything.

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

/// Storage abstraction: stores, batches, keys, erasure.
#[cfg(feature = "store")]
pub mod store;
