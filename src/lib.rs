//! Cryptographic accumulators with pluggable storage and hashing.
//!
//! The crate provides two accumulator types:
//!
//! - `mmr` — a Merkle Mountain Range (MMR) for append-only accumulation of
//!   elements, with inclusion proofs over any range of elements
//! - `merkle_tree` — an incremental Merkle tree whose leaves can be updated
//!   in place
//!
//! Accumulator nodes are persisted through a `store` — an in-memory store or
//! an SQLite-backed store — and combined with a `hasher`: Keccak256,
//! Poseidon, Pedersen, or the Cairo variant of Blake2s.
//!
//! Everything is feature-gated. Enable `all`, or pick individual
//! accumulators (`mmr`, `stacked_mmr`, `draft_mmr`, `merkle_tree`,
//! `incremental_merkle_tree`), hashers (`keccak`, `poseidon`, `pedersen`,
//! `blake`) and stores (`memory`, `sqlite`). See the
//! [README](https://github.com/HerodotusDev/rust-accumulators) for details.

#[cfg(feature = "hasher")]
pub mod hasher;
#[cfg(feature = "merkle_tree")]
pub mod merkle_tree;
#[cfg(feature = "mmr")]
pub mod mmr;
#[cfg(feature = "store")]
pub mod store;
