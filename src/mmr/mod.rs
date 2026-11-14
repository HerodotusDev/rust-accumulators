//! The redesigned MMR: type-stated variants, cached peaks, batched I/O,
//! self-contained proofs.
//!
//! Entry points:
//! - [`Mmr`](crate::mmr::handle::Mmr) — sync handle (works everywhere, including `no_std`),
//! - [`AsyncMmr`](crate::mmr::async_mmr::AsyncMmr) — async handle over [`AsyncStore`](crate::store::AsyncStore),
//! - [`state`](crate::mmr::state) — the pure algorithmic core both shells share,
//! - [`layout`](crate::mmr::layout) — the node-index vocabulary and pure layout math,
//! - [`proof`](crate::mmr::proof) — [`Proof`](crate::mmr::proof::Proof) / [`MultiProof`](crate::mmr::proof::MultiProof) and standalone verification,
#![cfg_attr(
    feature = "stacked_mmr",
    doc = "- [`stacked`](crate::mmr::stacked) — pinned sub-views and stacking construction (`stacked_mmr` feature).\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "- [`draft`](crate::mmr::draft) — the in-memory draft overlay (`draft_mmr` feature).\n"
)]
//!
//! # The four MMR states
//!
//! - **Plain** — built from scratch, full history provable.
//! - **Stacked** — built on top of pinned views of other MMRs; sub-MMRs keep
//!   growing independently, the stack only reads them up to the pin size.
//!   Unlimited depth and breadth; sub-MMRs may live in different stores; one
//!   hasher across all layers.
//! - **Draft** — in-memory overlay on top of any MMR: append, prove, inspect;
//!   then `commit`, `discard`, or `commit_as_stacked`.
//! - **Peaks-only** — created from peaks; root identical to the full MMR, but
//!   only leaves appended on top are provable. Encoded as the
//!   [`WithPeaks`](crate::mmr::kinds::WithPeaks) type-state so the restriction is visible in the type.
//!
//! # Mutability modes (the second type-state axis)
//!
//! `Mmr<H, S, K, M>` — mode `M` says what may happen to leaves after they
//! exist, and is persisted in metadata + validated on `open`:
//!
//! - [`AppendOnly`](crate::mmr::mode::AppendOnly) (default) — no `update`/`delete` exists on the type;
//!   mutating history is a compile error.
//! - [`Editable`](crate::mmr::mode::Editable) — in-place `update`/`delete` with recomputed paths.
//!   **Base-use only**: available for `Plain` (all leaves) and `WithPeaks`
//!   (only above the seed); an editable MMR cannot be pinned or stacked
//!   upon, and the `Stacked` kind cannot be editable — all compile-time
//!   ([`Stackable`](crate::mmr::mode::Stackable)). Stacked accumulators mutate only through nullifiers.
//! - [`Nullifying`](crate::mmr::mode::Nullifying) — data stays append-only forever; `nullify` records
//!   `(mmr id, leaf id) → size at nullification` in a plain table (the same
//!   shape as the on-chain map — no SMT, no cryptographic commitment),
//!   `replace` = nullify + append. Works for all kinds; proofs refuse leaves
//!   with a *resolving* nullifier. Two depths:
//!   - **Shallow** — record holds the size; through a stack, sub-MMR records
//!     count only when their size ≤ the stack point (later history is
//!     invisible through the pin). Available for every kind, any index below
//!     the leaf count (including below a `WithPeaks` floor).
//!   - **Deep** — record holds `0` ("always applies"); every stacked MMR on
//!     top is influenced regardless of when the nullification happened.
//!     Available for Plain and Stacked only — `WithPeaks` cannot
//!     deep-nullify (compile-time, [`DeepNullifiable`](crate::mmr::kinds::DeepNullifiable)).
//!   Shallow records live in the topmost MMR's store; deep records in the
//!   store of the layer that holds the value.

pub mod async_mmr;
pub mod handle;
pub mod kinds;
pub mod layout;
pub mod mode;
pub mod nullifiers;
pub mod proof;
pub mod stacked;
pub mod state;

#[cfg(feature = "draft_mmr")]
pub mod draft;

pub use async_mmr::AsyncMmr;
#[cfg(feature = "draft_mmr")]
pub use draft::{CommitFailure, CommitReport, CommitResult, Draft, Optimise, StackedCommitResult};
pub use handle::{
    AppendBatchOutcome, AppendOutcome, Corrupted, Mmr, MmrError, NullifyOutcome, ReplaceOutcome,
    UpdateOutcome,
};
pub use kinds::{DeepNullifiable, EditableKind, Kind, Plain, Stacked, WithPeaks};
pub use layout::{
    Height, LeafCount, MmrSize, NodeIndex, PathStep, Side, bag_peaks, merges_on_append,
    peak_heights, peaks_of, root_from, sibling_path, size_of,
};
pub use mode::{AppendOnly, Editable, Mode, Nullifying, Stackable};
pub use nullifiers::{NullifierError, NullifierRecord, NullifierSet};
pub use proof::encoding::{
    EncodedMultiProof, EncodedProof, EncodingError, FixedWidth, ProofEncoding,
};
pub use proof::{MultiProof, Proof, VerifyError};
pub use stacked::SubView;
#[cfg(feature = "stacked_mmr")]
pub use stacked::{InvalidSubViews, StackingError};
pub use state::{AppendDelta, MmrState, Provenance};
