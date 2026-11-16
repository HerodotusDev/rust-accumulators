//! The MMR: type-stated variants, cached peaks, batched I/O,
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
#![cfg_attr(
    feature = "draft_mmr",
    doc = "- [`async_draft`](crate::mmr::async_draft) — the async draft over\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "  [`AsyncMmr`](crate::mmr::async_mmr::AsyncMmr) (`draft_mmr` feature).\n"
)]
//!
//! # Layout and terminology
//!
//! An MMR of 5 leaves — node indexes above, leaf (element) indexes below.
//! Merges happen only between equal-height right-spine neighbors, so the
//! leaf-to-node mapping has gaps (`2i + 1 − popcount(i)`):
//!
//! ```text
//! height
//!   2 │                 7  ← peak
//!   1 │        3                  6
//!   0 │    1       2       4       5       8  ← peak
//!         │        │       │       │       │
//!         L0       L1      L2      L3      L4
//!
//! peaks = [7, 8]          one peak per set bit of the leaf count
//! bag   = H(peak_7, peak_8)   peaks bagged right-to-left, leftmost outermost
//! root  = H(size, bag)        size = node count (here 8)
//! ```
//!
//! - **node index** — 1-based position in the flat node space (the store-key
//!   space). Every node, internal or leaf, has one.
//! - **leaf index** — 0-based position of an appended element. The space all
//!   *public* proof APIs speak ([`LeafIndex`](crate::primitives::LeafIndex)).
//! - **peak** — root of one perfect subtree; count = `popcount(leaf count)`.
//! - **bagging** — folding the peaks (right-to-left) with the size into the
//!   root ([`bag_peaks`](crate::mmr::bag_peaks) / [`root_from`](crate::mmr::root_from)).
//! - **pin size** — the node count a stacked layer is frozen at: reads
//!   through a pin never exceed it
//!   ([`SubView::pinned_size`](crate::mmr::SubView::pinned_size)).
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

pub mod aliases;
pub mod async_mmr;
mod fanout;
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

#[cfg(feature = "draft_mmr")]
pub mod async_draft;

pub use aliases::{
    AsyncPlainAppendMmr, AsyncPlainEditableMmr, AsyncPlainNullifyingMmr, AsyncWithPeaksAppendMmr,
    AsyncWithPeaksEditableMmr, AsyncWithPeaksNullifyingMmr, PlainAppendMmr, PlainEditableMmr,
    PlainNullifyingMmr, WithPeaksAppendMmr, WithPeaksEditableMmr, WithPeaksNullifyingMmr,
};
#[cfg(feature = "stacked_mmr")]
pub use aliases::{
    AsyncStackedAppendMmr, AsyncStackedNullifyingMmr, StackedAppendMmr, StackedNullifyingMmr,
};
#[cfg(feature = "draft_mmr")]
pub use async_draft::{
    AsyncCommitFailure, AsyncCommitResult, AsyncDraft, AsyncStackedCommitResult,
};
pub use async_mmr::AsyncMmr;
#[cfg(feature = "draft_mmr")]
pub use draft::{CommitFailure, CommitReport, CommitResult, Draft, Optimise, StackedCommitResult};
pub use handle::{
    AppendBatchOutcome, AppendOutcome, Corrupted, Mmr, MmrError, NullifyOutcome, ReplaceOutcome,
    UpdateOutcome,
};
pub use kinds::{DeepNullifiable, EditableKind, Kind, Plain, Stacked, WithPeaks};
pub use layout::{
    Height, InvalidMmrSize, LeafCount, MmrSize, NodeIndex, NodeIndexZero, PathStep, Side,
    bag_peaks, merges_on_append, peak_heights, peaks_of, root_from, sibling_path, size_of,
};
pub use mode::{AppendOnly, Editable, Mode, Nullifying, Stackable};
pub use nullifiers::{AsyncNullifierSet, NullifierError, NullifierRecord, NullifierSet};
pub use proof::encoding::{
    EncodedMultiProof, EncodedProof, EncodingError, FixedWidth, ProofEncoding,
};
pub use proof::{
    ConsistencyProof, MultiProof, Proof, VerifyError, verify_consistency_proof, verify_multi_proof,
    verify_multi_proof_hashed, verify_proof, verify_proof_hashed,
};
pub use stacked::SubView;
#[cfg(feature = "stacked_mmr")]
pub use stacked::{InvalidSubViews, StackingError};
pub use state::{AppendDelta, MmrState, Provenance};
