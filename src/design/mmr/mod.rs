//! The redesigned MMR: type-stated variants, cached peaks, batched I/O,
//! self-contained proofs.
//!
//! Entry points:
//! - [`Mmr`] — sync handle (works everywhere, including `no_std`),
//! - [`AsyncMmr`] — async handle over [`AsyncStore`](crate::design::store::AsyncStore),
//! - [`state`] — the pure algorithmic core both shells share,
//! - [`proof`] — `Proof` / `MultiProof` and standalone verification,
//! - [`stacked`] — pinned sub-views and stacking construction,
//! - [`draft`] — the in-memory draft overlay.

pub mod async_mmr;
pub mod draft;
pub mod handle;
pub mod kinds;
pub mod mode;
pub mod nullifiers;
pub mod proof;
pub mod stacked;
pub mod state;

pub use async_mmr::AsyncMmr;
pub use draft::{CommitFailure, CommitReport, CommitResult, Draft, Optimise, StackedCommitResult};
pub use handle::{
    AppendBatchOutcome, AppendOutcome, Corrupted, Mmr, MmrError, NullifyOutcome, ReplaceOutcome,
    UpdateOutcome,
};
pub use kinds::{DeepNullifiable, EditableKind, Kind, Plain, Stacked, WithPeaks};
pub use mode::{AppendOnly, Editable, Mode, Nullifying, Stackable};
pub use nullifiers::{NullifierError, NullifierRecord, NullifierSet};
pub use proof::encoding::{
    EncodedMultiProof, EncodedProof, EncodingError, FixedWidth, ProofEncoding,
};
pub use proof::{MultiProof, Proof, VerifyError};
pub use stacked::{StackingError, SubView, SubViewsError};
pub use state::{AppendDelta, MmrState, Provenance};
