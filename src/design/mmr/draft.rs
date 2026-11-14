//! Draft MMRs: an in-memory overlay over any MMR, with commit / discard /
//! commit-as-stacked.
//!
//! A draft behaves like a normal MMR that nothing is persisted from yet.
//! Which operations it offers mirrors the base's mutability mode:
//!
//! - every draft: `append` / `append_batch`,
//! - [`Editable`] drafts: additionally `update` / `delete`,
//! - [`Nullifying`] drafts: additionally `nullify_shallow` /
//!   `nullify_deep` / `replace_shallow` / `replace_deep` (deep unavailable on
//!   `WithPeaks` bases — compile-time).
//!
//! Every action is buffered **in order** as an operation log; reads (root,
//! peaks, counts, proofs, multiproofs, verification) compose the log over the
//! base from memory — full read parity with the base handle. Then either
//! [`Draft::commit`] the
//! log into the base (replaying all actions), [`Draft::discard`] it
//! (consuming `self` makes use-after-discard unrepresentable), or — for
//! [`Stackable`] base modes — [`Draft::commit_as_stacked`]
//! apply the log as a new stacked layer on top of the base.
//!
//! Replay has two strategies ([`Optimise`]): the default replays every
//! buffered action exactly as issued; the optimised fold collapses each
//! leaf's sequence to its net effect — an append erased by a later delete
//! appends nothing at all.
//!
//! v0.5 defects this design fixes:
//! - the draft poked the concrete `InMemoryStore` internals during commit —
//!   here the overlay is the crate's own structure and commit is a batched
//!   replay through the store contract,
//! - commit failed halfway with no rollback — atomicity is now the store
//!   contract, and a failed commit returns the draft (and its log) via
//!   [`CommitFailure`] instead of dropping it,
//! - the draft borrowed `&mut` without explaining why — the mutable borrow
//!   is load-bearing: commit updates the base handle's cached state.

use super::AppendBatchOutcome;
use super::AppendOutcome;
use super::kinds::DeepNullifiable;
use super::mode::{Editable, Mode, Nullifying, Stackable};
use super::nullifiers::NullifierDepth;
use super::proof::MultiProof;
use crate::design::hashers::Hasher;
use crate::design::hashers::HasherError;
use crate::design::ids::{MmrId, TreeId};
use crate::design::primitives::{HashValue, LeafCount, LeafIndex, MmrSize};
use crate::design::store::{Storage, Store};
use alloc::vec::Vec;

/// One buffered draft operation, in log order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DraftOp<O: HashValue> {
    /// Append a new leaf (already-hashed element).
    Append(O),
    /// Rewrite a leaf in place.
    Update {
        /// Target leaf.
        leaf: LeafIndex,
        /// New hash for the leaf.
        new: O,
        /// Lost-update gate evaluated at commit time.
        expected_current: Option<O>,
    },
    /// Clear a leaf in place.
    Delete {
        /// Target leaf.
        leaf: LeafIndex,
        /// Lost-update gate evaluated at commit time.
        expected_current: Option<O>,
    },
    /// Record a nullification.
    Nullify {
        /// Target leaf.
        leaf: LeafIndex,
        /// Nullification depth.
        depth: NullifierDepth,
    },
    /// Nullify the old leaf and append a new element as one unit.
    Replace {
        /// Leaf to nullify.
        leaf: LeafIndex,
        /// Hash of the new element to append.
        new: O,
        /// Nullification depth.
        depth: NullifierDepth,
    },
}

/// Replay strategy for [`Draft::commit`].
///
/// Default is [`Optimise::Off`]: apply every buffered action properly.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Optimise {
    /// Replay every buffered operation in order. The base receives each
    /// write individually — leaf counts and node indexes reflect every
    /// intermediate append, even ones later undone by a delete.
    #[default]
    Off,
    /// Fold each leaf's operation sequence to its net effect before
    /// applying:
    ///
    /// - an append erased by a later in-draft `delete` appends nothing,
    /// - update chains collapse to the final value,
    /// - an append **nullified later in the same draft** skips both the
    ///   append and the nullifier record — the leaf never existed in any
    ///   committed state,
    /// - nullifications of *pre-existing* leaves always apply: nullifiers
    ///   are external commitments (on-chain maps) and cannot be unsaid.
    ///
    /// **Lost-update gates survive folding, fail-closed**: a folded op
    /// (update chain, collapsed append+nullify) retains the *earliest*
    /// `expected_current` gate in its chain — if any buffered op in the
    /// chain would have failed its gate at commit time, the folded op
    /// fails too. No flag may silently weaken concurrency protection.
    ///
    /// Produces a *different* final shape than [`Optimise::Off`] (lower leaf
    /// count, shifted node indexes for subsequent appends) — pick this only
    /// when the skipped history is not load-bearing.
    On,
}

/// Summary of what a draft commit applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitReport<O: HashValue> {
    /// Leaves appended to the target.
    pub appended: LeafCount,
    /// In-place edits applied (updates + deletes).
    pub edits: usize,
    /// Nullifier records written.
    pub nullifications: usize,
    /// Final root after the commit.
    pub root: O,
}

/// An in-memory draft over a base MMR.
///
/// Created with [`super::Mmr::start_draft`]; the draft holds the base by
/// mutable borrow so its commit can update the base's cached state.
pub struct Draft<'m, H: Hasher, S, K, M = super::AppendOnly, Id = MmrId> {
    pub(crate) base: &'m mut super::Mmr<H, S, K, M, Id>,
    pub(crate) ops: Vec<DraftOp<H::Output>>,
}

impl<'m, H: Hasher, S: Store, K, M: Mode, Id: TreeId> Draft<'m, H, S, K, M, Id> {
    /// Appends one element to the draft (in memory — no store writes).
    ///
    /// # Errors
    ///
    /// [`HasherError`] for malformed elements.
    pub fn append(&mut self, element: &[u8]) -> Result<AppendOutcome<H::Output>, HasherError> {
        let _ = element;
        todo!()
    }

    /// Appends many elements to the draft in memory.
    ///
    /// Accepts anything iterable of byte-like items — `&[&[u8]]`,
    /// `Vec<Vec<u8>>`, iterators of `Bytes`, etc.
    ///
    /// # Errors
    ///
    /// As [`Self::append`].
    pub fn append_batch<I>(
        &mut self,
        elements: I,
    ) -> Result<AppendBatchOutcome<H::Output>, HasherError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let _ = elements;
        todo!()
    }

    /// Draft root: base state composed with the buffered log, from memory.
    ///
    /// Infallible: composition folds [`Hasher::hash_pair`] calls, which are
    /// infallible by contract.
    #[must_use]
    pub fn root(&self) -> H::Output {
        todo!()
    }

    /// Inclusion proof over the composed (base + draft) view.
    ///
    /// Leaves under the base resolve through the base's stores (nullifier
    /// resolution included); draft leaves resolve through the log. Proofs
    /// are self-contained either way.
    ///
    /// # Errors
    ///
    /// Unprovable leaves ([`super::MmrError::UnprovableLeaf`]), resolving
    /// nullifiers ([`super::MmrError::LeafNullified`]) or hasher failures.
    pub fn proof(
        &self,
        leaf: LeafIndex,
    ) -> Result<super::proof::Proof<H::Output>, super::MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Number of leaves appended in this draft so far (draft-only — excludes
    /// the base; see [`Self::leaf_count`] for the composed view).
    #[must_use]
    pub fn draft_len(&self) -> LeafCount {
        todo!()
    }

    /// Number of leaves in the composed (base + draft) view — no store access.
    #[must_use]
    pub fn leaf_count(&self) -> LeafCount {
        todo!()
    }

    /// Total node count of the composed (base + draft) view.
    #[must_use]
    pub fn size(&self) -> MmrSize {
        todo!()
    }

    /// Current peaks of the composed (base + draft) view, left to right.
    ///
    /// Computed in memory: the base's cached peaks folded through the buffered
    /// log — no store access.
    #[must_use]
    pub fn peaks(&self) -> Vec<H::Output> {
        todo!()
    }

    /// Builds a multiproof for many leaves over the composed (base + draft)
    /// view with a deduplicated sibling pool.
    ///
    /// Accepts any iterable of leaf indexes. Base leaves resolve through the
    /// base's stores (one batched read per distinct store, nullifier
    /// resolution and provenance floor included); draft leaves resolve
    /// through the log.
    ///
    /// # Errors
    ///
    /// As [`Self::proof`].
    pub fn multiproof<I>(&self, leaves: I) -> Result<MultiProof<H::Output>, super::MmrError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let _ = leaves;
        todo!()
    }

    /// Verifies a proof against the draft's *current* root (the composed
    /// base + draft view). For standalone verification — no draft instance,
    /// e.g. in a verifier process — use [`super::proof::verify_proof`], which
    /// checks the proof against its own commitment.
    ///
    /// # Errors
    ///
    /// [`super::MmrError::Verify`] when the proof is structurally inconsistent.
    pub fn verify(
        &self,
        proof: &super::proof::Proof<H::Output>,
        element: &[u8],
    ) -> Result<bool, super::MmrError<S>> {
        let _ = (proof, element);
        todo!()
    }

    /// Verifies a multiproof against the draft's *current* root.
    ///
    /// `elements` must align positionally with the proof's leaves.
    ///
    /// # Errors
    ///
    /// [`super::MmrError::Verify`] when the proof or the element set is
    /// structurally inconsistent.
    pub fn verify_multi<I>(
        &self,
        proof: &MultiProof<H::Output>,
        elements: I,
    ) -> Result<bool, super::MmrError<S>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let _ = (proof, elements);
        todo!()
    }
}

impl<'m, H: Hasher, S: Store, K, Id: TreeId> Draft<'m, H, S, K, Editable, Id> {
    /// Buffers an in-place rewrite of `leaf` (in memory — no store writes).
    ///
    /// `expected_current` is evaluated **at commit time** against the base's
    /// then-current state (lost-update gate between draft start and commit).
    ///
    /// # Errors
    ///
    /// [`HasherError`] for malformed elements.
    pub fn update(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
        expected_current: Option<H::Output>,
    ) -> Result<(), HasherError> {
        let _ = (leaf, element, expected_current);
        todo!()
    }

    /// Buffers an in-place clear of `leaf`. See [`Self::update`].
    ///
    /// # Errors
    ///
    /// [`HasherError`] for malformed elements.
    pub fn delete(
        &mut self,
        leaf: LeafIndex,
        expected_current: Option<H::Output>,
    ) -> Result<(), HasherError> {
        let _ = (leaf, expected_current);
        todo!()
    }
}

impl<'m, H: Hasher, S: Store, K: super::Kind, Id: TreeId> Draft<'m, H, S, K, Nullifying, Id> {
    /// Buffers a **shallow** nullification (in memory — no store writes).
    /// Record semantics match [`super::Mmr::nullify_shallow`]; records
    /// materialize at commit.
    ///
    /// Buffering performs an immediate range check against the composed
    /// (base + draft) leaf count — a log entry that can never commit is
    /// rejected here, not at commit time (`expected_current` gates are
    /// different: they are value-contested and deliberately deferred).
    ///
    /// # Errors
    ///
    /// [`super::MmrError::UnprovableLeaf`] when `leaf` is at or beyond the
    /// composed leaf count.
    pub fn nullify_shallow(&mut self, leaf: LeafIndex) -> Result<(), super::MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Buffers a **shallow** nullification of the old leaf **and** an append
    /// of the new element — the draft's `replace`.
    ///
    /// # Errors
    ///
    /// As [`Self::append`] and [`Self::nullify_shallow`].
    pub fn replace_shallow(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<(), super::MmrError<S>> {
        let _ = (leaf, element);
        todo!()
    }
}

impl<'m, H: Hasher, S: Store, K: DeepNullifiable, Id: TreeId> Draft<'m, H, S, K, Nullifying, Id> {
    /// Buffers a **deep** nullification. Available only on bases that are
    /// [`Plain`](crate::design::mmr::Plain) or [`Stacked`](crate::design::mmr::Stacked) — a
    /// `WithPeaks` draft cannot deep-nullify (compile-time, see
    /// [`DeepNullifiable`]).
    ///
    /// Range-checked at buffer time, like [`Self::nullify_shallow`].
    ///
    /// # Errors
    ///
    /// [`super::MmrError::UnprovableLeaf`] when `leaf` is at or beyond the
    /// composed leaf count.
    pub fn nullify_deep(&mut self, leaf: LeafIndex) -> Result<(), super::MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Buffers a **deep** nullification of the old leaf **and** an append of
    /// the new element. See [`Self::nullify_deep`] for availability.
    ///
    /// # Errors
    ///
    /// As [`Self::append`] and [`Self::nullify_deep`].
    pub fn replace_deep(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<(), super::MmrError<S>> {
        let _ = (leaf, element);
        todo!()
    }
}

impl<'m, H: Hasher, S: Store, K, M: Mode, Id: TreeId> Draft<'m, H, S, K, M, Id> {
    /// Replays the buffered log into the base and updates its cached state.
    ///
    /// Appends and nullifier records land in one batch per target store
    /// (see [`Optimise`] for replay strategies). **Deep** nullifier records
    /// target the owning sub-MMR's store — a separate write, therefore not
    /// atomic together with the rest (known limitation; see the store
    /// atomicity contract).
    ///
    /// Consumes the draft; on failure the log comes back inside
    /// [`CommitFailure::draft`] — the safe action (discard) is never lost to
    /// a failed commit. Note that after a failure the log may be *partially
    /// applied* (deep records cross stores); inspect the error before
    /// retrying, and prefer [`Self::discard`] over a blind re-commit.
    ///
    /// # Errors
    ///
    /// [`CommitFailure`] wrapping store failures, hasher failures, scope
    /// violations at apply time (edits below a `WithPeaks` floor or below a
    /// stack point, [`super::MmrError::UpdateMismatch`] from a lost-update
    /// gate).
    pub fn commit(self, optimise: Optimise) -> CommitResult<'m, H, S, K, M, Id> {
        let _ = optimise;
        todo!()
    }

    /// Throws the draft and its buffered log away.
    ///
    /// Consuming `self` makes use-after-discard unrepresentable.
    pub fn discard(self) {}
}

impl<'m, H: Hasher, S: Store, K, M: Stackable, Id: TreeId> Draft<'m, H, S, K, M, Id> {
    /// Applies the log as a **new stacked layer** on top of the base instead
    /// of replaying it into the base.
    ///
    /// Only exists for [`Stackable`] base modes — a draft on
    /// an [`Editable`] base cannot commit as a stack, because
    /// the new layer would pin an editable MMR (compile-time guarantee).
    /// Appends and nullifications express naturally as a new layer (shallow
    /// records land on the new top, deep records on their owners).
    ///
    /// `hasher` and `store` are taken explicitly because the new layer is a
    /// *separate* accumulator: its store is not the base's, and re-using the
    /// base's hasher handle is not assumed (no hidden `Clone` requirement).
    ///
    /// # Errors
    ///
    /// As [`Self::commit`], plus invalid sub-view construction.
    pub fn commit_as_stacked(
        self,
        hasher: H,
        store: S,
        id: Id,
        optimise: Optimise,
    ) -> StackedCommitResult<'m, H, S, K, M, Id> {
        let _ = (hasher, store, id, optimise);
        todo!()
    }
}

/// Result of a draft [`Draft::commit`]: the report, or the failure carrying
/// the draft (and its buffered log) back.
pub type CommitResult<'m, H, S, K, M, Id> =
    Result<CommitReport<<H as Hasher>::Output>, CommitFailure<'m, H, S, K, M, Id>>;

/// Result of [`Draft::commit_as_stacked`]: the new stacked layer, or the
/// failure carrying the draft (and its buffered log) back.
pub type StackedCommitResult<'m, H, S, K, M, Id> =
    Result<super::Mmr<H, S, super::Stacked, M, Id>, CommitFailure<'m, H, S, K, M, Id>>;

/// A failed [`Draft::commit`] / [`Draft::commit_as_stacked`]: the error plus
/// the draft back, so the buffered log is never silently lost to a failed
/// store write.
///
/// The draft may be *partially applied* when deep nullifier records were in
/// play (they cross stores and are not atomic with the rest) — inspect
/// [`Self::error`] before deciding to retry or [`Draft::discard`].
pub struct CommitFailure<'m, H: Hasher, S: Storage, K, M, Id> {
    /// What went wrong.
    pub error: super::MmrError<S>,
    /// The draft with its (possibly partially applied) log.
    pub draft: Draft<'m, H, S, K, M, Id>,
}

impl<'m, H: Hasher, S: Storage, K, M, Id> CommitFailure<'m, H, S, K, M, Id> {
    /// The error that caused the failure.
    #[must_use]
    pub const fn error(&self) -> &super::MmrError<S> {
        &self.error
    }

    /// Discards the failed draft and returns the error, for `?`-style
    /// propagation when the log is not worth recovering.
    #[must_use]
    pub fn into_error(self) -> super::MmrError<S> {
        self.error
    }
}
