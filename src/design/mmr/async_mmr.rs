//! The async shell over the same pure [`super::state`] core.
//!
//! Mirrors [`super::Mmr`] method-for-method, generic over [`AsyncStore`]
//! instead of [`Store`](crate::design::store::Store). Because all algorithms live in the state core
//! (sync, pure), there is zero duplication between the shells: each method
//! is "fetch state → pure transform → one batch write".
//!
//! Errors are unified with the sync shell: [`MmrError`] is generic over
//! [`Storage`](crate::design::store::Storage), which both
//! [`Store`](crate::design::store::Store) and [`AsyncStore`] require as a
//! supertrait. No wrapper types, no duplicated error enums, and a backend
//! implementing both contracts reports the same error type through either.
//!
//! Send-bounds: the shell's futures are `Send` when `H: Send`, `S:
//! AsyncStore + Send + Sync` and `Id: Send` (the generic params' auto traits
//! propagate into the returned futures). Construct the handle with those
//! bounds to spawn its methods on a multi-thread runtime.
//!
//! Note on runtimes: the trait uses native async-fn-in-trait; no
//! `async-trait` boxing anywhere. `no_std` targets use the sync
//! [`Mmr`](super::Mmr) with a sync store instead.

use super::kinds::{DeepNullifiable, EditableKind};
use super::mode::{Editable, Mode, Nullifying};
use super::proof::{MultiProof, Proof};
use super::state::Provenance;
use super::{
    AppendBatchOutcome, AppendOutcome, Kind, MmrError, NullifyOutcome, ReplaceOutcome,
    UpdateOutcome,
};
use crate::design::hashers::Hasher;
use crate::design::ids::{MmrId, TreeId};
use crate::design::primitives::{LeafCount, LeafIndex, MmrSize};
use crate::design::store::AsyncStore;

/// An async MMR handle. Semantics identical to [`Mmr`](super::Mmr) — see that type for
/// the full method contract, including the mode and id axes.
pub struct AsyncMmr<H: Hasher, S, K = super::Plain, M = super::AppendOnly, Id = MmrId> {
    pub(crate) hasher: H,
    pub(crate) store: S,
    pub(crate) id: Id,
    pub(crate) state: super::state::MmrState<H>,
    pub(crate) _kind: core::marker::PhantomData<fn() -> K>,
    pub(crate) _mode: core::marker::PhantomData<fn() -> M>,
}

impl<H: Hasher, S: AsyncStore, K: Kind, M: Mode, Id: TreeId> AsyncMmr<H, S, K, M, Id> {
    /// The MMR's id.
    #[must_use]
    pub const fn id(&self) -> Id {
        self.id
    }

    /// Number of leaves.
    #[must_use]
    pub const fn leaf_count(&self) -> LeafCount {
        self.state.leaf_count
    }

    /// Total node count ("MMR size").
    #[must_use]
    pub const fn size(&self) -> MmrSize {
        self.state.node_count
    }

    /// Provenance: full history or peaks-only (with the seed size).
    #[must_use]
    pub const fn provenance(&self) -> Provenance {
        self.state.provenance
    }

    /// Current peaks (from cache — no store read).
    #[must_use]
    pub fn peaks(&self) -> &[H::Output] {
        &self.state.peaks
    }

    /// Current root (from cache — no store read, no await).
    ///
    /// Infallible: recomputed purely from the cached peaks via
    /// [`Hasher::hash_pair`].
    #[must_use]
    pub fn root(&self) -> H::Output {
        todo!()
    }

    /// Appends one element. See [`Mmr::append`](super::Mmr::append).
    ///
    /// # Errors
    ///
    /// As [`Mmr::append`](super::Mmr::append).
    pub async fn append(
        &mut self,
        element: &[u8],
    ) -> Result<AppendOutcome<H::Output>, MmrError<S>> {
        let _ = element;
        todo!()
    }

    /// Appends many elements in one batch write. See [`Mmr::append_batch`](super::Mmr::append_batch).
    ///
    /// Accepts anything iterable of byte-like items — `&[&[u8]]`,
    /// `Vec<Vec<u8>>`, iterators of `Bytes`, etc.
    ///
    /// # Errors
    ///
    /// As [`Mmr::append_batch`](super::Mmr::append_batch).
    pub async fn append_batch<I>(
        &mut self,
        elements: I,
    ) -> Result<AppendBatchOutcome<H::Output>, MmrError<S>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let _ = elements;
        todo!()
    }

    /// Builds an inclusion proof. See [`Mmr::proof`](super::Mmr::proof).
    ///
    /// # Errors
    ///
    /// As [`Mmr::proof`](super::Mmr::proof).
    pub async fn proof(&self, leaf: LeafIndex) -> Result<Proof<H::Output>, MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Builds a multiproof. See [`Mmr::multiproof`](super::Mmr::multiproof).
    ///
    /// Accepts any iterable of leaf indexes.
    ///
    /// # Errors
    ///
    /// As [`Mmr::multiproof`](super::Mmr::multiproof).
    pub async fn multiproof<I>(&self, leaves: I) -> Result<MultiProof<H::Output>, MmrError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let _ = leaves;
        todo!()
    }

    /// Verifies a proof against this MMR's *current* root. Synchronous: the
    /// check is pure over the proof and the cached state — no store, no
    /// await. See [`Mmr::verify`](super::Mmr::verify).
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof is structurally inconsistent.
    pub fn verify(&self, proof: &Proof<H::Output>, element: &[u8]) -> Result<bool, MmrError<S>> {
        let _ = (proof, element);
        todo!()
    }

    /// Verifies a multiproof against this MMR's *current* root. Synchronous;
    /// see [`Mmr::verify_multi`](super::Mmr::verify_multi).
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof or the element set is structurally
    /// inconsistent.
    pub fn verify_multi<I>(
        &self,
        proof: &MultiProof<H::Output>,
        elements: I,
    ) -> Result<bool, MmrError<S>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let _ = (proof, elements);
        todo!()
    }

    /// The stored hash of a leaf, if it is occupied and readable. See
    /// [`Mmr::leaf_hash`](super::Mmr::leaf_hash).
    ///
    /// # Errors
    ///
    /// As [`Mmr::leaf_hash`](super::Mmr::leaf_hash).
    pub async fn leaf_hash(&self, leaf: LeafIndex) -> Result<Option<H::Output>, MmrError<S>> {
        let _ = leaf;
        todo!()
    }
}

impl<H: Hasher, S: AsyncStore, M: Mode, Id: TreeId> AsyncMmr<H, S, super::Plain, M, Id> {
    /// Creates a fresh, empty MMR and persists its genesis metadata. See
    /// [`Mmr::create`](super::Mmr::create).
    ///
    /// # Errors
    ///
    /// As [`Mmr::create`](super::Mmr::create).
    pub async fn create(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// Re-opens an existing MMR from the store, validating all persisted
    /// metadata. See [`Mmr::open`](super::Mmr::open).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open`](super::Mmr::open).
    pub async fn open(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// Creates a peaks-only MMR from peaks at a known node count. See
    /// [`Mmr::from_peaks`](super::Mmr::from_peaks).
    ///
    /// # Errors
    ///
    /// As [`Mmr::from_peaks`](super::Mmr::from_peaks).
    pub async fn from_peaks(
        hasher: H,
        store: S,
        id: Id,
        size: MmrSize,
        peaks: &[H::Output],
    ) -> Result<AsyncMmr<H, S, super::WithPeaks, M, Id>, MmrError<S>> {
        let _ = (&hasher, &store, id, size, peaks);
        todo!()
    }
}

impl<H: Hasher, S: AsyncStore, Id: TreeId> AsyncMmr<H, S, super::Plain, Editable, Id> {
    /// [`AsyncMmr::create`](Self::create) with an [`Editable`]
    /// base. See [`Mmr::create_editable`](super::Mmr::create_editable).
    ///
    /// # Errors
    ///
    /// As [`Mmr::create_editable`](super::Mmr::create_editable).
    pub async fn create_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// [`AsyncMmr::open`](Self::open) declaring an [`Editable`]
    /// base. See [`Mmr::open_editable`](super::Mmr::open_editable).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open_editable`](super::Mmr::open_editable).
    pub async fn open_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }
}

impl<H: Hasher, S: AsyncStore, Id: TreeId> AsyncMmr<H, S, super::Plain, Nullifying, Id> {
    /// [`AsyncMmr::create`](Self::create) with a [`Nullifying`]
    /// base. See [`Mmr::create_nullifying`](super::Mmr::create_nullifying).
    ///
    /// # Errors
    ///
    /// As [`Mmr::create_nullifying`](super::Mmr::create_nullifying).
    pub async fn create_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// [`AsyncMmr::open`](Self::open) declaring a [`Nullifying`]
    /// base. See [`Mmr::open_nullifying`](super::Mmr::open_nullifying).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open_nullifying`](super::Mmr::open_nullifying).
    pub async fn open_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }
}

impl<H: Hasher, S: AsyncStore, K: EditableKind> AsyncMmr<H, S, K, Editable> {
    /// Rewrites a leaf in place. See [`Mmr::update`](super::Mmr::update).
    ///
    /// # Errors
    ///
    /// As [`Mmr::update`](super::Mmr::update).
    pub async fn update(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
        expected_current: Option<H::Output>,
    ) -> Result<UpdateOutcome<H::Output>, MmrError<S>> {
        let _ = (leaf, element, expected_current);
        todo!()
    }

    /// Clears a leaf in place. See [`Mmr::delete`](super::Mmr::delete).
    ///
    /// # Errors
    ///
    /// As [`Mmr::delete`](super::Mmr::delete).
    pub async fn delete(
        &mut self,
        leaf: LeafIndex,
        expected_current: Option<H::Output>,
    ) -> Result<UpdateOutcome<H::Output>, MmrError<S>> {
        let _ = (leaf, expected_current);
        todo!()
    }
}

impl<H: Hasher, S: AsyncStore, K: Kind, Id: TreeId> AsyncMmr<H, S, K, Nullifying, Id> {
    /// Marks a leaf as no longer valid with a **shallow** record. See
    /// [`Mmr::nullify_shallow`](super::Mmr::nullify_shallow).
    ///
    /// # Errors
    ///
    /// As [`Mmr::nullify_shallow`](super::Mmr::nullify_shallow).
    pub async fn nullify_shallow(
        &mut self,
        leaf: LeafIndex,
    ) -> Result<NullifyOutcome, MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Shallow nullification of the old leaf and append of the new element.
    /// See [`Mmr::replace_shallow`](super::Mmr::replace_shallow).
    ///
    /// # Errors
    ///
    /// As [`Mmr::replace_shallow`](super::Mmr::replace_shallow).
    pub async fn replace_shallow(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let _ = (leaf, element);
        todo!()
    }
}

impl<H: Hasher, S: AsyncStore, K: DeepNullifiable, Id: TreeId> AsyncMmr<H, S, K, Nullifying, Id> {
    /// Marks a leaf as no longer valid with a **deep** record. Available for
    /// [`Plain`](crate::design::mmr::Plain) and [`Stacked`](crate::design::mmr::Stacked) only — see
    /// [`Mmr::nullify_deep`](super::Mmr::nullify_deep).
    ///
    /// # Errors
    ///
    /// As [`Mmr::nullify_deep`](super::Mmr::nullify_deep).
    pub async fn nullify_deep(&mut self, leaf: LeafIndex) -> Result<NullifyOutcome, MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Deep nullification of the old leaf and append of the new element. See
    /// [`Mmr::replace_deep`](super::Mmr::replace_deep).
    ///
    /// # Errors
    ///
    /// As [`Mmr::replace_deep`](super::Mmr::replace_deep).
    pub async fn replace_deep(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let _ = (leaf, element);
        todo!()
    }
}
