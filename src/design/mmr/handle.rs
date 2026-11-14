//! The type-stated MMR handle — the sync shell over the pure [`state`](super::state) core.
//!
//! One struct, three type-state axes: the kind ([`Plain`](crate::design::mmr::Plain),
//! [`WithPeaks`](crate::design::mmr::WithPeaks), [`Stacked`](crate::design::mmr::Stacked)), the
//! mutability mode ([`AppendOnly`](crate::design::mmr::AppendOnly), [`Editable`],
//! [`Nullifying`]), and the id type ([`TreeId`], defaulting
//! to [`MmrId`]). Variant-specific methods are gated by the parameters:
//! `update`/`delete` exist only on [`Editable`], `nullify`/
//! `replace` only on [`Nullifying`] — calling them on an
//! append-only MMR is a compile error. All methods are sync and non-async by
//! design: state is cached, appends are a single batch write, proofs are a
//! single batch read. For async backends see [`AsyncMmr`](super::AsyncMmr) — same methods,
//! async shell, identical semantics.

use super::Kind;
use super::kinds::{DeepNullifiable, EditableKind};
use super::mode::{Editable, Mode, Nullifying, Stackable};
use super::nullifiers::{NullifierError, NullifierRecord, NullifierSet};
use super::proof::{MultiProof, Proof, VerifyError};
use super::state::{MmrState, Provenance};
use crate::design::hashers::{Hasher, HasherError};
use crate::design::ids::{MmrId, TreeId};
use crate::design::primitives::{HashValue, LeafCount, LeafIndex, MmrSize, NodeIndex};
use crate::design::store::{Storage, Store, keys, keys::Table};
use alloc::vec::Vec;

/// A loaded, ready-to-use MMR handle (sync store).
///
/// `K` selects the kind ([`super::Plain`], [`super::WithPeaks`], or
/// [`super::Stacked`]); `M` the mutability mode ([`super::AppendOnly`] by
/// default); `Id` the id type ([`MmrId`] by default). The common case reads
/// clean: `Mmr<PoseidonHasher, MyStore>`.
pub struct Mmr<H: Hasher, S, K = super::Plain, M = super::AppendOnly, Id = MmrId> {
    pub(crate) hasher: H,
    pub(crate) store: S,
    pub(crate) id: Id,
    pub(crate) state: MmrState<H>,
    pub(crate) _kind: core::marker::PhantomData<fn() -> K>,
    pub(crate) _mode: core::marker::PhantomData<fn() -> M>,
}

/// Outcome of an append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendOutcome<O: HashValue> {
    /// Leaf index assigned to the appended element.
    pub leaf: LeafIndex,
    /// Node index that now holds the element's hash.
    pub node: NodeIndex,
    /// New root after the append (from cache — no store read).
    pub root: O,
}

/// Outcome of a batch append.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AppendBatchOutcome<O: HashValue> {
    /// First leaf assigned in the batch.
    pub first_leaf: LeafIndex,
    /// Number of leaves appended.
    pub appended: LeafCount,
    /// New root after the batch (from cache).
    pub root: O,
}

/// Outcome of an in-place edit ([`Editable`] mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpdateOutcome<O: HashValue> {
    /// The edited leaf.
    pub leaf: LeafIndex,
    /// Previous hash at this leaf, if it was occupied.
    pub previous: Option<O>,
    /// New root after the edit (from cache).
    pub root: O,
}

/// Outcome of a nullification ([`Nullifying`] mode).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NullifyOutcome {
    /// The nullified leaf.
    pub leaf: LeafIndex,
    /// The record written (depth + size at nullification).
    pub record: NullifierRecord,
}

/// Outcome of a replace ([`Nullifying`] mode): nullify the
/// old leaf, append the new element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplaceOutcome<O: HashValue> {
    /// The leaf that was nullified.
    pub nullified: LeafIndex,
    /// The nullifier record written for it.
    pub record: NullifierRecord,
    /// The append result for the new element.
    pub appended: AppendOutcome<O>,
    /// New MMR root after the append.
    pub root: O,
}

/// Everything that can go wrong at the MMR handle level.
///
/// Generic over [`Storage`] — not over a concrete store trait — so the sync
/// `Mmr` and `AsyncMmr` shells share this
/// one enum; the backend's error surfaces identically through either.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MmrError<S: Storage> {
    /// Store I/O failed.
    #[error("store error")]
    Store(#[source] S::Error),

    /// Leaf ingestion failed.
    #[error("invalid element")]
    Hasher(#[from] HasherError),

    /// The requested leaf cannot be proven (out of range, or below the
    /// provenance floor of a peaks-only MMR).
    #[error("leaf {leaf} is not provable; provable range starts at {provable_from}")]
    UnprovableLeaf {
        /// The rejected leaf.
        leaf: LeafIndex,
        /// First provable leaf for this MMR's provenance.
        provable_from: LeafIndex,
    },

    /// The leaf has a *resolving* nullifier: no proof is issued for it in
    /// [`Nullifying`] mode (own records always resolve;
    /// sub-MMR records only when their size ≤ the stack point — see
    /// [`super::nullifiers`]).
    #[error("leaf {leaf} is nullified")]
    LeafNullified {
        /// The rejected leaf.
        leaf: LeafIndex,
    },

    /// An in-place edit was rejected: the leaf's current value does not
    /// match `expected_current`.
    #[error("edit rejected: leaf {leaf} is not occupied by the expected value")]
    UpdateMismatch {
        /// The rejected leaf.
        leaf: LeafIndex,
    },

    /// Caller-supplied peaks/size do not form a consistent peaks-only seed
    /// (used by `from_peaks`; distinct from [`MmrError::Corrupted`] — the
    /// store is fine, the input is not).
    #[error("invalid peaks seed: {peaks} peaks do not match node count {size}")]
    InvalidPeaks {
        /// The node count the peaks were seeded with.
        size: MmrSize,
        /// How many peaks were supplied.
        peaks: usize,
    },

    /// Persisted metadata is missing, malformed, or names a different
    /// hasher/mode.
    #[error("store does not contain a consistent MMR under this id: {0}")]
    Corrupted(#[source] Corrupted),

    /// A nullifier-record operation failed.
    #[error(transparent)]
    Nullifier(#[from] NullifierError<S>),

    /// Proof verification could not be attempted.
    #[error("could not verify proof: {0}")]
    Verify(#[from] VerifyError),
}

/// Specific corruption findings when opening or resuming an MMR.
///
/// `open` validates every persisted record shape it reads; these are the
/// possible findings. Not `Copy` — `stored` values are read from the store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Corrupted {
    /// A required record is absent (counters, hasher info, mode, root,
    /// sub-views…).
    #[error("required record missing: {table:?}")]
    MissingRecord {
        /// The table whose record was absent.
        table: Table,
    },
    /// A record exists but is malformed: wrong length, invalid UTF-8,
    /// unknown tag, or a value inconsistent with its siblings.
    #[error("persisted record is malformed: {table:?}")]
    MalformedRecord {
        /// The table whose record was malformed.
        table: Table,
    },
    /// Persisted hasher id/config differs from the hasher in use.
    #[error("hasher mismatch: store has {stored}, caller supplied {supplied}")]
    HasherMismatch {
        /// Hasher identity/config recorded at creation (read from the store).
        stored: alloc::string::String,
        /// Hasher passed to the constructor.
        supplied: &'static str,
    },
    /// Peaks cached in metadata do not match the node count.
    #[error("cached peaks do not match node count: expected {expected}, found {found}")]
    PeaksMismatch {
        /// Peak count implied by the persisted node count.
        expected: usize,
        /// Peak count actually stored.
        found: usize,
    },
    /// Persisted root disagrees with the root recomputed from cached peaks.
    #[error("persisted root does not match the recomputed root")]
    RootMismatch,
    /// Persisted mutability mode differs from the mode the caller declared
    /// at `open`.
    #[error("mode mismatch: store has {stored}, caller declared {declared}")]
    ModeMismatch {
        /// Mode recorded at creation (read from the store).
        stored: alloc::string::String,
        /// Mode the caller declared.
        declared: &'static str,
    },
}

impl<H: Hasher, S: Store, K: Kind, M: Mode, Id: TreeId> Mmr<H, S, K, M, Id> {
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

    /// Current root (from cache — no store read).
    ///
    /// Infallible: recomputed purely from the cached peaks via
    /// [`Hasher::hash_pair`], which is infallible by contract.
    #[must_use]
    pub fn root(&self) -> H::Output {
        todo!()
    }

    /// Appends one element (raw bytes; hashed here via [`Hasher::hash_leaf`]).
    ///
    /// One atomic batch write, regardless of how many merges fire.
    ///
    /// # Errors
    ///
    /// [`MmrError::Hasher`] for malformed elements, [`MmrError::Store`] for
    /// backend failures.
    pub fn append(&mut self, element: &[u8]) -> Result<AppendOutcome<H::Output>, MmrError<S>> {
        let _ = element;
        todo!()
    }

    /// Appends many elements in one batch write.
    ///
    /// Accepts anything iterable of byte-like items — `&[&[u8]]`,
    /// `Vec<Vec<u8>>`, iterators of `Bytes`, etc. All-or-nothing: on store
    /// failure none of the batch is persisted.
    ///
    /// # Errors
    ///
    /// As [`Self::append`]; on error the in-memory state is unchanged.
    pub fn append_batch<I>(
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

    /// Builds an inclusion proof for `leaf`.
    ///
    /// One batched read of the sibling path. For a
    /// [`WithPeaks`](crate::design::mmr::WithPeaks) MMR, leaves below the provenance floor
    /// return [`MmrError::UnprovableLeaf`]. In [`Nullifying`]
    /// mode, leaves with a *resolving* nullifier return
    /// [`MmrError::LeafNullified`].
    ///
    /// # Errors
    ///
    /// See above, plus store failures.
    pub fn proof(&self, leaf: LeafIndex) -> Result<Proof<H::Output>, MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Builds a multiproof for many leaves with a deduplicated sibling pool.
    ///
    /// Accepts any iterable of leaf indexes. Single batched read; sibling
    /// overlap across leaves is collapsed.
    ///
    /// # Errors
    ///
    /// As [`Self::proof`].
    pub fn multiproof<I>(&self, leaves: I) -> Result<MultiProof<H::Output>, MmrError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let _ = leaves;
        todo!()
    }

    /// Verifies a proof against this MMR's *current* root.
    ///
    /// For standalone verification (no MMR instance, e.g. inside a contract
    /// client or another process) use [`super::proof::verify_proof`], which
    /// checks the proof against its own commitment.
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof is structurally inconsistent.
    pub fn verify(&self, proof: &Proof<H::Output>, element: &[u8]) -> Result<bool, MmrError<S>> {
        let _ = (proof, element);
        todo!()
    }

    /// Verifies a multiproof against this MMR's *current* root.
    ///
    /// `elements` must align positionally with `proof`'s leaves.
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

    /// The stored hash of a leaf, if it is occupied and readable.
    ///
    /// The cheap way to source [`Self::update`]'s `expected_current` gate —
    /// one single-key batched read instead of a full proof. Returns
    /// [`MmrError::UnprovableLeaf`] below a
    /// [`WithPeaks`](crate::design::mmr::WithPeaks) provenance floor (the value cannot be
    /// known, distinct from an unoccupied leaf's `None`).
    ///
    /// # Errors
    ///
    /// As above, plus store failures.
    pub fn leaf_hash(&self, leaf: LeafIndex) -> Result<Option<H::Output>, MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Reads a node hash from the store (batched, single round trip).
    pub(crate) fn load_nodes(
        &self,
        nodes: &[NodeIndex],
    ) -> Result<Vec<Option<H::Output>>, MmrError<S>> {
        let _ = nodes;
        todo!()
    }

    /// Encodes and commits nodes in one atomic batch.
    pub(crate) fn commit_nodes(
        &mut self,
        nodes: &[(NodeIndex, H::Output)],
    ) -> Result<(), MmrError<S>> {
        let _ = nodes;
        todo!()
    }
}

impl<H: Hasher, S: Store, M: Mode, Id: TreeId> Mmr<H, S, super::Plain, M, Id> {
    /// Creates a fresh, empty MMR and persists its genesis metadata
    /// (including the declared [`Mode`]).
    ///
    /// The mode is chosen by the type annotation:
    /// `Mmr::<_, _, Plain, Editable>::create(..)` — or by the named
    /// constructors [`Self::create_editable`] / [`Self::create_nullifying`]
    /// when inference is awkward.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub fn create(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// Re-opens an existing MMR from the store, validating counters, peaks,
    /// the persisted hasher identity/config, **and the persisted mode**
    /// against the caller's declared type parameters.
    ///
    /// This is where the v0.5 "metadata forgets the padding flag" bug is
    /// structurally prevented: a mismatch is a hard error, not a silent
    /// divergence. Named per-mode variants: [`Self::open_editable`] /
    /// [`Self::open_nullifying`].
    ///
    /// # Errors
    ///
    /// [`MmrError::Corrupted`] for missing/mismatched metadata.
    pub fn open(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// Creates a peaks-only MMR from peaks at a known node count.
    ///
    /// The result is a `Mmr<H, S, WithPeaks, M, Id>`: same root as the source
    /// MMR, appendable, stackable, draftable — but leaves below the seed
    /// size are not provable, enforced at runtime with
    /// [`MmrError::UnprovableLeaf`]. The mode carries over unchanged.
    ///
    /// Available on every kind and mode — building a peaks-only MMR does not
    /// read the source handle, so it is not confined to `Plain`.
    ///
    /// # Errors
    ///
    /// Store failures; inconsistent peaks/size seed ([`MmrError::InvalidPeaks`]).
    pub fn from_peaks(
        hasher: H,
        store: S,
        id: Id,
        size: MmrSize,
        peaks: &[H::Output],
    ) -> Result<Mmr<H, S, super::WithPeaks, M, Id>, MmrError<S>> {
        let _ = (&hasher, &store, id, size, peaks);
        todo!()
    }
}

impl<H: Hasher, S: Store, Id: TreeId> Mmr<H, S, super::Plain, Editable, Id> {
    /// [`Self::create`](Mmr::create) with an [`Editable`]
    /// base — the named alternative to the four-parameter turbofish.
    ///
    /// # Errors
    ///
    /// As [`Mmr::create`].
    pub fn create_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// [`Self::open`](Mmr::open) declaring an [`Editable`]
    /// base — the named alternative to the four-parameter turbofish. The
    /// persisted mode must be `editable`.
    ///
    /// # Errors
    ///
    /// As [`Mmr::open`] ([`Corrupted::ModeMismatch`](Corrupted) on a
    /// different persisted mode).
    pub fn open_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }
}

impl<H: Hasher, S: Store, Id: TreeId> Mmr<H, S, super::Plain, Nullifying, Id> {
    /// [`Self::create`](Mmr::create) with a [`Nullifying`]
    /// base — the named alternative to the four-parameter turbofish.
    ///
    /// # Errors
    ///
    /// As [`Mmr::create`].
    pub fn create_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// [`Self::open`](Mmr::open) declaring a [`Nullifying`]
    /// base — the named alternative to the four-parameter turbofish. The
    /// persisted mode must be `nullifying`.
    ///
    /// # Errors
    ///
    /// As [`Mmr::open`] ([`Corrupted::ModeMismatch`](Corrupted) on a
    /// different persisted mode).
    pub fn open_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }
}

impl<H: Hasher, S: Store + Clone, K: Kind, M: Mode + Stackable, Id: TreeId> Mmr<H, S, K, M, Id> {
    /// Pinned, read-only view of this MMR at its current size, for use as a
    /// stacking layer. The view does not follow later growth of this MMR.
    ///
    /// Only exists for [`Stackable`] modes: an [`Editable`]
    /// MMR cannot be pinned or stacked upon — in-place edits under a pin
    /// would silently corrupt every layer above. This is a compile-time
    /// guarantee, not a runtime check.
    ///
    /// The view aliases the sub-MMR's *store backend* (cloned handle), not
    /// this handle — it stays valid after this handle is dropped. Safe
    /// because pins freeze size and [`Stackable`] bases never edit in place.
    #[must_use]
    pub fn pin(&self) -> super::stacked::SubView<S, Id, H::Output> {
        todo!()
    }
}

impl<H: Hasher, S: Store, M: Stackable, Id: TreeId> Mmr<H, S, super::Stacked, M, Id> {
    /// Builds a stacked MMR over validated sub-views.
    ///
    /// The stacked MMR's own appends go to `store` (its own layer), starting
    /// right after the largest pin size. Its root is identical to the root of
    /// a hypothetical single MMR containing all layers' elements. The new
    /// layer's mode `M` is [`AppendOnly`](crate::design::mmr::AppendOnly) or
    /// [`Nullifying`] — an editable stacked layer is
    /// unconstructible ([`Stackable`]).
    ///
    /// Sub-views are validated (strictly increasing pin sizes, well-formed
    /// sizes — see [`super::stacked::validate_sub_views`]); an invalid set
    /// cannot become a stack.
    ///
    /// # Errors
    ///
    /// Invalid sub-views ([`StackingError::SubViews`](super::stacked::StackingError))
    /// or store failures.
    pub fn stack<I>(
        hasher: H,
        store: S,
        id: Id,
        subs: I,
    ) -> Result<Self, super::stacked::StackingError<S>>
    where
        I: IntoIterator<Item = super::stacked::SubView<S, Id, H::Output>>,
    {
        let _ = (&hasher, &store, id, subs);
        todo!()
    }
}

impl<H: Hasher, S: Store, K: Kind, M: Mode, Id: TreeId> Mmr<H, S, K, M, Id> {
    /// Opens an in-memory draft over this MMR. The draft offers operations
    /// per this MMR's [`Mode`] and holds the base by mutable borrow so its
    /// commit can update the cached state. See [`super::Draft`].
    ///
    /// Exists for every mode: a draft is a buffered session over any base —
    /// an [`Editable`] base drafts `update`/`delete`, a
    /// [`Nullifying`] base drafts the nullify family. What
    /// is mode-gated is *where the log can land*: [`Draft::commit`](super::Draft::commit) replays
    /// into any base, [`Draft::commit_as_stacked`](super::Draft::commit_as_stacked) requires [`Stackable`].
    #[must_use]
    pub fn start_draft(&mut self) -> super::Draft<'_, H, S, K, M, Id> {
        todo!()
    }
}

impl<H: Hasher, S: Store, K: EditableKind> Mmr<H, S, K, Editable> {
    /// Rewrites a leaf in place and recomputes its path to the root — one
    /// batch write.
    ///
    /// Only exists for [`Plain`](crate::design::mmr::Plain) and
    /// [`WithPeaks`](crate::design::mmr::WithPeaks) MMRs — the `Stacked` kind cannot be
    /// editable: unconstructible at the type level via
    /// [`EditableKind`], not just missing a
    /// constructor.
    ///
    /// `expected_current` gates the edit: pass the hash you believe the leaf
    /// currently holds (e.g. from [`Self::leaf_hash`](Mmr::leaf_hash)) to
    /// refuse lost-update races
    /// with [`MmrError::UpdateMismatch`]; pass `None` to skip the check.
    ///
    /// Scope rule (runtime, value-dependent): a `WithPeaks` MMR refuses
    /// leaves below the seed floor ([`MmrError::UnprovableLeaf`] — there is
    /// no node data to recompute from).
    ///
    /// # Errors
    ///
    /// As above, plus [`MmrError::Hasher`] for malformed elements and store
    /// failures.
    pub fn update(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
        expected_current: Option<H::Output>,
    ) -> Result<UpdateOutcome<H::Output>, MmrError<S>> {
        let _ = (leaf, element, expected_current);
        todo!()
    }

    /// Clears a leaf in place: writes the hasher's null value and recomputes
    /// the path — the structure stays dense (no element removal, no
    /// compaction). Same scope rules and gating as [`Self::update`].
    ///
    /// # Errors
    ///
    /// As [`Self::update`].
    pub fn delete(
        &mut self,
        leaf: LeafIndex,
        expected_current: Option<H::Output>,
    ) -> Result<UpdateOutcome<H::Output>, MmrError<S>> {
        let _ = (leaf, expected_current);
        todo!()
    }
}

impl<H: Hasher, S: Store, K: Kind, Id: TreeId> Mmr<H, S, K, Nullifying, Id> {
    /// Marks `leaf` as no longer valid with a **shallow** record — the MMR
    /// data itself is untouched.
    ///
    /// Works for every kind, for any leaf index below the leaf count —
    /// including below a [`WithPeaks`](crate::design::mmr::WithPeaks) floor: records are
    /// index-keyed and need no content.
    ///
    /// The record `(self.id, leaf) → self.size` lands in **this** MMR's
    /// store (the topmost one operated on), never in a sub-MMR's store.
    /// Through stacks, sub-MMR shallow records are respected only when
    /// their size ≤ the stack point — see [`super::nullifiers`] for the
    /// full rules.
    ///
    /// # Errors
    ///
    /// Store failures.
    pub fn nullify_shallow(&mut self, leaf: LeafIndex) -> Result<NullifyOutcome, MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// Overwrite semantics without breaking append-only storage: **shallow**
    /// nullification of the old leaf **and** append of `element` as a new
    /// leaf. The MMR grows by one leaf; the old position is invalid from the
    /// recorded size onward.
    ///
    /// # Errors
    ///
    /// As [`Self::nullify_shallow`] plus append errors.
    pub fn replace_shallow(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let _ = (leaf, element);
        todo!()
    }

    /// Borrowed view of this MMR's own nullifier records.
    #[must_use]
    pub fn nullifier_set(&self) -> NullifierSet<'_, S, Id> {
        todo!()
    }
}

impl<H: Hasher, S: Store, K: DeepNullifiable, Id: TreeId> Mmr<H, S, K, Nullifying, Id> {
    /// Marks `leaf` as no longer valid with a **deep** record — every
    /// stacked MMR above is influenced regardless of when the
    /// nullification happened.
    ///
    /// The record `(owner.id, leaf) → 0` lands in the store of the layer
    /// that **holds the value** (an owning sub-MMR if the leaf lies below a
    /// stack point), so every stack above sees it. Available for
    /// [`Plain`](crate::design::mmr::Plain) and [`Stacked`](crate::design::mmr::Stacked) only — a
    /// `WithPeaks` MMR cannot deep-nullify (compile-time, see
    /// [`DeepNullifiable`]).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub fn nullify_deep(&mut self, leaf: LeafIndex) -> Result<NullifyOutcome, MmrError<S>> {
        let _ = leaf;
        todo!()
    }

    /// **Deep** nullification of the old leaf **and** append of `element` —
    /// the deep variant of [`Self::replace_shallow`]. See
    /// [`Self::nullify_deep`] for record semantics.
    ///
    /// # Errors
    ///
    /// As [`Self::nullify_deep`] plus append errors.
    pub fn replace_deep(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let _ = (leaf, element);
        todo!()
    }
}

/// Unused-import keepers for the draft compile; removed once implemented.
#[allow(unused)]
fn _shape_checks(_t: Table, _k: fn(&MmrId, Table, u64) -> Vec<u8>) {
    let _ = keys::decode;
}
