//! The type-stated MMR handle — the sync shell over the pure [`state`] core.
//!
//! One struct, three type-state axes: the kind ([`Plain`](crate::mmr::Plain),
//! [`WithPeaks`](crate::mmr::WithPeaks), or [`Stacked`](crate::mmr::Stacked)),
//! the mutability mode ([`AppendOnly`](crate::mmr::AppendOnly) by default),
//! and the id type (`AccumulatorId` by default). Variant-specific
//! methods are gated by the parameters: `update`/`delete` exist only on
//! [`Editable`], `nullify`/`replace` only on [`Nullifying`] — calling them on
//! an append-only MMR is a compile error. All methods are sync and
//! non-async by design: state is cached, appends are a single batch write,
//! proofs are a single batch read. For async backends see
//! [`AsyncMmr`](super::AsyncMmr) — same methods, async shell, identical
//! semantics.

use super::Kind;
#[cfg(feature = "stacked_mmr")]
use super::kinds::SingleLayerKind;
use super::kinds::{DeepNullifiable, EditableKind};
use super::layout::{
    LeafCount, MmrSize, NodeIndex, PathStep, Side, bag_peaks, peaks_of, root_from, sibling_path,
};
#[cfg(feature = "stacked_mmr")]
use super::mode::Stackable;
use super::mode::{Editable, Mode, Nullifying};
use super::nullifiers::{NullifierDepth, NullifierError, NullifierRecord, NullifierSet};
use super::proof::{MultiProof, Proof};
use super::stacked::SubView;
use super::stacked::parse_node_value;
#[cfg(feature = "stacked_mmr")]
use super::stacked::{InvalidSubViews, validate_sub_views};
use super::state::{self, AppendDelta, MmrState, Provenance};
use crate::hashers::{Hasher, HasherError};
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::{HashValue, LeafIndex};
use crate::store::{Batch, Storage, Store, keys, keys::Table, record};
#[cfg(feature = "draft_mmr")]
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// A loaded, ready-to-use MMR handle (sync store).
///
/// `K` selects the kind ([`super::Plain`], [`super::WithPeaks`], or
/// [`super::Stacked`]); `M` the mutability mode ([`super::AppendOnly`] by
/// default); `Id` the id type ([`AccumulatorId`] by default). The common case reads
/// clean: `Mmr<PoseidonStarkHasher, MyStore>`.
pub struct Mmr<H: Hasher, S, K = super::Plain, M = super::AppendOnly, Id = AccumulatorId> {
    pub(crate) hasher: H,
    pub(crate) store: S,
    pub(crate) id: Id,
    pub(crate) state: MmrState<H>,
    /// Pinned sub-views — populated only for the [`Stacked`](crate::mmr::Stacked)
    /// kind; always empty otherwise.
    pub(crate) subs: Vec<SubView<S, Id, H::Output>>,
    pub(crate) _kind: core::marker::PhantomData<fn() -> K>,
    pub(crate) _mode: core::marker::PhantomData<fn() -> M>,
}

// State summary only: the store is never rendered — stores are not `Debug`
// and their contents would be noise in logs.
impl<H: Hasher, S, K, M, Id: TreeId> core::fmt::Debug for Mmr<H, S, K, M, Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Mmr")
            .field("id", &self.id)
            .field("leaf_count", &self.state.leaf_count())
            .field("size", &self.state.node_count())
            .field("provenance", &self.state.provenance())
            .field("root", &self.state.root(&self.hasher))
            .finish_non_exhaustive()
    }
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
    /// Previous hash at this leaf. Always `Some` on success: the structure
    /// is dense and an edit onto a *missing* leaf node record is rejected as
    /// corruption ([`Corrupted::MissingRecord`]) — the Option exists only to
    /// mirror the `expected_current` gate's shape.
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

    /// A nullify/replace targeted a leaf at or beyond the MMR's leaf count.
    /// Distinct from [`MmrError::UnprovableLeaf`]: nullifier records are
    /// index-keyed and need no content, so "below a provenance floor" is
    /// meaningful for them — only the range itself is a rejection, and a
    /// fabricated provable-from would be a wrong diagnosis.
    #[error("leaf {leaf} is out of range for an MMR of {leaf_count} leaves")]
    LeafOutOfRange {
        /// The rejected leaf.
        leaf: LeafIndex,
        /// The MMR's leaf count.
        leaf_count: LeafCount,
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

    /// A consistency proof was requested from a `prev_size` this MMR cannot
    /// serve: not a well-formed MMR size, above this MMR's size, or — for a
    /// peaks-only provenance — below the seed floor (the empty prefix `0` is
    /// always servable: the empty MMR's root is a public constant).
    #[error(
        "cannot prove consistency from size {prev_size}: provable range is {provable_from}..={current}"
    )]
    InvalidPrevSize {
        /// The rejected size.
        prev_size: MmrSize,
        /// The smallest servable size (the seed floor for peaks-only
        /// provenance, zero otherwise).
        provable_from: MmrSize,
        /// This MMR's size.
        current: MmrSize,
    },

    /// Persisted metadata is missing, malformed, or names a different
    /// hasher/mode.
    #[error("store does not contain a consistent MMR under this id: {0}")]
    Corrupted(#[source] Corrupted),

    /// A nullifier-record operation failed.
    #[error(transparent)]
    Nullifier(#[from] NullifierError<S>),

    /// A stacked construction was rejected (draft `commit_as_stacked`).
    #[cfg(feature = "stacked_mmr")]
    #[error("invalid stack construction: {0}")]
    Stacking(#[source] super::stacked::InvalidSubViews),

    /// Proof verification could not be attempted.
    #[error("could not verify proof: {0}")]
    Verify(#[from] super::proof::VerifyError),

    /// The caller-supplied hasher's identity/config cannot be represented in
    /// the persisted `HasherInfo` record (custom name over 255 bytes or
    /// config over 65535 bytes) — rejected at creation instead of persisting
    /// a record that would brick every later open. Distinct from
    /// [`MmrError::Corrupted`]: the store is fine, the input is not.
    #[error("hasher identity cannot be represented in the persisted record")]
    UnrepresentableHasher,
}

/// The pure planner's range rejection maps onto the shells' typed variant —
/// the planner itself stays error-enum-free.
impl<S: Storage> From<super::proof::PrevSizeRejection> for MmrError<S> {
    fn from(rejected: super::proof::PrevSizeRejection) -> Self {
        Self::InvalidPrevSize {
            prev_size: rejected.prev_size,
            provable_from: rejected.provable_from,
            current: rejected.current,
        }
    }
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
    /// unknown tag, or a value inconsistent with its siblings — or, at write
    /// time, a record that cannot be produced within its wire format (e.g. a
    /// sub-view list exceeding the record's length prefixes).
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
        /// Hasher passed to the constructor, rendered as `id (config)`.
        supplied: alloc::string::String,
    },
    /// Persisted counters/peaks are inconsistent with the node count.
    #[error("persisted state is inconsistent with node count: expected {expected}, found {found}")]
    PeaksMismatch {
        /// Count implied by the persisted node count.
        expected: usize,
        /// Count actually stored or implied elsewhere.
        found: usize,
    },
    /// Persisted root disagrees with the root recomputed from cached peaks.
    #[error("persisted root does not match the recomputed root")]
    RootMismatch,
    /// A stacked layer's own node count is smaller than the size pinned over
    /// it — the layer cannot back the pin. Distinct from
    /// [`Corrupted::PeaksMismatch`]: this compares a pin against a layer's
    /// counter, not two peak lists.
    #[error("pinned size {pinned} exceeds the layer's node count {layer_size}")]
    PinSizeMismatch {
        /// The size pinned over the layer.
        pinned: MmrSize,
        /// The layer's persisted node count.
        layer_size: MmrSize,
    },
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

/// A recomputed edit path: the changed nodes (leaf first) with their new
/// hashes, plus the index of the containing peak in the cached peaks.
type PathChanges<H> = (Vec<(NodeIndex, <H as Hasher>::Output)>, usize);

/// One batched nullifier read from one sub-layer store: the keys to read
/// there and, per key, the position it fills in the result plus the pin
/// size of the consulted layer.
struct LayerRead<'a, S> {
    store: &'a S,
    keys: Vec<Vec<u8>>,
    targets: Vec<(usize, u64)>,
}

/// One batched nullifier write for one target store: pre-encoded keys and
/// the records to write under them. Only the draft replay's batched commit
/// uses it.
#[cfg(feature = "draft_mmr")]
struct RecordTarget<'a, S> {
    store: &'a S,
    keys: Vec<Vec<u8>>,
    records: Vec<NullifierRecord>,
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
        self.state.root(&self.hasher)
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
        let element_hash = self.hasher.hash_leaf(element)?;
        self.append_hashed(element_hash)
    }

    /// Appends an already-hashed element (crate-internal: the draft replays
    /// buffered appends without re-hashing).
    pub(crate) fn append_hashed(
        &mut self,
        element_hash: H::Output,
    ) -> Result<AppendOutcome<H::Output>, MmrError<S>> {
        let delta = super::state::apply_append(&self.hasher, &self.state, element_hash);
        let leaf = self.state.leaf_count.next_leaf();
        let leaf_node = leaf.node();

        let mut batch = Batch::new();
        self.push_delta(&mut batch, &delta);
        self.store.write(batch).map_err(MmrError::Store)?;
        self.state = delta.state;

        Ok(AppendOutcome {
            leaf,
            node: leaf_node,
            root: delta.root,
        })
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
        let mut element_hashes = Vec::new();
        for element in elements {
            element_hashes.push(self.hasher.hash_leaf(element.as_ref())?);
        }
        if element_hashes.is_empty() {
            return Ok(AppendBatchOutcome {
                first_leaf: self.state.leaf_count.next_leaf(),
                appended: LeafCount::ZERO,
                root: self.state.root(&self.hasher),
            });
        }

        let first_leaf = self.state.leaf_count.next_leaf();
        let root = self.append_hashed_batch(&element_hashes)?;

        Ok(AppendBatchOutcome {
            first_leaf,
            appended: LeafCount::new(element_hashes.len() as u64),
            root,
        })
    }

    /// Batch-append engine for already-hashed elements: one
    /// [`apply_append_batch`](super::state::apply_append_batch) pass and one
    /// batch write, returning the root after the batch. Crate-internal: the
    /// draft commit replay coalesces buffered appends through it.
    pub(crate) fn append_hashed_batch(
        &mut self,
        element_hashes: &[H::Output],
    ) -> Result<H::Output, MmrError<S>> {
        if element_hashes.is_empty() {
            return Ok(self.state.root(&self.hasher));
        }
        let delta = super::state::apply_append_batch(&self.hasher, &self.state, element_hashes);

        let mut batch = Batch::new();
        self.push_delta(&mut batch, &delta);
        self.store.write(batch).map_err(MmrError::Store)?;
        self.state = delta.state;

        Ok(delta.root)
    }

    /// Builds an inclusion proof for `leaf`.
    ///
    /// One batched read of the sibling path. For a
    /// [`WithPeaks`](crate::mmr::WithPeaks) MMR, leaves below the provenance
    /// floor return [`MmrError::UnprovableLeaf`]. In [`Nullifying`]
    /// mode, leaves with a *resolving* nullifier return
    /// [`MmrError::LeafNullified`].
    ///
    /// # Errors
    ///
    /// See above, plus store failures.
    pub fn proof(&self, leaf: LeafIndex) -> Result<Proof<H::Output>, MmrError<S>> {
        self.check_provable(leaf)?;
        self.check_nullified(leaf)?;

        let path = sibling_path(leaf, self.state.node_count);
        let mut indexes: Vec<NodeIndex> = Vec::with_capacity(path.len() + 1);
        indexes.push(leaf.node());
        indexes.extend(path.iter().map(|step| step.sibling));

        let loaded = self.load_nodes(&indexes)?;
        let missing = || {
            MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Nodes,
            })
        };
        let leaf_hash = loaded[0].ok_or_else(missing)?;
        let siblings: Vec<H::Output> = loaded[1..]
            .iter()
            .map(|value| value.ok_or_else(missing))
            .collect::<Result<_, _>>()?;

        Ok(Proof {
            leaf,
            element_hash: leaf_hash,
            siblings,
            peaks: Vec::clone(&self.state.peaks),
            root: self.state.root(&self.hasher),
            size: self.state.node_count,
        })
    }

    /// Builds a multiproof for many leaves with a deduplicated sibling pool.
    ///
    /// Accepts any iterable of leaf indexes. Single batched read per distinct
    /// store (element and sibling nodes together); sibling overlap across
    /// leaves is collapsed. Nullifier resolution is likewise one batched read
    /// per distinct store.
    ///
    /// # Errors
    ///
    /// As [`Self::proof`].
    pub fn multiproof<I>(&self, leaves: I) -> Result<MultiProof<H::Output>, MmrError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        // Canonical order: ascending leaves, deduplicated.
        let mut leaves: Vec<LeafIndex> = leaves.into_iter().collect();
        leaves.sort_unstable();
        leaves.dedup();
        for &leaf in &leaves {
            self.check_provable(leaf)?;
        }
        self.reject_nullified(&leaves)?;

        // Collect every path's node indexes; the pool is first-discovery
        // order so proofs are byte-comparable.
        let paths: Vec<Vec<PathStep>> = leaves
            .iter()
            .map(|leaf| sibling_path(*leaf, self.state.node_count))
            .collect();
        let (pool_indexes, pool_refs) = super::proof::build_sibling_pool(&paths);

        // One batched read: element nodes first, then the pool — split
        // positionally.
        let element_indexes: Vec<NodeIndex> = leaves.iter().map(|leaf| leaf.node()).collect();
        let mut indexes = Vec::with_capacity(element_indexes.len() + pool_indexes.len());
        indexes.extend_from_slice(&element_indexes);
        indexes.extend_from_slice(&pool_indexes);
        let loaded = self.load_nodes(&indexes)?;
        let (loaded_elements, loaded_pool) = loaded.split_at(element_indexes.len());
        let missing = || {
            MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Nodes,
            })
        };

        Ok(MultiProof {
            element_hashes: loaded_elements
                .iter()
                .copied()
                .map(|value| value.ok_or_else(missing))
                .collect::<Result<Vec<_>, _>>()?,
            leaves,
            sibling_pool: loaded_pool
                .iter()
                .copied()
                .map(|value| value.ok_or_else(missing))
                .collect::<Result<Vec<_>, _>>()?,
            sibling_refs: pool_refs,
            peaks: Vec::clone(&self.state.peaks),
            root: self.state.root(&self.hasher),
            size: self.state.node_count,
        })
    }

    /// Builds a consistency proof: the MMR at `prev_size` — an earlier size
    /// of this MMR's history — is a prefix of the MMR at the current size.
    /// Verify with
    /// [`verify_consistency_proof`](super::proof::verify_consistency_proof);
    /// the verifier needs only the hasher and the two roots.
    ///
    /// `prev_size` must be a well-formed MMR size at or below the current
    /// size and — for a peaks-only provenance — at or above the seed floor.
    /// The degenerate sizes are served from the cached peaks with no store
    /// read: `prev_size == current` (the trivial prefix) and `prev_size ==
    /// 0` (the empty MMR's root is a public constant). Every other size is
    /// one batched read of the earlier peaks plus the bridge nodes. Works
    /// over stacked MMRs through the same routed reads as [`Self::proof`] —
    /// nodes invisible through a pin surface come back as missing records.
    /// Nullifiers do not participate: a consistency proof is a
    /// statement about the structure's prefixes, not about leaf validity.
    ///
    /// # Errors
    ///
    /// [`MmrError::InvalidPrevSize`] for a `prev_size` outside the provable
    /// range, [`MmrError::Corrupted`] when a required node is missing, store
    /// failures otherwise.
    pub fn consistency_proof(
        &self,
        prev_size: MmrSize,
    ) -> Result<super::proof::ConsistencyProof<H::Output>, MmrError<S>> {
        let current = self.state.node_count;
        let floor = match self.state.provenance {
            Provenance::Full => MmrSize::ZERO,
            Provenance::FromPeaks { size_at_creation } => size_at_creation,
        };
        match super::proof::consistency_plan(prev_size, current, floor, &self.state.peaks)? {
            super::proof::ConsistencyPlan::Ready(proof) => Ok(proof),
            super::proof::ConsistencyPlan::Fetch {
                indexes,
                peak_count,
            } => {
                // One batched read: the earlier peaks, then the bridge
                // nodes — split positionally.
                let loaded = self.load_nodes(&indexes)?;
                super::proof::consistency_from_loaded(prev_size, current, &loaded, peak_count)
                    .map_err(MmrError::Corrupted)
            }
        }
    }

    /// Verifies a proof against this MMR's *current* root.
    ///
    /// The proof's own commitment is validated standalone (see
    /// [`super::proof::verify_proof`]) and its root must equal the current
    /// one — a proof taken before later appends no longer verifies here;
    /// use the standalone verifier for historical checks.
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof is structurally inconsistent.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify(&self, proof: &Proof<H::Output>, element: &[u8]) -> Result<bool, MmrError<S>> {
        let valid = super::proof::verify_proof(&self.hasher, proof, element)?;
        Ok(valid && proof.root == self.state.root(&self.hasher))
    }

    /// Verifies a multiproof against this MMR's *current* root.
    ///
    /// `elements` must align positionally with `proof`'s leaves.
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof or the element set is structurally
    /// inconsistent.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify_multi<I>(
        &self,
        proof: &MultiProof<H::Output>,
        elements: I,
    ) -> Result<bool, MmrError<S>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let valid = super::proof::verify_multi_proof(&self.hasher, proof, elements)?;
        Ok(valid && proof.root == self.state.root(&self.hasher))
    }

    /// The stored hash of a leaf, if it is occupied and readable.
    ///
    /// The cheap way to source [`Self::update`]'s `expected_current` gate —
    /// one single-key batched read instead of a full proof. Returns
    /// [`MmrError::UnprovableLeaf`] below a
    /// [`WithPeaks`](crate::mmr::WithPeaks) provenance floor (the value
    /// cannot be known, distinct from an unoccupied leaf's `None`).
    ///
    /// # Errors
    ///
    /// As above, plus store failures.
    pub fn leaf_hash(&self, leaf: LeafIndex) -> Result<Option<H::Output>, MmrError<S>> {
        self.check_provable(leaf)?;
        let mut loaded = self.load_nodes(&[leaf.node()])?;
        Ok(loaded.pop().flatten())
    }

    /// Whether `leaf` is inside the provable range of this MMR.
    pub(crate) fn check_provable(&self, leaf: LeafIndex) -> Result<(), MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() || !self.state.is_provable(leaf) {
            return Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from: self.state.provenance.first_provable_leaf(),
            });
        }
        Ok(())
    }

    /// Nullifier gate for [`Nullifying`] mode: own records always resolve;
    /// sub-MMR records resolve under the pin-size rule.
    pub(crate) fn check_nullified(&self, leaf: LeafIndex) -> Result<(), MmrError<S>> {
        if M::NULLIFYING && self.resolve_nullifier(leaf)?.is_some() {
            return Err(MmrError::LeafNullified { leaf });
        }
        Ok(())
    }

    /// Batched nullifier gate for many leaves (multiproof path): resolves
    /// every leaf in one pass — one batched read per distinct store — and
    /// rejects the first (ascending-order) leaf with a resolving record.
    pub(crate) fn reject_nullified(&self, leaves: &[LeafIndex]) -> Result<(), MmrError<S>> {
        if !M::NULLIFYING {
            return Ok(());
        }
        let resolved = self.resolve_nullifiers(leaves)?;
        for (leaf, record) in leaves.iter().zip(&resolved) {
            if record.is_some() {
                return Err(MmrError::LeafNullified { leaf: *leaf });
            }
        }
        Ok(())
    }

    /// Resolves the nullifier record for `leaf` across this MMR's layers.
    /// `Some(record)` means the leaf is nullified for this viewer.
    pub(crate) fn resolve_nullifier(
        &self,
        leaf: LeafIndex,
    ) -> Result<Option<NullifierRecord>, MmrError<S>> {
        Ok(self
            .resolve_nullifiers(&[leaf])?
            .into_iter()
            .next()
            .flatten())
    }

    /// Resolves nullifier records for many leaves across all layers — one
    /// batched read per distinct store (own records and every covering
    /// sub-layer together).
    ///
    /// Every layer whose pin covers a leaf's node is consulted — own records
    /// always resolve; sub-layer records under the per-layer `resolves_at`
    /// pin rule — and the **strongest** resolution wins (deep overrides
    /// shallow; among shallows the smaller, more restrictive, size wins).
    /// That merge is a max over a totally-ordered record set, so consulting
    /// layers in grouped batches yields exactly the sequential walk's result.
    pub(crate) fn resolve_nullifiers(
        &self,
        leaves: &[LeafIndex],
    ) -> Result<Vec<Option<NullifierRecord>>, MmrError<S>> {
        if leaves.is_empty() {
            return Ok(Vec::new());
        }

        // Own (topmost) records always resolve — no pin gates them.
        let mut resolved = super::nullifiers::read_records(&self.store, self.id, leaves)
            .map_err(MmrError::Nullifier)?;

        // Sub records resolve through each view's layer chain (own records
        // of the sub always; deeper layers under the pin-size rule). With
        // strictly increasing pins at most one view covers a leaf, but
        // collecting the strongest keeps this correct even for views whose
        // content was not validated at construction. Reads are grouped per
        // distinct store; merging follows the per-leaf record, so grouping
        // order cannot change the result.
        let mut reads: Vec<LayerRead<'_, S>> = Vec::new();
        for sub in &self.subs {
            for (position, leaf) in leaves.iter().enumerate() {
                let node = leaf.node().get();
                for layer in &sub.layers {
                    if node > layer.pinned_size.get() {
                        continue;
                    }
                    let key = keys::encode(&layer.id_ref(), Table::Nullifiers, leaf.get());
                    match reads
                        .iter_mut()
                        .find(|read| Store::same_store(read.store, layer.store_ref()))
                    {
                        Some(read) => {
                            read.keys.push(key);
                            read.targets.push((position, layer.pinned_size.get()));
                        }
                        None => reads.push(LayerRead {
                            store: layer.store_ref(),
                            keys: vec![key],
                            targets: vec![(position, layer.pinned_size.get())],
                        }),
                    }
                }
            }
        }
        for read in reads {
            let refs: Vec<&[u8]> = read.keys.iter().map(Vec::as_slice).collect();
            let values = read.store.read(&refs).map_err(MmrError::Store)?;
            for (value, (position, pin)) in values.into_iter().zip(&read.targets) {
                let record = match value {
                    None => continue,
                    Some(bytes) => NullifierRecord::parse(&bytes)
                        .ok_or(MmrError::Nullifier(NullifierError::MalformedRecord))?,
                };
                if record.resolves_at(*pin) {
                    resolved[*position] = Some(match resolved[*position] {
                        Some(existing) => existing.stronger(record),
                        None => record,
                    });
                }
            }
        }
        Ok(resolved)
    }

    /// Reads node hashes with layer routing: one batched read per distinct
    /// store, same-store layers merged, keys deduplicated per store.
    pub(crate) fn load_nodes(
        &self,
        nodes: &[NodeIndex],
    ) -> Result<Vec<Option<H::Output>>, MmrError<S>> {
        if self.subs.is_empty() {
            return Self::read_nodes(&self.store, self.id, nodes);
        }
        let groups =
            super::stacked::plan_node_reads(&self.subs, &self.store, self.id, nodes, |a, b| {
                Store::same_store(a, b)
            });

        let mut results: Vec<Option<H::Output>> = vec![None; nodes.len()];
        for group in groups {
            let refs: Vec<&[u8]> = group.keys.iter().map(Vec::as_slice).collect();
            let values = group.store.read(&refs).map_err(MmrError::Store)?;
            for (value, slots) in values.into_iter().zip(&group.slots) {
                let parsed = parse_node_value(value)?;
                for &position in slots {
                    results[position] = parsed;
                }
            }
        }
        Ok(results)
    }

    /// Batched node read from one store under one id.
    fn read_nodes(
        store: &S,
        id: Id,
        nodes: &[NodeIndex],
    ) -> Result<Vec<Option<H::Output>>, MmrError<S>> {
        let encoded: Vec<Vec<u8>> = nodes
            .iter()
            .map(|node| keys::encode(&id, Table::Nodes, node.get()))
            .collect();
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        store
            .read(&refs)
            .map_err(MmrError::Store)?
            .into_iter()
            .map(parse_node_value)
            .collect()
    }

    /// Pushes an append delta's nodes and counters onto a batch.
    fn push_delta(&self, batch: &mut Batch<'_>, delta: &AppendDelta<H>) {
        for (node, hash) in &delta.nodes {
            let key = keys::encode(&self.id, Table::Nodes, node.get());
            batch.put_owned(key, record::hash_value(hash));
        }
        batch.put_owned(
            keys::encode(&self.id, Table::LeafCount, 0),
            record::counter(delta.state.leaf_count.get()),
        );
        batch.put_owned(
            keys::encode(&self.id, Table::NodeCount, 0),
            record::counter(delta.state.node_count.get()),
        );
        batch.put_owned(
            keys::encode(&self.id, Table::Root, 0),
            record::hash_value(&delta.root),
        );
    }

    /// Shared genesis writer: persists metadata for `state` — including the
    /// provenance record (peaks-only seeds persist their seed size, so
    /// `open` can reconstruct the proof floor) — and returns the handle.
    /// Peaks-only seeds also persist their peaks as node
    /// values so `open` reconstructs the state and proves above the floor.
    /// Kind-generic: used by `create` ([`super::Plain`]) and `from_peaks`
    /// ([`super::WithPeaks`]).
    pub(crate) fn create_with_state(
        hasher: H,
        store: S,
        id: Id,
        state: MmrState<H>,
    ) -> Result<Self, MmrError<S>> {
        let mut batch = Batch::new();
        batch.put_owned(
            keys::encode(&id, Table::HasherInfo, 0),
            record::hasher_info(&hasher).ok_or(MmrError::UnrepresentableHasher)?,
        );
        batch.put_owned(keys::encode(&id, Table::Mode, 0), record::text(M::NAME));
        batch.put_owned(
            keys::encode(&id, Table::LeafCount, 0),
            record::counter(state.leaf_count.get()),
        );
        batch.put_owned(
            keys::encode(&id, Table::NodeCount, 0),
            record::counter(state.node_count.get()),
        );
        batch.put_owned(
            keys::encode(&id, Table::Provenance, 0),
            state::encode_provenance(state.provenance),
        );
        batch.put_owned(
            keys::encode(&id, Table::Root, 0),
            record::hash_value(&state.root(&hasher)),
        );
        for (peak, node) in state.peaks.iter().zip(peaks_of(state.node_count)) {
            batch.put_owned(
                keys::encode(&id, Table::Nodes, node.get()),
                record::hash_value(peak),
            );
        }
        store.write(batch).map_err(MmrError::Store)?;

        Ok(Self {
            hasher,
            store,
            id,
            state,
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        })
    }

    /// Reads the persisted metadata block (hasher, mode, counters,
    /// provenance) and validates it through the one shared validation helper
    /// (`state::validate_metadata`); returns the parsed metadata plus the raw
    /// root record for the caller's post-peaks root check. Shared by
    /// [`Self::load`] and `open_stack`.
    fn read_metadata(
        hasher: &H,
        store: &S,
        id: Id,
        declared_mode: &'static str,
    ) -> Result<(state::Metadata, Vec<u8>), MmrError<S>> {
        let metadata_keys: Vec<Vec<u8>> = [
            Table::HasherInfo,
            Table::Mode,
            Table::LeafCount,
            Table::NodeCount,
            Table::Provenance,
            Table::Root,
        ]
        .iter()
        .map(|table| keys::encode(&id, *table, 0))
        .collect();
        let refs: Vec<&[u8]> = metadata_keys.iter().map(Vec::as_slice).collect();
        let values = store.read(&refs).map_err(MmrError::Store)?;

        let missing = |table| MmrError::Corrupted(Corrupted::MissingRecord { table });
        let value = |index: usize, table| -> Result<&[u8], MmrError<S>> {
            values
                .get(index)
                .and_then(Option::as_deref)
                .ok_or_else(|| missing(table))
        };

        let tables = [
            Table::HasherInfo,
            Table::Mode,
            Table::LeafCount,
            Table::NodeCount,
            Table::Provenance,
        ];
        let mut metadata = [&[] as &[u8]; 5];
        for (slot, (index, table)) in metadata.iter_mut().zip(tables.iter().enumerate()) {
            *slot = value(index, *table)?;
        }
        let parsed = state::validate_metadata(hasher, metadata, declared_mode)
            .map_err(MmrError::Corrupted)?;

        Ok((parsed, value(5, Table::Root)?.to_vec()))
    }

    /// Shared loader: reads and validates all persisted metadata through the
    /// one shared validation helper (`state::validate_metadata` — hasher,
    /// mode, counters, provenance), then the peaks and the root. The
    /// provenance is reconstructed from its record; the caller (the
    /// kind-specific `open`) checks it against the kind being opened.
    pub(crate) fn load(
        hasher: H,
        store: S,
        id: Id,
        declared_mode: &'static str,
    ) -> Result<(H, S, Id, MmrState<H>), MmrError<S>> {
        let (
            state::Metadata {
                leaf_count,
                node_count,
                provenance,
            },
            root_record,
        ) = Self::read_metadata(&hasher, &store, id, declared_mode)?;

        // Peaks from the node table.
        let peak_nodes = peaks_of(node_count);
        let peak_values = Self::read_nodes(&store, id, &peak_nodes)?;
        let peaks: Vec<H::Output> = peak_values
            .into_iter()
            .map(|value| {
                value.ok_or_else(|| {
                    MmrError::Corrupted(Corrupted::MissingRecord {
                        table: Table::Nodes,
                    })
                })
            })
            .collect::<Result<_, _>>()?;

        let state = MmrState {
            leaf_count,
            node_count,
            peaks,
            provenance,
        };
        if record::hash_value(&state.root(&hasher)).as_slice() != root_record.as_slice() {
            return Err(MmrError::Corrupted(Corrupted::RootMismatch));
        }

        Ok((hasher, store, id, state))
    }

    /// Recomputes the path from `leaf` upward with `new_leaf_hash`, returning
    /// the changed node values (leaf first) and the index of the containing
    /// peak in the cached peaks.
    ///
    /// `siblings` holds the pre-loaded sibling values for `leaf`'s full
    /// sibling path (bottom-up, as [`sibling_path`] yields it) — callers
    /// batch the leaf and sibling reads into one store call.
    pub(crate) fn recompute_path(
        &self,
        leaf: LeafIndex,
        new_leaf_hash: H::Output,
        siblings: &[Option<H::Output>],
    ) -> Result<PathChanges<H>, MmrError<S>> {
        let path = sibling_path(leaf, self.state.node_count);

        let missing = || {
            MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Nodes,
            })
        };
        let mut hash = new_leaf_hash;
        let mut changed = vec![(leaf.node(), new_leaf_hash)];
        let mut node = leaf.node();
        for (step, sibling) in path.iter().zip(siblings.iter()) {
            let sibling = sibling.ok_or_else(missing)?;
            hash = match step.side {
                Side::Left => self.hasher.hash_pair(sibling, hash),
                Side::Right => self.hasher.hash_pair(hash, sibling),
            };
            node = node.parent().ok_or_else(missing)?;
            changed.push((node, hash));
        }

        // The final node is the leaf's containing peak.
        let peaks = peaks_of(self.state.node_count);
        let peak_index = peaks
            .iter()
            .position(|peak| peak.get() == node.get())
            .ok_or_else(missing)?;
        Ok((changed, peak_index))
    }

    /// The shared edit engine: gate check, path recompute, one batch write,
    /// cached peaks updated. Crate-internal: the public surface gates it on
    /// [`Editable`] + [`EditableKind`]; the draft replay uses it directly.
    pub(crate) fn update_hashed(
        &mut self,
        leaf: LeafIndex,
        new_hash: H::Output,
        expected_current: Option<H::Output>,
    ) -> Result<UpdateOutcome<H::Output>, MmrError<S>> {
        self.check_provable(leaf)?;

        // One batched read for the leaf and all its siblings.
        let path = sibling_path(leaf, self.state.node_count);
        let mut indexes: Vec<NodeIndex> = Vec::with_capacity(path.len() + 1);
        indexes.push(leaf.node());
        indexes.extend(path.iter().map(|step| step.sibling));
        let mut loaded = self.load_nodes(&indexes)?;
        let current = loaded.first().copied().flatten();
        let siblings = loaded.split_off(1);
        // An edit onto an absent leaf node is corruption (the structure is
        // dense), not a gate mismatch: it must fail as a missing record
        // regardless of the gate, never "repair" the state by writing over
        // nothing.
        let Some(current) = current else {
            return Err(MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Nodes,
            }));
        };
        if let Some(expected) = expected_current
            && current != expected
        {
            return Err(MmrError::UpdateMismatch { leaf });
        }

        let (changed, peak_index) = self.recompute_path(leaf, new_hash, &siblings)?;
        #[expect(
            clippy::expect_used,
            reason = "recompute_path always returns the leaf it starts from"
        )]
        let new_peak = changed.last().expect("path always touches the leaf").1;

        // One batch: changed path nodes + the recomputed root.
        let mut peaks = Vec::clone(&self.state.peaks);
        peaks[peak_index] = new_peak;
        let mut batch = Batch::new();
        for (node, hash) in &changed {
            batch.put_owned(
                keys::encode(&self.id, Table::Nodes, node.get()),
                record::hash_value(hash),
            );
        }
        batch.put_owned(
            keys::encode(&self.id, Table::Root, 0),
            record::hash_value(&root_from(
                &self.hasher,
                bag_peaks(&self.hasher, &peaks),
                self.state.node_count,
            )),
        );
        self.store.write(batch).map_err(MmrError::Store)?;

        self.state.peaks[peak_index] = new_peak;
        Ok(UpdateOutcome {
            leaf,
            previous: Some(current),
            root: self.state.root(&self.hasher),
        })
    }

    /// Resolves the store + id that own a deep record for `leaf` (the layer
    /// that holds the value), or `None` when this MMR's own layer owns it.
    fn deep_owner(&self, leaf: LeafIndex) -> Option<(&S, Id)> {
        let node = leaf.node().get();
        for sub in &self.subs {
            if node <= sub.pinned_size().get() {
                if let Some(layer) = sub.route(node) {
                    return Some((layer.store_ref(), layer.id_ref()));
                }
                break;
            }
        }
        None
    }

    /// Writes one nullifier record with full layer routing: shallow records
    /// land in this MMR's own store (the topmost one operated on), deep
    /// records in the store of the layer that holds the value. Crate-internal:
    /// the public surface gates it on [`Nullifying`] (and
    /// [`DeepNullifiable`] for deep); the draft replay uses it directly.
    pub(crate) fn record_nullifier(
        &mut self,
        leaf: LeafIndex,
        depth: NullifierDepth,
    ) -> Result<NullifierRecord, MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() {
            return Err(MmrError::LeafOutOfRange {
                leaf,
                leaf_count: self.state.leaf_count,
            });
        }
        match depth {
            NullifierDepth::Shallow => {
                let at = self.state.node_count;
                let set = NullifierSet {
                    store: &self.store,
                    id: self.id,
                };
                set.nullify_shallow(leaf, at).map_err(MmrError::Nullifier)?;
                Ok(NullifierRecord::Shallow { at })
            }
            NullifierDepth::Deep => {
                // Deep records land in the store of the layer that holds the
                // value, so every stack above sees them. Through a stacked
                // sub-view, the owner is the covering layer of the chain.
                let set = match self.deep_owner(leaf) {
                    Some((store, id)) => NullifierSet { store, id },
                    None => NullifierSet {
                        store: &self.store,
                        id: self.id,
                    },
                };
                set.nullify_deep(leaf).map_err(MmrError::Nullifier)?;
                Ok(NullifierRecord::Deep)
            }
        }
    }

    /// One batched write for a run of nullifier requests: existing records
    /// are read in one batched call per distinct target store, requests for
    /// the same leaf merge (strongest wins), and every store group commits
    /// in one atomic batch. Crate-internal: the draft commit replay uses it
    /// so a run of nullifications costs one read + one write per store, not
    /// one round trip per record.
    #[cfg(feature = "draft_mmr")]
    pub(crate) fn record_nullifiers(
        &self,
        requests: &[(LeafIndex, NullifierDepth)],
    ) -> Result<(), MmrError<S>> {
        if requests.is_empty() {
            return Ok(());
        }

        // Resolve each request's target (store, id) and wire record; group
        // by store so every distinct store sees one batched read + one
        // batched write.
        let at = self.state.node_count;
        let mut groups: Vec<RecordTarget<'_, S>> = Vec::new();
        for &(leaf, depth) in requests {
            if leaf.get() >= self.state.leaf_count.get() {
                return Err(MmrError::LeafOutOfRange {
                    leaf,
                    leaf_count: self.state.leaf_count,
                });
            }
            let record = match depth {
                NullifierDepth::Shallow => NullifierRecord::Shallow { at },
                NullifierDepth::Deep => NullifierRecord::Deep,
            };
            let (store, id) = match depth {
                NullifierDepth::Shallow => (&self.store, self.id),
                NullifierDepth::Deep => self.deep_owner(leaf).unwrap_or((&self.store, self.id)),
            };
            let key = keys::encode(&id, Table::Nullifiers, leaf.get());
            match groups
                .iter_mut()
                .find(|group| Store::same_store(group.store, store))
            {
                Some(group) => {
                    group.keys.push(key);
                    group.records.push(record);
                }
                None => groups.push(RecordTarget {
                    store,
                    keys: vec![key],
                    records: vec![record],
                }),
            }
        }

        for group in groups {
            super::nullifiers::write_records(group.store, group.keys, group.records)
                .map_err(MmrError::Nullifier)?;
        }
        Ok(())
    }

    /// The shared replace engine ([`Nullifying`] mode): hash-first — the
    /// element is ingested *before* any nullifier record is written, so a
    /// malformed element can never nullify a leaf unrecoverably.
    ///
    /// When the record and the append share one store (always true for
    /// shallow, and for deep when this layer owns the value), the nullifier
    /// record and the append delta land in **one** batch write. A deep
    /// record owned by a sub-layer's store is a separate, earlier write —
    /// cross-store, not atomic with the append (documented limitation).
    fn replace_hashed(
        &mut self,
        leaf: LeafIndex,
        element_hash: H::Output,
        depth: NullifierDepth,
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() {
            return Err(MmrError::LeafOutOfRange {
                leaf,
                leaf_count: self.state.leaf_count,
            });
        }

        let at = self.state.node_count;
        let record = match depth {
            NullifierDepth::Shallow => NullifierRecord::Shallow { at },
            NullifierDepth::Deep => NullifierRecord::Deep,
        };

        // Shallow records share this MMR's store with the append — the two
        // coalesce into one atomic batch. Deep records coalesce only when
        // this layer owns the value; a sub-layer-owned deep record is a
        // separate, earlier write (cross-store, not atomic with the append).
        let owner = match depth {
            NullifierDepth::Shallow => None,
            NullifierDepth::Deep => self.deep_owner(leaf),
        };

        match owner {
            None => {
                // One batched read of the existing record (strengthen-only
                // rule), then one atomic batch: record + append delta.
                let existing = super::nullifiers::read_record(&self.store, self.id, leaf)
                    .map_err(MmrError::Nullifier)?;
                let delta = super::state::apply_append(&self.hasher, &self.state, element_hash);
                let leaf_out = self.state.leaf_count.next_leaf();
                let leaf_node = leaf_out.node();
                let mut batch = Batch::new();
                let write_record = !existing.is_some_and(|existing| existing.strength_over(record));
                if write_record {
                    batch.put_owned(
                        keys::encode(&self.id, Table::Nullifiers, leaf.get()),
                        record::counter(record.encoded()),
                    );
                }
                self.push_delta(&mut batch, &delta);
                self.store.write(batch).map_err(MmrError::Store)?;
                self.state = delta.state;
                Ok(ReplaceOutcome {
                    nullified: leaf,
                    record,
                    appended: AppendOutcome {
                        leaf: leaf_out,
                        node: leaf_node,
                        root: delta.root,
                    },
                    root: delta.root,
                })
            }
            Some((owner_store, owner_id)) => {
                // Cross-store deep record: write it to the owning sub-layer's
                // store first (its own atomic batch), then the append. Not
                // atomic together.
                super::nullifiers::nullify_record(owner_store, owner_id, leaf, record)
                    .map_err(MmrError::Nullifier)?;
                let appended = self.append_hashed(element_hash)?;
                Ok(ReplaceOutcome {
                    root: appended.root,
                    nullified: leaf,
                    record,
                    appended,
                })
            }
        }
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
        Self::create_with_state(hasher, store, id, MmrState::empty())
    }

    /// Re-opens an existing MMR from the store, validating counters, peaks,
    /// the persisted hasher identity/config, **and the persisted mode**
    /// against the caller's declared type parameters.
    ///
    /// Any mismatch is a hard error, never a silent divergence. Named
    /// per-mode variants: [`Self::open_editable`] /
    /// [`Self::open_nullifying`]. A store whose provenance record says
    /// peaks-only ([`Provenance::FromPeaks`]) is rejected — open it as a
    /// [`WithPeaks`](super::WithPeaks) MMR instead, which restores the seed
    /// floor ([`Self::open`](Mmr::open) on that kind).
    ///
    /// # Errors
    ///
    /// [`MmrError::Corrupted`] for missing/mismatched metadata — including a
    /// provenance record that does not match this kind.
    pub fn open(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let (hasher, store, id, state) = Self::load(hasher, store, id, M::NAME)?;
        // A Plain handle claims full history; a peaks-only store would
        // silently lose its proof floor here.
        if state.provenance() != Provenance::Full {
            return Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::Provenance,
            }));
        }
        Ok(Self {
            hasher,
            store,
            id,
            state,
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        })
    }
}

impl<H: Hasher, S: Store, M: Mode, Id: TreeId> Mmr<H, S, super::WithPeaks, M, Id> {
    /// Creates a peaks-only MMR from peaks at a known node count.
    ///
    /// The result is a `Mmr<H, S, WithPeaks, M, Id>`: same root as the source
    /// MMR, appendable, stackable, draftable — but leaves below the seed
    /// size are not provable, enforced at runtime with
    /// [`MmrError::UnprovableLeaf`]. The mode carries over unchanged.
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
    ) -> Result<Self, MmrError<S>> {
        let Some(leaf_count) = size.leaf_count() else {
            return Err(MmrError::InvalidPeaks {
                size,
                peaks: peaks.len(),
            });
        };
        if peaks.len() != leaf_count.get().count_ones() as usize {
            return Err(MmrError::InvalidPeaks {
                size,
                peaks: peaks.len(),
            });
        }

        Self::create_with_state(hasher, store, id, MmrState::from_peaks(size, peaks))
    }

    /// Re-opens an existing peaks-only MMR from the store, reconstructing
    /// the seed floor from the persisted provenance record.
    ///
    /// Full parity with [`Mmr::open`](Mmr::open) on the
    /// [`Plain`](super::Plain) kind — a peaks-only MMR grows, stacks, and
    /// drafts like any MMR: the persisted
    /// metadata (hasher, mode, counters, provenance) is validated, and a
    /// store whose provenance record says full history is rejected — open it
    /// as a Plain MMR instead. Named per-mode variants:
    /// [`Self::open_editable`] / [`Self::open_nullifying`].
    ///
    /// # Errors
    ///
    /// [`MmrError::Corrupted`] for missing/mismatched metadata — including a
    /// provenance record that does not match this kind.
    pub fn open(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let (hasher, store, id, state) = Self::load(hasher, store, id, M::NAME)?;
        // A WithPeaks handle needs the seed floor; a full-history store has
        // nothing to floor.
        if !matches!(state.provenance(), Provenance::FromPeaks { .. }) {
            return Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::Provenance,
            }));
        }
        Ok(Self {
            hasher,
            store,
            id,
            state,
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        })
    }
}

impl<H: Hasher, S: Store, Id: TreeId> Mmr<H, S, super::WithPeaks, Editable, Id> {
    /// [`Mmr::open`](Mmr::open) declaring a
    /// [`WithPeaks`](super::WithPeaks) + [`Editable`] base — the named
    /// alternative to the turbofish. See [`Self::open`](Self::open).
    ///
    /// # Errors
    ///
    /// As [`Self::open`](Self::open).
    pub fn open_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::open(hasher, store, id)
    }
}

impl<H: Hasher, S: Store, Id: TreeId> Mmr<H, S, super::WithPeaks, Nullifying, Id> {
    /// [`Mmr::open`](Mmr::open) declaring a
    /// [`WithPeaks`](super::WithPeaks) + [`Nullifying`] base — the named
    /// alternative to the turbofish. See [`Self::open`](Self::open).
    ///
    /// # Errors
    ///
    /// As [`Self::open`](Self::open).
    pub fn open_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::open(hasher, store, id)
    }
}

impl<H: Hasher, S: Store, Id: TreeId> Mmr<H, S, super::Plain, Editable, Id> {
    /// [`Mmr::create`] with an [`Editable`]
    /// base — the named alternative to the four-parameter turbofish.
    ///
    /// # Errors
    ///
    /// As [`Mmr::create`].
    pub fn create_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::create(hasher, store, id)
    }

    /// [`Mmr::open`] declaring an [`Editable`]
    /// base — the named alternative to the four-parameter turbofish. The
    /// persisted mode must be `editable`.
    ///
    /// # Errors
    ///
    /// As [`Mmr::open`] ([`Corrupted::ModeMismatch`](Corrupted) on a
    /// different persisted mode).
    pub fn open_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::open(hasher, store, id)
    }
}

impl<H: Hasher, S: Store, Id: TreeId> Mmr<H, S, super::Plain, Nullifying, Id> {
    /// [`Mmr::create`] with a [`Nullifying`]
    /// base — the named alternative to the four-parameter turbofish.
    ///
    /// # Errors
    ///
    /// As [`Mmr::create`].
    pub fn create_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::create(hasher, store, id)
    }

    /// [`Mmr::open`] declaring a [`Nullifying`]
    /// base — the named alternative to the four-parameter turbofish. The
    /// persisted mode must be `nullifying`.
    ///
    /// # Errors
    ///
    /// As [`Mmr::open`] ([`Corrupted::ModeMismatch`](Corrupted) on a
    /// different persisted mode).
    pub fn open_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::open(hasher, store, id)
    }
}

#[cfg(feature = "stacked_mmr")]
impl<H: Hasher, S: Store + Clone, K: SingleLayerKind, M: Mode + Stackable, Id: TreeId>
    Mmr<H, S, K, M, Id>
{
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
    /// (A [`Stacked`](crate::mmr::Stacked) MMR pins as a whole chain — see
    /// its `pin` impl.)
    #[must_use]
    pub fn pin(&self) -> SubView<S, Id, H::Output> {
        SubView {
            layers: vec![super::stacked::LayerView {
                id: self.id,
                store: S::clone(&self.store),
                pinned_size: self.state.node_count,
                locator: Store::locator(&self.store),
                _output: core::marker::PhantomData,
            }],
            pinned_size: self.state.node_count,
            _output: core::marker::PhantomData,
        }
    }
}

#[cfg(feature = "stacked_mmr")]
impl<H: Hasher, S: Store + Clone, M: Stackable, Id: TreeId> Mmr<H, S, super::Stacked, M, Id> {
    /// Pinned, read-only view of this stacked MMR at its current size, for
    /// use as a stacking layer. The view carries the whole flattened layer
    /// chain, so stacking it further preserves the routing; reads through it
    /// see nodes only up to this MMR's size at pin time.
    ///
    /// Only exists for [`Stackable`] modes — an [`Editable`] MMR cannot be
    /// pinned (compile-time guarantee).
    #[must_use]
    pub fn pin(&self) -> SubView<S, Id, H::Output> {
        let mut layers: Vec<super::stacked::LayerView<S, Id, H::Output>> = self
            .subs
            .iter()
            .flat_map(|sub| {
                sub.layers
                    .iter()
                    .map(|layer| super::stacked::LayerView {
                        id: layer.id,
                        store: S::clone(layer.store_ref()),
                        pinned_size: layer.pinned_size,
                        locator: layer.locator.clone(),
                        _output: core::marker::PhantomData,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        layers.push(super::stacked::LayerView {
            id: self.id,
            store: S::clone(&self.store),
            pinned_size: self.state.node_count,
            locator: Store::locator(&self.store),
            _output: core::marker::PhantomData,
        });
        SubView {
            layers,
            pinned_size: self.state.node_count,
            _output: core::marker::PhantomData,
        }
    }

    /// Builds a stacked MMR over validated sub-views.
    ///
    /// The stacked MMR's own appends go to `store` (its own layer), starting
    /// right after the largest pin size. Its root is identical to the root of
    /// a hypothetical single MMR containing all layers' elements. The new
    /// layer's mode `M` is [`AppendOnly`](crate::mmr::AppendOnly) or
    /// [`Nullifying`] — an editable stacked layer is
    /// unconstructible ([`Stackable`]).
    ///
    /// Sub-views are validated (strictly increasing pin sizes, well-formed
    /// sizes — see [`validate_sub_views`]); an invalid set
    /// cannot become a stack.
    ///
    /// # Errors
    ///
    /// Invalid sub-views ([`super::stacked::StackingError::SubViews`]),
    /// sub-view content that does not back its pin
    /// ([`InvalidSubViews::MissingPeakNodes`] — [`SubView::single`] is a
    /// forgeable constructor: it validates shape, not store content), or
    /// store failures.
    pub fn stack<I>(
        hasher: H,
        store: S,
        id: Id,
        subs: I,
    ) -> Result<Self, super::stacked::StackingError<S>>
    where
        I: IntoIterator<Item = SubView<S, Id, H::Output>>,
    {
        let subs: Vec<_> = subs.into_iter().collect();
        validate_sub_views(&subs).map_err(super::stacked::StackingError::SubViews)?;

        let mut handle = Self {
            hasher,
            store,
            id,
            state: MmrState::empty(),
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        };
        handle.init_stack(subs).map(|()| handle)
    }
    /// Shared stack bootstrap: reads routed peaks, persists genesis metadata
    /// and the sub-view record. Used by [`Self::stack`].
    ///
    /// Errors are [`StackingError`]s because every failure here is either a
    /// store failure or a sub-view whose content does not back its pin —
    /// the pins come from validated handles, but [`SubView::single`] is a
    /// forgeable constructor (it validates shape, not store content).
    pub(crate) fn init_stack(
        &mut self,
        subs: Vec<SubView<S, Id, H::Output>>,
    ) -> Result<(), super::stacked::StackingError<S>> {
        let top_start = subs.last().map_or(0, |sub| sub.pinned_size.get());

        // Install the sub-views first: the routed peak read below needs the
        // layer routing to find the pinned nodes.
        self.subs = subs;

        // Routed peak read across the layers. A missing or unparsable
        // pinned peak is sub-view content corruption, not a generic store
        // failure.
        let peak_nodes = peaks_of(MmrSize::new_unchecked(top_start));
        let peaks: Vec<H::Output> = self
            .load_nodes(&peak_nodes)
            .map_err(|error| match error {
                MmrError::Store(err) => super::stacked::StackingError::Store(err),
                // `load_nodes` reports corruption only through the node
                // table (a present-but-unparsable value), so a peak read's
                // corruption findings are pinned peaks the sub-view cannot
                // back; its other variants are unreachable from a read.
                // Fail closed either way — typed error, never a panic.
                _ => super::stacked::StackingError::SubViews(InvalidSubViews::MissingPeakNodes),
            })?
            .into_iter()
            .map(|value| {
                value.ok_or(super::stacked::StackingError::SubViews(
                    InvalidSubViews::MissingPeakNodes,
                ))
            })
            .collect::<Result<_, _>>()?;

        // Cross-layer hasher validation: a stack whose layers hash
        // with a different identity/config would not reproduce the reference
        // root. Runs after the peak read so a layer that cannot even back
        // its pin is diagnosed as missing peak nodes first.
        if let Some(stored) = super::stacked::first_layer_hasher_mismatch(&self.subs, &self.hasher)
        {
            return Err(super::stacked::StackingError::LayerHasherMismatch { stored });
        }

        self.state = MmrState {
            leaf_count: MmrSize::new_unchecked(top_start)
                .leaf_count()
                .unwrap_or(LeafCount::ZERO),
            node_count: MmrSize::new_unchecked(top_start),
            peaks,
            provenance: Provenance::Full,
        };

        // Persist genesis metadata + the sub-view record: every layer of
        // every sub-view, flattened bottom → top. Layers without a locator
        // (session-local backends) persist an empty one — such stacks cannot
        // be re-opened.
        let layers: Vec<super::stacked::PersistedLayer<Id>> = self
            .subs
            .iter()
            .flat_map(super::stacked::SubView::persisted_layers)
            .collect();

        let mut batch = Batch::new();
        batch.put_owned(
            keys::encode(&self.id, Table::HasherInfo, 0),
            record::hasher_info(&self.hasher)
                .ok_or_else(|| super::stacked::StackingError::UnrepresentableHasher)?,
        );
        batch.put_owned(
            keys::encode(&self.id, Table::Mode, 0),
            record::text(M::NAME),
        );
        batch.put_owned(
            keys::encode(&self.id, Table::LeafCount, 0),
            record::counter(self.state.leaf_count.get()),
        );
        batch.put_owned(
            keys::encode(&self.id, Table::NodeCount, 0),
            record::counter(self.state.node_count.get()),
        );
        batch.put_owned(
            keys::encode(&self.id, Table::Provenance, 0),
            state::encode_provenance(self.state.provenance),
        );
        batch.put_owned(
            keys::encode(&self.id, Table::Root, 0),
            record::hash_value(&self.state.root(&self.hasher)),
        );
        batch.put_owned(
            keys::encode(&self.id, Table::Subviews, 0),
            super::stacked::encode_subviews(&layers).ok_or_else(|| {
                super::stacked::StackingError::SubViews(InvalidSubViews::Unrepresentable)
            })?,
        );
        self.store
            .write(batch)
            .map_err(super::stacked::StackingError::Store)
    }
}

#[cfg(feature = "stacked_mmr")]
impl<H: Hasher, S: Store, M: Stackable, Id: TreeId> Mmr<H, S, super::Stacked, M, Id> {
    /// Re-open path shared with
    /// [`open_stacked`](super::stacked::open_stacked): validates the sub-view
    /// list, the persisted metadata (through the shared
    /// `state::validate_metadata` helper), every layer's hasher, then loads
    /// routed peaks for the reconstructed sub-views.
    pub(crate) fn open_stack(
        hasher: H,
        store: S,
        id: Id,
        subs: Vec<SubView<S, Id, H::Output>>,
    ) -> Result<Self, MmrError<S>> {
        let mut handle = Self {
            hasher,
            store,
            id,
            state: MmrState::empty(),
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        };

        // The sub-view list is validated exactly like at construction
        // ([`Mmr::stack`]): it is persisted data, so unsorted or duplicate
        // pins must not route reads to the wrong layer.
        validate_sub_views(&subs).map_err(MmrError::Stacking)?;

        // Cross-layer hasher validation — same gate as [`Mmr::stack`].
        if let Some(stored) = super::stacked::first_layer_hasher_mismatch(&subs, &handle.hasher) {
            return Err(MmrError::Corrupted(Corrupted::HasherMismatch {
                stored,
                supplied: alloc::format!("{} ({})", handle.hasher.id(), handle.hasher.config()),
            }));
        }

        // Metadata validation (the routed peaks need the subs, so they are
        // loaded after the sub-views are installed).
        let (
            state::Metadata {
                leaf_count,
                node_count,
                provenance,
            },
            root_record,
        ) = Self::read_metadata(&handle.hasher, &handle.store, handle.id, M::NAME)?;
        // A stacked layer's own provenance is always full history (stacks
        // start empty above their pins).
        if provenance != Provenance::Full {
            return Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::Provenance,
            }));
        }

        handle.subs = subs;
        let peak_nodes = peaks_of(node_count);
        let peaks: Vec<H::Output> = handle
            .load_nodes(&peak_nodes)?
            .into_iter()
            .map(|value| {
                value.ok_or_else(|| {
                    MmrError::Corrupted(Corrupted::MissingRecord {
                        table: Table::Nodes,
                    })
                })
            })
            .collect::<Result<_, _>>()?;
        handle.state = MmrState {
            leaf_count,
            node_count,
            peaks,
            provenance,
        };

        if record::hash_value(&handle.state.root(&handle.hasher)).as_slice()
            != root_record.as_slice()
        {
            return Err(MmrError::Corrupted(Corrupted::RootMismatch));
        }
        Ok(handle)
    }
}

#[cfg(feature = "draft_mmr")]
impl<H: Hasher, S: Store, K: Kind, M: Mode, Id: TreeId> Mmr<H, S, K, M, Id> {
    /// Opens an in-memory draft over this MMR. The draft offers operations
    /// per this MMR's [`Mode`] and holds the base by mutable borrow so its
    /// commit can update the cached state. See [`super::Draft`].
    ///
    /// Exists for every mode: a draft is a buffered session over any base —
    /// an [`Editable`] base drafts `update`/`delete`, a
    /// [`Nullifying`] base drafts the nullify family. What
    /// is mode-gated is *where the log can land*: [`super::Draft::commit`]
    /// replays into any base, [`super::Draft::commit_as_stacked`] requires
    /// [`Stackable`].
    #[must_use]
    pub fn start_draft(&mut self) -> super::Draft<'_, H, S, K, M, Id> {
        let state = self.state.clone();
        super::Draft {
            base: self,
            ops: Vec::new(),
            state,
            overlay: BTreeMap::new(),
            buffered_nullified: BTreeMap::new(),
        }
    }
}

impl<H: Hasher, S: Store, K: EditableKind, Id: TreeId> Mmr<H, S, K, Editable, Id> {
    /// Rewrites a leaf in place and recomputes its path to the root — one
    /// batch write.
    ///
    /// Only exists for [`Plain`](crate::mmr::Plain) and
    /// [`WithPeaks`](crate::mmr::WithPeaks) MMRs — the `Stacked` kind cannot
    /// be editable: unconstructible at the type level via
    /// [`EditableKind`], not just missing a
    /// constructor.
    ///
    /// `expected_current` gates the edit: pass the hash you believe the leaf
    /// currently holds (e.g. from [`Mmr::leaf_hash`]) to
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
        let new_hash = self.hasher.hash_leaf(element)?;
        self.update_hashed(leaf, new_hash, expected_current)
    }

    /// Clears a leaf in place: writes the hasher's genesis value and
    /// recomputes the path — the structure stays dense (no element removal,
    /// no compaction). Same scope rules and gating as [`Self::update`].
    ///
    /// # Errors
    ///
    /// As [`Self::update`].
    pub fn delete(
        &mut self,
        leaf: LeafIndex,
        expected_current: Option<H::Output>,
    ) -> Result<UpdateOutcome<H::Output>, MmrError<S>> {
        self.update_hashed(leaf, self.hasher.genesis(), expected_current)
    }
}

impl<H: Hasher, S: Store, K: Kind, Id: TreeId> Mmr<H, S, K, Nullifying, Id> {
    /// Marks `leaf` as no longer valid with a **shallow** record — the MMR
    /// data itself is untouched.
    ///
    /// Works for every kind, for any leaf index below the leaf count —
    /// including below a [`WithPeaks`](crate::mmr::WithPeaks) floor: records
    /// are index-keyed and need no content.
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
        let record = self.record_nullifier(leaf, NullifierDepth::Shallow)?;
        Ok(NullifyOutcome { leaf, record })
    }

    /// Overwrite semantics without breaking append-only storage: **shallow**
    /// nullification of the old leaf **and** append of `element` as a new
    /// leaf. The MMR grows by one leaf; the old position is invalid from the
    /// recorded size onward.
    ///
    /// The element is hashed **before** the nullifier record is written — a
    /// malformed element cannot nullify a leaf unrecoverably. The record and
    /// the append delta share this MMR's store, so they land in **one**
    /// atomic batch.
    ///
    /// # Errors
    ///
    /// [`MmrError::Hasher`] for malformed elements (nothing is written),
    /// [`MmrError::LeafOutOfRange`] for out-of-range leaves, store failures
    /// otherwise.
    pub fn replace_shallow(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let element_hash = self.hasher.hash_leaf(element)?;
        self.replace_hashed(leaf, element_hash, NullifierDepth::Shallow)
    }

    /// Borrowed view of this MMR's own nullifier records.
    #[must_use]
    pub fn nullifier_set(&self) -> NullifierSet<'_, S, Id> {
        NullifierSet {
            store: &self.store,
            id: self.id,
        }
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
    /// [`Plain`](crate::mmr::Plain) and [`Stacked`](crate::mmr::Stacked)
    /// only — a `WithPeaks` MMR cannot deep-nullify (compile-time, see
    /// [`DeepNullifiable`]).
    ///
    /// # Errors
    ///
    /// Store failures.
    pub fn nullify_deep(&mut self, leaf: LeafIndex) -> Result<NullifyOutcome, MmrError<S>> {
        let record = self.record_nullifier(leaf, NullifierDepth::Deep)?;
        Ok(NullifyOutcome { leaf, record })
    }

    /// **Deep** nullification of the old leaf **and** append of `element` —
    /// the deep variant of [`Self::replace_shallow`]. See
    /// [`Self::nullify_deep`] for record semantics.
    ///
    /// The element is hashed **before** the nullifier record is written — a
    /// malformed element cannot nullify a leaf unrecoverably. When this
    /// layer owns the value (no stack point below the leaf), the record and
    /// the append delta land in one atomic batch; when a sub-layer owns it,
    /// the deep record is a separate write in that sub-layer's store —
    /// **cross-store, not atomic** with the append (documented limitation,
    /// see the store atomicity contract).
    ///
    /// # Errors
    ///
    /// [`MmrError::Hasher`] for malformed elements (nothing is written),
    /// [`MmrError::LeafOutOfRange`] for out-of-range leaves, store failures
    /// otherwise.
    pub fn replace_deep(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let element_hash = self.hasher.hash_leaf(element)?;
        self.replace_hashed(leaf, element_hash, NullifierDepth::Deep)
    }
}
