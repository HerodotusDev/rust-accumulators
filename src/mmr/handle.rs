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
/// clean: `Mmr<PoseidonHasher, MyStore>`.
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
    /// Previous hash at this leaf (the structure is dense, so always
    /// occupied — `Option` mirrors the gate's shape).
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

    /// A stacked construction was rejected (draft `commit_as_stacked`).
    #[cfg(feature = "stacked_mmr")]
    #[error("invalid stack construction: {0}")]
    Stacking(#[source] super::stacked::InvalidSubViews),

    /// Proof verification could not be attempted.
    #[error("could not verify proof: {0}")]
    Verify(#[from] super::proof::VerifyError),
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
        /// Hasher passed to the constructor.
        supplied: &'static str,
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

/// Sibling resolver for [`Mmr::recompute_path`]: the base's `load_nodes`
/// for the handle, the overlay for drafts.
type NodeReader<'s, H, S> =
    dyn FnMut(&[NodeIndex]) -> Result<Vec<Option<<H as Hasher>::Output>>, MmrError<S>> + 's;

/// A recomputed edit path: the changed nodes (leaf first) with their new
/// hashes, plus the index of the containing peak in the cached peaks.
type PathChanges<H> = (Vec<(NodeIndex, <H as Hasher>::Output)>, usize);

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
            root: self.state.root(&self.hasher),
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
        let delta = super::state::apply_append_batch(&self.hasher, &self.state, &element_hashes);

        let mut batch = Batch::new();
        self.push_delta(&mut batch, &delta);
        self.store.write(batch).map_err(MmrError::Store)?;
        self.state = delta.state;

        Ok(AppendBatchOutcome {
            first_leaf,
            appended: LeafCount::new(element_hashes.len() as u64),
            root: self.state.root(&self.hasher),
        })
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
    /// store; sibling overlap across leaves is collapsed.
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
            self.check_nullified(leaf)?;
        }

        // Collect every path's node indexes; the pool is first-discovery
        // order so proofs are byte-comparable.
        let paths: Vec<Vec<PathStep>> = leaves
            .iter()
            .map(|leaf| sibling_path(*leaf, self.state.node_count))
            .collect();
        let (pool_indexes, pool_refs) = super::proof::build_sibling_pool(&paths);

        let element_indexes: Vec<NodeIndex> = leaves.iter().map(|leaf| leaf.node()).collect();
        let loaded_elements = self.load_nodes(&element_indexes)?;
        let loaded_pool = self.load_nodes(&pool_indexes)?;
        let missing = || {
            MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Nodes,
            })
        };

        Ok(MultiProof {
            element_hashes: loaded_elements
                .into_iter()
                .map(|value| value.ok_or_else(missing))
                .collect::<Result<Vec<_>, _>>()?,
            leaves,
            sibling_pool: loaded_pool
                .into_iter()
                .map(|value| value.ok_or_else(missing))
                .collect::<Result<Vec<_>, _>>()?,
            sibling_refs: pool_refs,
            peaks: Vec::clone(&self.state.peaks),
            root: self.state.root(&self.hasher),
            size: self.state.node_count,
        })
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

    /// Resolves the nullifier record for `leaf` across this MMR's layers.
    /// `Some(record)` means the leaf is nullified for this viewer.
    pub(crate) fn resolve_nullifier(
        &self,
        leaf: LeafIndex,
    ) -> Result<Option<NullifierRecord>, MmrError<S>> {
        // Own (topmost) records always resolve.
        let own = NullifierSet {
            store: &self.store,
            id: self.id,
        }
        .record(leaf)
        .map_err(MmrError::Nullifier)?;
        if own.is_some() {
            return Ok(own);
        }

        // Sub records resolve through each view's layer chain (own records
        // of the sub always; deeper layers under the pin-size rule).
        for sub in &self.subs {
            if let Some(record) = sub.resolve_nullifier(leaf).map_err(MmrError::Store)? {
                return Ok(Some(record));
            }
        }
        Ok(None)
    }

    /// Reads node hashes with layer routing: one batched read per distinct
    /// store, same-store layers merged, keys deduplicated per store.
    pub(crate) fn load_nodes(
        &self,
        nodes: &[NodeIndex],
    ) -> Result<Vec<Option<H::Output>>, MmrError<S>> {
        if self.subs.is_empty() {
            return Self::read_nodes(&self.store, self.id, nodes).map_err(MmrError::Store);
        }

        // Route each node to its layer, grouping requests per store. Each
        // sub-view routes internally through its own (possibly multi-layer)
        // chain; this handle's own layer handles everything above the pins.
        let mut router = super::stacked::NodeRouter::new();
        for (position, node) in nodes.iter().enumerate() {
            let mut covered = false;
            for sub in &self.subs {
                if node.get() <= sub.pinned_size().get() {
                    if let Some(layer) = sub.route(node.get()) {
                        router.route(layer.store_ref(), layer.id_ref(), *node, position);
                    }
                    covered = true;
                    break;
                }
            }
            if !covered {
                router.route(&self.store, self.id, *node, position);
            }
        }
        router.read(nodes.len()).map_err(MmrError::Store)
    }

    /// Batched node read from one store under one id.
    fn read_nodes(
        store: &S,
        id: Id,
        nodes: &[NodeIndex],
    ) -> Result<Vec<Option<H::Output>>, S::Error> {
        let encoded: Vec<Vec<u8>> = nodes
            .iter()
            .map(|node| keys::encode(&id, Table::Nodes, node.get()))
            .collect();
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        Ok(store
            .read(&refs)?
            .into_iter()
            .map(|value| value.and_then(|bytes| H::Output::from_bytes(&bytes)))
            .collect())
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
            record::hash_value(&delta.state.root(&self.hasher)),
        );
    }

    /// Recomputes the path from `leaf` upward with `new_leaf_hash`, returning
    /// the changed node values (leaf first) and the index of the containing
    /// peak in the cached peaks.
    ///
    /// `read` resolves sibling values — the base's `load_nodes` for the
    /// handle, the overlay for drafts.
    pub(crate) fn recompute_path(
        &self,
        leaf: LeafIndex,
        new_leaf_hash: H::Output,
        read: &mut NodeReader<'_, H, S>,
    ) -> Result<PathChanges<H>, MmrError<S>> {
        let path = sibling_path(leaf, self.state.node_count);
        let indexes: Vec<NodeIndex> = path.iter().map(|step| step.sibling).collect();
        // The leaf's own previous value is not needed for the recompute; only
        // siblings are. Request them in one batched read.
        let siblings = if indexes.is_empty() {
            Vec::new()
        } else {
            read(&indexes)?
        };

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

        let mut loaded = self.load_nodes(&[leaf.node()])?;
        let current = loaded.pop().flatten();
        if let Some(expected) = expected_current
            && current != Some(expected)
        {
            return Err(MmrError::UpdateMismatch { leaf });
        }

        let (changed, peak_index) =
            self.recompute_path(leaf, new_hash, &mut |nodes| self.load_nodes(nodes))?;
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
            previous: current,
            root: self.state.root(&self.hasher),
        })
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
            return Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from: LeafIndex::FIRST,
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
                let node = leaf.node().get();
                let mut owner = None;
                for sub in &self.subs {
                    if node <= sub.pinned_size().get() {
                        if let Some(layer) = sub.owner_of(node) {
                            owner = Some((layer.store_ref(), layer.id_ref()));
                        }
                        break;
                    }
                }
                let set = match owner {
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
    /// This is where the v0.5 "metadata forgets the padding flag" bug is
    /// structurally prevented: a mismatch is a hard error, not a silent
    /// divergence. Named per-mode variants: [`Self::open_editable`] /
    /// [`Self::open_nullifying`].
    ///
    /// # Errors
    ///
    /// [`MmrError::Corrupted`] for missing/mismatched metadata.
    pub fn open(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let (hasher, store, id, state) = Self::load(hasher, store, id, M::NAME)?;
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
    ) -> Result<Mmr<H, S, super::WithPeaks, M, Id>, MmrError<S>> {
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

        let plain = Self::create_with_state(hasher, store, id, MmrState::from_peaks(size, peaks))?;
        Ok(Mmr {
            hasher: plain.hasher,
            store: plain.store,
            id: plain.id,
            state: plain.state,
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        })
    }

    /// Shared genesis writer: persists metadata for `state` and returns the
    /// handle. Peaks-only seeds persist their peaks as node values so `open`
    /// reconstructs the state and proves above the floor.
    pub(crate) fn create_with_state(
        hasher: H,
        store: S,
        id: Id,
        state: MmrState<H>,
    ) -> Result<Self, MmrError<S>> {
        let mut batch = Batch::new();
        batch.put_owned(
            keys::encode(&id, Table::HasherInfo, 0),
            record::hasher_info(&hasher),
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

    /// Shared loader: reads and validates all persisted metadata.
    pub(crate) fn load(
        hasher: H,
        store: S,
        id: Id,
        declared_mode: &'static str,
    ) -> Result<(H, S, Id, MmrState<H>), MmrError<S>> {
        let metadata_keys: Vec<Vec<u8>> = [
            Table::HasherInfo,
            Table::Mode,
            Table::LeafCount,
            Table::NodeCount,
            Table::Root,
        ]
        .iter()
        .map(|table| keys::encode(&id, *table, 0))
        .collect();
        let refs: Vec<&[u8]> = metadata_keys.iter().map(Vec::as_slice).collect();
        let values = store.read(&refs).map_err(MmrError::Store)?;

        let missing = |table| MmrError::Corrupted(Corrupted::MissingRecord { table });
        let malformed = |table| MmrError::Corrupted(Corrupted::MalformedRecord { table });
        let value = |index: usize, table| -> Result<&[u8], MmrError<S>> {
            values
                .get(index)
                .and_then(Option::as_deref)
                .ok_or_else(|| missing(table))
        };

        // Hasher identity + config.
        let (stored_id, stored_config) = record::parse_hasher_info(value(0, Table::HasherInfo)?)
            .ok_or_else(|| malformed(Table::HasherInfo))?;
        if stored_id != hasher.id() || stored_config != hasher.config() {
            return Err(MmrError::Corrupted(Corrupted::HasherMismatch {
                stored: alloc::format!("{stored_id} ({stored_config})"),
                supplied: "",
            }));
        }

        // Mode.
        let stored_mode =
            record::parse_text(value(1, Table::Mode)?).ok_or_else(|| malformed(Table::Mode))?;
        if stored_mode != declared_mode {
            return Err(MmrError::Corrupted(Corrupted::ModeMismatch {
                stored: stored_mode,
                declared: declared_mode,
            }));
        }

        // Counters and their mutual consistency.
        let leaf_count = record::parse_counter(value(2, Table::LeafCount)?)
            .ok_or_else(|| malformed(Table::LeafCount))?;
        let node_count = record::parse_counter(value(3, Table::NodeCount)?)
            .ok_or_else(|| malformed(Table::NodeCount))?;
        let (leaf_count, node_count) = match state::checked_counters(leaf_count, node_count) {
            state::CounterCheck::Ok(leaves, nodes) => (leaves, nodes),
            state::CounterCheck::MalformedNodeCount => {
                return Err(malformed(Table::NodeCount));
            }
            state::CounterCheck::Mismatch => {
                return Err(MmrError::Corrupted(Corrupted::PeaksMismatch {
                    expected: node_count.count_ones() as usize,
                    found: leaf_count.count_ones() as usize,
                }));
            }
        };

        // Peaks from the node table.
        let peak_nodes = peaks_of(node_count);
        let peak_values = Self::read_nodes(&store, id, &peak_nodes).map_err(MmrError::Store)?;
        let peaks: Vec<H::Output> = peak_values
            .into_iter()
            .map(|value| value.ok_or_else(|| missing(Table::Nodes)))
            .collect::<Result<_, _>>()?;

        // Root check.
        let state = MmrState {
            leaf_count,
            node_count,
            peaks,
            provenance: Provenance::Full,
        };
        let stored_root = value(4, Table::Root)?;
        if record::hash_value(&state.root(&hasher)).as_slice() != stored_root {
            return Err(MmrError::Corrupted(Corrupted::RootMismatch));
        }

        Ok((hasher, store, id, state))
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
        Mmr::create(hasher, store, id)
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
        Mmr::open(hasher, store, id)
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
        Mmr::create(hasher, store, id)
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
        Mmr::open(hasher, store, id)
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
    /// Invalid sub-views ([`super::stacked::StackingError::SubViews`])
    /// or store failures.
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

        let mut handle = Mmr {
            hasher,
            store,
            id,
            state: MmrState::empty(),
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        };
        match handle.init_stack(subs) {
            Ok(()) => Ok(handle),
            Err(MmrError::Store(err)) => Err(super::stacked::StackingError::Store(err)),
            Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::Subviews,
            })) => Err(super::stacked::StackingError::SubViews(
                InvalidSubViews::Unrepresentable,
            )),
            Err(other) => unreachable!("stack initialization failed unexpectedly: {other}"),
        }
    }

    /// Shared stack bootstrap: reads routed peaks, persists genesis metadata
    /// and the sub-view record. Used by [`Self::stack`] and
    /// [`open_stacked`](super::stacked::open_stacked).
    pub(crate) fn init_stack(
        &mut self,
        subs: Vec<SubView<S, Id, H::Output>>,
    ) -> Result<(), MmrError<S>> {
        let top_start = subs.last().map_or(0, |sub| sub.pinned_size.get());

        // Install the sub-views first: the routed peak read below needs the
        // layer routing to find the pinned nodes.
        self.subs = subs;

        // Routed peak read across the layers.
        let peak_nodes = peaks_of(MmrSize::new_unchecked(top_start));
        let peaks: Vec<H::Output> = self
            .load_nodes(&peak_nodes)?
            .into_iter()
            .map(|value| {
                value.ok_or(MmrError::Corrupted(Corrupted::MissingRecord {
                    table: Table::Nodes,
                }))
            })
            .collect::<Result<_, _>>()?;

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
            record::hasher_info(&self.hasher),
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
            keys::encode(&self.id, Table::Root, 0),
            record::hash_value(&self.state.root(&self.hasher)),
        );
        batch.put_owned(
            keys::encode(&self.id, Table::Subviews, 0),
            super::stacked::encode_subviews(&layers).ok_or_else(|| {
                MmrError::Corrupted(Corrupted::MalformedRecord {
                    table: Table::Subviews,
                })
            })?,
        );
        self.store.write(batch).map_err(MmrError::Store)
    }
}

#[cfg(feature = "stacked_mmr")]
impl<H: Hasher, S: Store, M: Stackable, Id: TreeId> Mmr<H, S, super::Stacked, M, Id> {
    /// Re-open path shared with
    /// [`open_stacked`](super::stacked::open_stacked): validates metadata,
    /// then loads routed peaks for the reconstructed sub-views.
    pub(crate) fn open_stack(
        hasher: H,
        store: S,
        id: Id,
        subs: Vec<SubView<S, Id, H::Output>>,
    ) -> Result<Self, MmrError<S>> {
        let mut handle = Mmr {
            hasher,
            store,
            id,
            state: MmrState::empty(),
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        };

        // Metadata validation (the routed peaks need the subs, so they are
        // loaded after the sub-views are installed).
        let metadata_keys: Vec<Vec<u8>> = [
            Table::HasherInfo,
            Table::Mode,
            Table::LeafCount,
            Table::NodeCount,
            Table::Root,
        ]
        .iter()
        .map(|table| keys::encode(&handle.id, *table, 0))
        .collect();
        let refs: Vec<&[u8]> = metadata_keys.iter().map(Vec::as_slice).collect();
        let values = handle.store.read(&refs).map_err(MmrError::Store)?;
        let missing = |table| MmrError::Corrupted(Corrupted::MissingRecord { table });
        let get = |index: usize, table| -> Result<&[u8], MmrError<S>> {
            values
                .get(index)
                .and_then(Option::as_deref)
                .ok_or_else(|| missing(table))
        };

        let (stored_id, stored_config) = record::parse_hasher_info(get(0, Table::HasherInfo)?)
            .ok_or_else(|| {
                MmrError::Corrupted(Corrupted::MalformedRecord {
                    table: Table::HasherInfo,
                })
            })?;
        if stored_id != handle.hasher.id() || stored_config != handle.hasher.config() {
            return Err(MmrError::Corrupted(Corrupted::HasherMismatch {
                stored: alloc::format!("{stored_id} ({stored_config})"),
                supplied: "",
            }));
        }
        let stored_mode = record::parse_text(get(1, Table::Mode)?).ok_or_else(|| {
            MmrError::Corrupted(Corrupted::MalformedRecord { table: Table::Mode })
        })?;
        if stored_mode != M::NAME {
            return Err(MmrError::Corrupted(Corrupted::ModeMismatch {
                stored: stored_mode,
                declared: M::NAME,
            }));
        }
        let leaf_count = record::parse_counter(get(2, Table::LeafCount)?).ok_or_else(|| {
            MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::LeafCount,
            })
        })?;
        let node_count = record::parse_counter(get(3, Table::NodeCount)?).ok_or_else(|| {
            MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::NodeCount,
            })
        })?;
        // Same mutual-consistency gate as [`Mmr::load`] — a corrupted leaf
        // counter must not pass a stacked re-open that a plain re-open
        // rejects.
        let (leaf_count, node_count) = match state::checked_counters(leaf_count, node_count) {
            state::CounterCheck::Ok(leaves, nodes) => (leaves, nodes),
            state::CounterCheck::MalformedNodeCount => {
                return Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                    table: Table::NodeCount,
                }));
            }
            state::CounterCheck::Mismatch => {
                return Err(MmrError::Corrupted(Corrupted::PeaksMismatch {
                    expected: node_count.count_ones() as usize,
                    found: leaf_count.count_ones() as usize,
                }));
            }
        };

        handle.subs = subs;
        let peak_nodes = peaks_of(node_count);
        let peaks: Vec<H::Output> = handle
            .load_nodes(&peak_nodes)?
            .into_iter()
            .map(|value| value.ok_or_else(|| missing(Table::Nodes)))
            .collect::<Result<_, _>>()?;
        handle.state = MmrState {
            leaf_count,
            node_count,
            peaks,
            provenance: Provenance::Full,
        };

        if record::hash_value(&handle.state.root(&handle.hasher)).as_slice() != get(4, Table::Root)?
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
    /// # Errors
    ///
    /// As [`Self::nullify_shallow`] plus append errors.
    pub fn replace_shallow(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let nullified = self.nullify_shallow(leaf)?;
        let element_hash = self.hasher.hash_leaf(element)?;
        let appended = self.append_hashed(element_hash)?;
        Ok(ReplaceOutcome {
            root: appended.root,
            nullified: nullified.leaf,
            record: nullified.record,
            appended,
        })
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
    /// # Errors
    ///
    /// As [`Self::nullify_deep`] plus append errors.
    pub fn replace_deep(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let nullified = self.nullify_deep(leaf)?;
        let element_hash = self.hasher.hash_leaf(element)?;
        let appended = self.append_hashed(element_hash)?;
        Ok(ReplaceOutcome {
            root: appended.root,
            nullified: nullified.leaf,
            record: nullified.record,
            appended,
        })
    }
}
