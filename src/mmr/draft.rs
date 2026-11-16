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
//! [`Draft::commit`] the log into the base (replaying all actions),
//! [`Draft::discard`] it (consuming `self` makes use-after-discard
//! unrepresentable), or — for [`Stackable`] base modes —
//! [`Draft::commit_as_stacked`] apply the log as a new stacked layer on top
//! of the base. A `replace` buffers as its two ingredients (nullify + append)
//! so replay and folding see one primitive set.
//!
//! Replay has two strategies ([`Optimise`]): the default replays every
//! buffered action exactly as issued; the optimised fold collapses each
//! leaf's sequence to its net effect — an append erased by a later delete
//! appends nothing at all.
//!
//! A commit is atomic per store segment: a failure mid-commit can leave
//! earlier segments applied (deep nullifier records cross stores). A failed
//! commit returns the draft with its log via [`CommitFailure`].

use super::AppendBatchOutcome;
use super::AppendOutcome;
use super::kinds::{DeepNullifiable, EditableKind};
use super::layout::{LeafCount, MmrSize, NodeIndex, PathStep, Side, peaks_of, sibling_path};
use super::mode::{Editable, Mode, Nullifying, Stackable};
use super::nullifiers::{NullifierDepth, NullifierRecord};
use super::proof::MultiProof;
use super::state::{MmrState, Provenance};
use crate::hashers::{Hasher, HasherError};
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::{HashValue, LeafIndex};
use crate::store::Store;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// One buffered draft operation, in log order.
///
/// `replace` buffers as [`DraftOp::Nullify`] + [`DraftOp::Append`]; the log
/// only ever holds these four primitives.
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
        /// Lost-update gate: commit-time for pre-existing leaves,
        /// evaluated and stripped at buffer time for draft-appended
        /// leaves (see [`Draft::update`]).
        expected_current: Option<O>,
    },
    /// Clear a leaf in place.
    Delete {
        /// Target leaf.
        leaf: LeafIndex,
        /// Lost-update gate: commit-time for pre-existing leaves,
        /// evaluated and stripped at buffer time for draft-appended
        /// leaves (see [`Draft::update`]).
        expected_current: Option<O>,
    },
    /// Record a nullification.
    Nullify {
        /// Target leaf.
        leaf: LeafIndex,
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
    /// - an append erased by a later in-draft `delete` appends nothing (a
    ///   later edit re-occupies the leaf: the append survives with the new
    ///   value),
    /// - update chains collapse to the final value,
    /// - an append **nullified later in the same draft** skips both the
    ///   append and the nullifier record — the leaf never existed in any
    ///   committed state (a `Nullifying` draft has no edit ops, so nothing
    ///   can re-occupy the leaf afterwards),
    /// - nullifications of *pre-existing* leaves always apply: nullifiers
    ///   are external commitments (on-chain maps) and cannot be unsaid.
    ///
    /// **Lost-update gates survive folding, fail-closed.** Gates on
    /// *pre-existing* leaves are preserved: a folded edit chain keeps the
    /// *earliest* gate of its chain. Gates on *draft-appended* leaves are
    /// evaluated at buffer time against the draft-local value (no concurrent
    /// writer can observe a draft leaf) and stripped: a surviving gate would
    /// be evaluated against a rewritten value, or against a replay index
    /// shifted by annihilated appends — a wrong-leaf edit.
    ///
    /// The committed shape differs from [`Optimise::Off`]: erased appends
    /// lower the leaf count, so later appends shift to earlier indexes, and
    /// an append resurrected by a later edit re-enters at the end. With a
    /// base of 3 leaves, the buffered sequence `append(A)`, `delete(3)`,
    /// `append(B)` commits leaf 3 = `B`; under [`Optimise::Off`] the same
    /// log commits leaf 3 = `A`, leaf 4 = `B`. Pick this only when the
    /// skipped history is not load-bearing.
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
pub struct Draft<'m, H: Hasher, S, K, M = super::AppendOnly, Id = AccumulatorId> {
    pub(crate) base: &'m mut super::Mmr<H, S, K, M, Id>,
    pub(crate) ops: Vec<DraftOp<H::Output>>,
    /// Composed (base + log) state, maintained at buffer time.
    pub(crate) state: MmrState<H>,
    /// Current values of nodes written by the draft (appended nodes, edited
    /// paths) — read parity without touching the base.
    pub(crate) overlay: BTreeMap<u64, H::Output>,
    /// Leaves with a buffered nullification, mapped to the record the replay
    /// will write — the O(1) member check behind [`Self::check_nullified`]
    /// and the source for [`Self::nullifier_record`] (kept in lockstep with
    /// the log; only populated in [`Nullifying`] drafts).
    pub(crate) buffered_nullified: BTreeMap<LeafIndex, NullifierRecord>,
}

// Summary of the composed state; op-log/overlay internals are not rendered.
impl<H: Hasher, S, K, M, Id: TreeId> core::fmt::Debug for Draft<'_, H, S, K, M, Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Draft")
            .field("id", &self.base.id)
            .field("leaf_count", &self.state.leaf_count())
            .field("size", &self.state.node_count())
            .field("provenance", &self.state.provenance())
            .field("root", &self.state.root(&self.base.hasher))
            .field(
                "draft_len",
                &self
                    .state
                    .leaf_count
                    .get()
                    .saturating_sub(self.base.state.leaf_count.get()),
            )
            .finish_non_exhaustive()
    }
}

impl<H: Hasher, S: Store, K: super::Kind, M: Mode, Id: TreeId> Draft<'_, H, S, K, M, Id> {
    /// Appends one element to the draft (in memory — no store writes).
    ///
    /// # Errors
    ///
    /// [`HasherError`] for malformed elements.
    pub fn append(&mut self, element: &[u8]) -> Result<AppendOutcome<H::Output>, HasherError> {
        let element_hash = self.base.hasher.hash_leaf(element)?;
        Ok(self.append_hashed(element_hash))
    }

    /// Appends many elements to the draft in memory.
    ///
    /// Accepts anything iterable of byte-like items — `&[&[u8]]`,
    /// `Vec<Vec<u8>>`, iterators of `Bytes`, etc. One
    /// [`apply_append_batch`](super::state::apply_append_batch) pass — the
    /// root is derived once from the final state, not per element.
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
        let mut element_hashes = Vec::new();
        for element in elements {
            element_hashes.push(self.base.hasher.hash_leaf(element.as_ref())?);
        }
        let first_leaf = self.state.leaf_count.next_leaf();
        if element_hashes.is_empty() {
            return Ok(AppendBatchOutcome {
                first_leaf,
                appended: LeafCount::ZERO,
                root: self.root(),
            });
        }

        let delta =
            super::state::apply_append_batch(&self.base.hasher, &self.state, &element_hashes);
        for (node, hash) in &delta.nodes {
            self.overlay.insert(node.get(), *hash);
        }
        self.state = delta.state;
        self.ops
            .extend(element_hashes.iter().map(|hash| DraftOp::Append(*hash)));

        Ok(AppendBatchOutcome {
            first_leaf,
            appended: LeafCount::new(element_hashes.len() as u64),
            root: delta.root,
        })
    }

    /// In-memory append: folds the hash into the composed state.
    fn append_hashed(&mut self, element_hash: H::Output) -> AppendOutcome<H::Output> {
        let leaf = self.state.leaf_count.next_leaf();
        let delta = super::state::apply_append(&self.base.hasher, &self.state, element_hash);
        for (node, hash) in &delta.nodes {
            self.overlay.insert(node.get(), *hash);
        }
        self.state = delta.state;
        self.ops.push(DraftOp::Append(element_hash));

        AppendOutcome {
            leaf,
            node: leaf.node(),
            root: self.state.root(&self.base.hasher),
        }
    }

    /// The draft's id — the base handle's id (drafts never mint one).
    #[must_use]
    pub const fn id(&self) -> Id {
        self.base.id
    }

    /// Provenance: full history or peaks-only (with the seed size) — the
    /// composed view's provenance, which drafts never change (delegates to
    /// the base handle).
    #[must_use]
    pub const fn provenance(&self) -> Provenance {
        self.base.provenance()
    }

    /// Draft root: base state composed with the buffered log, from memory.
    ///
    /// Infallible: composition only folds [`Hasher::hash_pair`] calls,
    /// which cannot fail.
    #[must_use]
    pub fn root(&self) -> H::Output {
        self.state.root(&self.base.hasher)
    }

    /// The stored hash of a leaf over the composed (base + draft) view, if
    /// the leaf is occupied and readable. See
    /// [`Mmr::leaf_hash`](super::Mmr::leaf_hash).
    ///
    /// Draft-appended leaves resolve through the overlay; base leaves
    /// through one batched read per distinct store. Also the cheap way to
    /// source `expected_current` gates. Returns
    /// [`MmrError::UnprovableLeaf`](super::MmrError::UnprovableLeaf) below a
    /// [`WithPeaks`](crate::mmr::WithPeaks) provenance floor (the value
    /// cannot be known, distinct from an unoccupied leaf's `None`).
    ///
    /// # Errors
    ///
    /// As [`Mmr::leaf_hash`](super::Mmr::leaf_hash), plus store failures.
    pub fn leaf_hash(&self, leaf: LeafIndex) -> Result<Option<H::Output>, super::MmrError<S>> {
        self.check_provable(leaf)?;
        let mut loaded = self.resolve_nodes(&[leaf.node()])?;
        Ok(loaded.pop().flatten())
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
    /// nullifiers ([`super::MmrError::LeafNullified`]) or store failures.
    pub fn proof(
        &self,
        leaf: LeafIndex,
    ) -> Result<super::proof::Proof<H::Output>, super::MmrError<S>> {
        self.check_provable(leaf)?;
        self.check_nullified(leaf)?;

        let path = sibling_path(leaf, self.state.node_count);
        let mut indexes: Vec<NodeIndex> = Vec::with_capacity(path.len() + 1);
        indexes.push(leaf.node());
        indexes.extend(path.iter().map(|step| step.sibling));

        let loaded = self.resolve_nodes(&indexes)?;
        let missing = || {
            super::MmrError::Corrupted(super::Corrupted::MissingRecord {
                table: crate::store::keys::Table::Nodes,
            })
        };
        let leaf_hash = loaded[0].ok_or_else(missing)?;
        let siblings: Vec<H::Output> = loaded[1..]
            .iter()
            .map(|value| value.ok_or_else(missing))
            .collect::<Result<_, _>>()?;

        Ok(super::proof::Proof {
            leaf,
            element_hash: leaf_hash,
            siblings,
            peaks: Vec::clone(&self.state.peaks),
            root: self.state.root(&self.base.hasher),
            size: self.state.node_count,
        })
    }

    /// Number of leaves appended in this draft so far (draft-only — excludes
    /// the base; see [`Self::leaf_count`] for the composed view).
    #[must_use]
    pub fn draft_len(&self) -> LeafCount {
        LeafCount::new(
            self.state
                .leaf_count
                .get()
                .saturating_sub(self.base.state.leaf_count.get()),
        )
    }

    /// Number of leaves in the composed (base + draft) view — no store access.
    #[must_use]
    pub const fn leaf_count(&self) -> LeafCount {
        self.state.leaf_count
    }

    /// Total node count of the composed (base + draft) view.
    #[must_use]
    pub const fn size(&self) -> MmrSize {
        self.state.node_count
    }

    /// Current peaks of the composed (base + draft) view, left to right.
    ///
    /// Computed in memory: the base's cached peaks folded through the buffered
    /// log — no store access, no clone.
    #[must_use]
    pub fn peaks(&self) -> &[H::Output] {
        &self.state.peaks
    }

    /// Builds a multiproof for many leaves over the composed (base + draft)
    /// view with a deduplicated sibling pool.
    ///
    /// Accepts any iterable of leaf indexes. Base leaves resolve through the
    /// base's stores (one batched read per distinct store for nodes and
    /// nullifiers alike); draft leaves resolve through the log.
    ///
    /// # Errors
    ///
    /// As [`Self::proof`].
    pub fn multiproof<I>(&self, leaves: I) -> Result<MultiProof<H::Output>, super::MmrError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let mut leaves: Vec<LeafIndex> = leaves.into_iter().collect();
        leaves.sort_unstable();
        leaves.dedup();
        for &leaf in &leaves {
            self.check_provable(leaf)?;
        }
        if M::NULLIFYING {
            for &leaf in &leaves {
                if self.buffered_nullified.contains_key(&leaf) {
                    return Err(super::MmrError::LeafNullified { leaf });
                }
            }
            let base_leaves: Vec<LeafIndex> = leaves
                .iter()
                .copied()
                .filter(|leaf| leaf.get() < self.base.state.leaf_count.get())
                .collect();
            let resolved = self.base.resolve_nullifiers(&base_leaves)?;
            for (leaf, record) in base_leaves.iter().zip(&resolved) {
                if record.is_some() {
                    return Err(super::MmrError::LeafNullified { leaf: *leaf });
                }
            }
        }

        let paths: Vec<Vec<PathStep>> = leaves
            .iter()
            .map(|leaf| sibling_path(*leaf, self.state.node_count))
            .collect();
        let (pool_indexes, pool_refs) = super::proof::build_sibling_pool(&paths);

        let element_indexes: Vec<NodeIndex> = leaves.iter().map(|leaf| leaf.node()).collect();
        let mut indexes = Vec::with_capacity(element_indexes.len() + pool_indexes.len());
        indexes.extend_from_slice(&element_indexes);
        indexes.extend_from_slice(&pool_indexes);
        let loaded = self.resolve_nodes(&indexes)?;
        let (loaded_elements, loaded_pool) = loaded.split_at(element_indexes.len());
        let missing = || {
            super::MmrError::Corrupted(super::Corrupted::MissingRecord {
                table: crate::store::keys::Table::Nodes,
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
            root: self.state.root(&self.base.hasher),
            size: self.state.node_count,
        })
    }

    /// Builds a consistency proof over the composed (base + draft) view:
    /// the composed view at `prev_size` — an earlier node count of the same
    /// node space — is a prefix of the current composed view. Verify with
    /// [`verify_consistency_proof`](super::proof::verify_consistency_proof);
    /// the verifier needs only the hasher and the two roots.
    ///
    /// Semantics mirror [`Mmr::consistency_proof`](super::Mmr::consistency_proof)
    /// exactly, with the draft's composed resolver standing in for the
    /// store: the earlier peaks and the bridge nodes resolve through the
    /// same overlay-over-base read every draft proof uses. Draft reads
    /// serve only the *current* composed view — there is no historical
    /// pinning — so a buffered update or delete rewrites the values a
    /// prefix proof carries, exactly as the base handle's own in-place
    /// edits do on the committed side: the prefix statement is about the
    /// node values the composed view serves *now*. Prefixes reaching into
    /// the draft's appends (sizes above the base's node count) resolve
    /// entirely through the overlay; the base's provenance floor still
    /// gates `prev_size`; the degenerate pairs (`prev_size == size`, and
    /// `prev_size == 0`) are served from the composed peaks with no store
    /// access. Nullifiers do not participate: a consistency proof is a
    /// statement about the structure's prefixes, not about leaf validity —
    /// buffered nullifications change no node values and no records are
    /// consulted.
    ///
    /// [`Optimise`] is deliberately absent from the read path: the composed
    /// state is the buffer-time fold of the log in order, whichever replay
    /// strategy commits it later — a folded log can commit a *different*
    /// (smaller) shape, so a pre-commit proof commits the composed view,
    /// not the post-commit one.
    ///
    /// # Errors
    ///
    /// [`super::MmrError::InvalidPrevSize`] for a `prev_size` outside the
    /// provable range, [`super::MmrError::Corrupted`] when a required node
    /// is missing, store failures otherwise.
    pub fn consistency_proof(
        &self,
        prev_size: MmrSize,
    ) -> Result<super::proof::ConsistencyProof<H::Output>, super::MmrError<S>> {
        let current = self.state.node_count;
        let floor = match self.base.state.provenance {
            Provenance::Full => MmrSize::ZERO,
            Provenance::FromPeaks { size_at_creation } => size_at_creation,
        };
        match super::proof::consistency_plan(prev_size, current, floor, &self.state.peaks)? {
            super::proof::ConsistencyPlan::Ready(proof) => Ok(proof),
            super::proof::ConsistencyPlan::Fetch {
                indexes,
                peak_count,
            } => {
                // One composed read: the earlier peaks, then the bridge
                // nodes — split positionally.
                let loaded = self.resolve_nodes(&indexes)?;
                super::proof::consistency_from_loaded(prev_size, current, &loaded, peak_count)
                    .map_err(super::MmrError::Corrupted)
            }
        }
    }

    /// Verifies a proof against the draft's *current* root (the composed
    /// base + draft view). For standalone verification — no draft instance,
    /// e.g. in a verifier process — use [`super::proof::verify_proof`], which
    /// checks the proof against its own commitment.
    ///
    /// # Errors
    ///
    /// [`super::MmrError::Verify`] when the proof is structurally inconsistent.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify(
        &self,
        proof: &super::proof::Proof<H::Output>,
        element: &[u8],
    ) -> Result<bool, super::MmrError<S>> {
        let valid = super::proof::verify_proof(&self.base.hasher, proof, element)?;
        Ok(valid && proof.root == self.root())
    }

    /// Verifies a multiproof against the draft's *current* root.
    ///
    /// `elements` must align positionally with the proof's leaves.
    ///
    /// # Errors
    ///
    /// [`super::MmrError::Verify`] when the proof or the element set is
    /// structurally inconsistent.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify_multi<I>(
        &self,
        proof: &MultiProof<H::Output>,
        elements: I,
    ) -> Result<bool, super::MmrError<S>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let valid = super::proof::verify_multi_proof(&self.base.hasher, proof, elements)?;
        Ok(valid && proof.root == self.root())
    }

    /// Verifies a consistency proof whose target is the draft's *current*
    /// composed root. `prev_root` is the caller's trusted anchor for the
    /// earlier state — obtained from wherever that state was
    /// authenticated; a draft cannot recompute a historical root because
    /// it serves only the current composed view. The structural check is
    /// the standalone
    /// [`verify_consistency_proof`](super::proof::verify_consistency_proof).
    ///
    /// # Errors
    ///
    /// [`super::MmrError::Verify`] when the proof is structurally
    /// inconsistent.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify_consistency(
        &self,
        proof: &super::proof::ConsistencyProof<H::Output>,
        prev_root: H::Output,
    ) -> Result<bool, super::MmrError<S>> {
        let valid = super::proof::verify_consistency_proof(
            &self.base.hasher,
            proof,
            prev_root,
            self.root(),
        )?;
        Ok(valid)
    }

    /// Whether `leaf` is provable in the composed view: inside the composed
    /// leaf count, and (for base leaves) above the base's provenance floor.
    fn check_provable(&self, leaf: LeafIndex) -> Result<(), super::MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get()
            || (leaf.get() < self.base.state.leaf_count.get() && !self.base.state.is_provable(leaf))
        {
            return Err(super::MmrError::UnprovableLeaf {
                leaf,
                provable_from: self.base.state.provenance.first_provable_leaf(),
            });
        }
        Ok(())
    }

    /// Nullifier gate over the composed view: buffered nullifications resolve
    /// immediately (own records always do), base records through the base's
    /// layer resolution.
    fn check_nullified(&self, leaf: LeafIndex) -> Result<(), super::MmrError<S>> {
        if M::NULLIFYING
            && (self.buffered_nullified.contains_key(&leaf)
                || self.base.resolve_nullifier(leaf)?.is_some())
        {
            return Err(super::MmrError::LeafNullified { leaf });
        }
        Ok(())
    }

    /// Resolves node values over the composed view: draft overlay first,
    /// base (with layer routing) underneath.
    fn resolve_nodes(
        &self,
        nodes: &[NodeIndex],
    ) -> Result<Vec<Option<H::Output>>, super::MmrError<S>> {
        let unresolved: Vec<NodeIndex> = nodes
            .iter()
            .copied()
            .filter(|node| !self.overlay.contains_key(&node.get()))
            .collect();
        let base_values = self.base.load_nodes(&unresolved)?;
        let mut base_iter = base_values.into_iter();
        Ok(nodes
            .iter()
            .map(|node| match self.overlay.get(&node.get()) {
                Some(hash) => Some(*hash),
                None => base_iter.next().flatten(),
            })
            .collect())
    }

    /// Recomputes an edited leaf's path over the composed state, updating the
    /// overlay and the cached peaks. Siblings resolve through
    /// [`Self::resolve_nodes`].
    fn apply_edit(&mut self, leaf: LeafIndex, new_hash: H::Output) -> Result<(), super::MmrError<S>>
    where
        S: Store,
    {
        let path = sibling_path(leaf, self.state.node_count);
        let indexes: Vec<NodeIndex> = path.iter().map(|step| step.sibling).collect();
        let siblings = self.resolve_nodes(&indexes)?;

        let missing = || {
            super::MmrError::Corrupted(super::Corrupted::MissingRecord {
                table: crate::store::keys::Table::Nodes,
            })
        };
        let mut hash = new_hash;
        let mut node = leaf.node();
        self.overlay.insert(node.get(), hash);
        for (step, sibling) in path.iter().zip(&siblings) {
            let sibling = sibling.ok_or_else(missing)?;
            hash = match step.side {
                Side::Left => self.base.hasher.hash_pair(sibling, hash),
                Side::Right => self.base.hasher.hash_pair(hash, sibling),
            };
            node = node.parent().ok_or_else(missing)?;
            self.overlay.insert(node.get(), hash);
        }

        let peaks = peaks_of(self.state.node_count);
        let peak_index = peaks
            .iter()
            .position(|peak| peak.get() == node.get())
            .ok_or_else(missing)?;
        self.state.peaks[peak_index] = hash;
        Ok(())
    }
}

impl<H: Hasher, S: Store, K: EditableKind, Id: TreeId> Draft<'_, H, S, K, Editable, Id> {
    /// Buffers an in-place rewrite of `leaf` (in memory — no store writes).
    ///
    /// `expected_current` gates the edit, fail-closed: on a *pre-existing*
    /// leaf it is evaluated at commit time against the base's then-current
    /// state (lost-update gate between draft start and commit); on a
    /// *draft-appended* leaf it is evaluated here against the draft-local
    /// value (no concurrent writer can observe a draft leaf) and the gate
    /// never reaches the replay.
    ///
    /// # Errors
    ///
    /// [`HasherError`] for malformed elements,
    /// [`super::MmrError::UnprovableLeaf`] for out-of-scope leaves,
    /// [`super::MmrError::UpdateMismatch`] for a failing draft-leaf gate.
    pub fn update(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
        expected_current: Option<H::Output>,
    ) -> Result<(), super::MmrError<S>> {
        let new_hash = self.base.hasher.hash_leaf(element)?;
        self.buffer_edit(
            leaf,
            DraftOp::Update {
                leaf,
                new: new_hash,
                expected_current,
            },
        )
    }

    /// Buffers an in-place clear of `leaf`. See [`Self::update`].
    ///
    /// # Errors
    ///
    /// As [`Self::update`].
    pub fn delete(
        &mut self,
        leaf: LeafIndex,
        expected_current: Option<H::Output>,
    ) -> Result<(), super::MmrError<S>> {
        self.buffer_edit(
            leaf,
            DraftOp::Delete {
                leaf,
                expected_current,
            },
        )
    }

    /// Shared edit buffering: scope check, draft-leaf gate evaluation,
    /// composed-state path recompute.
    fn buffer_edit(
        &mut self,
        leaf: LeafIndex,
        mut op: DraftOp<H::Output>,
    ) -> Result<(), super::MmrError<S>> {
        self.check_provable(leaf)?;
        // Draft-leaf gates are evaluated now and stripped: the value is
        // draft-local, and a surviving gate would be re-evaluated against a
        // rewritten value or a replay index shifted by annihilated appends.
        if leaf.get() >= self.base.state.leaf_count.get() {
            let gate = match &op {
                DraftOp::Update {
                    expected_current, ..
                }
                | DraftOp::Delete {
                    expected_current, ..
                } => *expected_current,
                _ => unreachable!("buffer_edit only receives edits"),
            };
            if let Some(expected) = gate {
                let current = self.overlay.get(&leaf.node().get()).copied();
                if current != Some(expected) {
                    return Err(super::MmrError::UpdateMismatch { leaf });
                }
            }
            match &mut op {
                DraftOp::Update {
                    expected_current, ..
                }
                | DraftOp::Delete {
                    expected_current, ..
                } => *expected_current = None,
                _ => unreachable!("buffer_edit only receives edits"),
            }
        }
        let new_hash = match &op {
            DraftOp::Update { new, .. } => *new,
            DraftOp::Delete { .. } => self.base.hasher.genesis(),
            _ => unreachable!("buffer_edit only receives edits"),
        };
        self.apply_edit(leaf, new_hash)?;
        self.ops.push(op);
        Ok(())
    }
}

impl<H: Hasher, S: Store, K: super::Kind, Id: TreeId> Draft<'_, H, S, K, Nullifying, Id> {
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
    /// [`super::MmrError::LeafOutOfRange`] when `leaf` is at or beyond the
    /// composed leaf count.
    pub fn nullify_shallow(&mut self, leaf: LeafIndex) -> Result<(), super::MmrError<S>> {
        self.buffer_nullify(leaf, NullifierDepth::Shallow)
    }

    /// The nullifier record for `leaf` over the composed (base + draft)
    /// view: a buffered nullification resolves immediately — with exactly
    /// the record its replay writes (a shallow record's size is the composed
    /// size at buffer time, which is the size at its replay point); otherwise
    /// the base's layer resolution decides. `None` when the leaf is not
    /// nullified. Mirrors the handle's
    /// [`NullifierSet::record`](crate::mmr::NullifierSet::record).
    ///
    /// The composed view is the buffer-time one: an append-nullify pair on a
    /// draft leaf folded away by [`Optimise::On`] writes no record at commit,
    /// while this query — like every draft read — still reports the buffered
    /// record.
    ///
    /// # Errors
    ///
    /// Base nullifier resolution failures
    /// ([`super::MmrError::Nullifier`]).
    pub fn nullifier_record(
        &self,
        leaf: LeafIndex,
    ) -> Result<Option<NullifierRecord>, super::MmrError<S>> {
        if let Some(&record) = self.buffered_nullified.get(&leaf) {
            return Ok(Some(record));
        }
        self.base.resolve_nullifier(leaf)
    }

    /// Buffers a **shallow** nullification of the old leaf **and** an append
    /// of the new element at the composed view's next leaf index — the
    /// draft's `replace`; the old position keeps its index and is nullified.
    ///
    /// # Errors
    ///
    /// As [`Self::append`] and [`Self::nullify_shallow`].
    pub fn replace_shallow(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<(), super::MmrError<S>> {
        self.nullify_shallow(leaf)?;
        self.append(element).map_err(super::MmrError::Hasher)?;
        Ok(())
    }

    /// Shared nullify buffering: composed range check. The rejection is
    /// [`super::MmrError::LeafOutOfRange`]: nullifier records are
    /// index-keyed, so only the range itself — not a provenance floor —
    /// rejects here.
    fn buffer_nullify(
        &mut self,
        leaf: LeafIndex,
        depth: NullifierDepth,
    ) -> Result<(), super::MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() {
            return Err(super::MmrError::LeafOutOfRange {
                leaf,
                leaf_count: self.state.leaf_count,
            });
        }
        self.ops.push(DraftOp::Nullify { leaf, depth });
        // Records only strengthen (see [`super::nullifiers`]): a deep
        // buffer overrides an earlier shallow one, among shallows the
        // first — smallest — size wins.
        let candidate = match depth {
            NullifierDepth::Shallow => NullifierRecord::Shallow {
                at: self.state.node_count,
            },
            NullifierDepth::Deep => NullifierRecord::Deep,
        };
        self.buffered_nullified
            .entry(leaf)
            .and_modify(|existing| {
                if !existing.strength_over(candidate) {
                    *existing = candidate;
                }
            })
            .or_insert(candidate);
        Ok(())
    }
}

impl<H: Hasher, S: Store, K: DeepNullifiable, Id: TreeId> Draft<'_, H, S, K, Nullifying, Id> {
    /// Buffers a **deep** nullification. Available only on bases that are
    /// [`Plain`](crate::mmr::Plain) or [`Stacked`](crate::mmr::Stacked) — a
    /// `WithPeaks` draft cannot deep-nullify (compile-time, see
    /// [`DeepNullifiable`]).
    ///
    /// Range-checked at buffer time, like [`Self::nullify_shallow`].
    ///
    /// # Errors
    ///
    /// [`super::MmrError::LeafOutOfRange`] when `leaf` is at or beyond the
    /// composed leaf count.
    pub fn nullify_deep(&mut self, leaf: LeafIndex) -> Result<(), super::MmrError<S>> {
        self.buffer_nullify(leaf, NullifierDepth::Deep)
    }

    /// Buffers a **deep** nullification of the old leaf **and** an append
    /// of the new element at the composed view's next leaf index. See
    /// [`Self::nullify_deep`] for availability.
    ///
    /// # Errors
    ///
    /// As [`Self::append`] and [`Self::nullify_deep`].
    pub fn replace_deep(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<(), super::MmrError<S>> {
        self.nullify_deep(leaf)?;
        self.append(element).map_err(super::MmrError::Hasher)?;
        Ok(())
    }
}

impl<'m, H: Hasher, S: Store, K: super::Kind, M: Mode, Id: TreeId> Draft<'m, H, S, K, M, Id> {
    /// Replays the buffered log into the base and updates its cached state.
    ///
    /// **One batch write per store segment**: consecutive appends coalesce
    /// into a single batched append
    /// ([`apply_append_batch`](super::state::apply_append_batch)), and each
    /// run of nullifications commits as one batched read + one batched write
    /// per target store (see [`Optimise`] for replay strategies). An edit,
    /// or an alternation between appends and nullifications, flushes what is
    /// pending — the write count is one per segment, not one per operation.
    /// **Deep** nullifier records are written to the owning sub-MMR's store,
    /// so a commit touching them is not atomic as a whole: a failure after
    /// earlier segments applied leaves those segments applied.
    ///
    /// Consumes the draft. On failure the draft — with its log — comes back
    /// inside [`CommitFailure::draft`]; inspect the error before retrying,
    /// and prefer [`Self::discard`] over a blind re-commit.
    ///
    /// # Errors
    ///
    /// [`CommitFailure`] wrapping store failures and apply-time rejections:
    /// an edit below a `WithPeaks` provenance floor
    /// ([`super::MmrError::UnprovableLeaf`]), a missing node record
    /// ([`super::MmrError::Corrupted`]), or
    /// [`super::MmrError::UpdateMismatch`] from a lost-update gate.
    #[expect(
        clippy::result_large_err,
        reason = "CommitFailure deliberately carries the full draft back; losing the log would be worse than the large error"
    )]
    pub fn commit(self, optimise: Optimise) -> CommitResult<'m, H, S, K, M, Id> {
        let this = self;
        let ops = match optimise {
            Optimise::Off => Vec::clone(&this.ops),
            Optimise::On => fold::<H>(&this.ops, this.base.state.leaf_count),
        };

        let mut appended = 0_u64;
        let mut edits = 0_usize;
        let mut nullifications = 0_usize;
        let mut replay = BatchedReplay::default();
        for op in &ops {
            let applied = match op {
                DraftOp::Append(hash) => replay.append(this.base, *hash),
                DraftOp::Update {
                    leaf,
                    new,
                    expected_current,
                } => replay.flush(this.base).and_then(|()| {
                    this.base
                        .update_hashed(*leaf, *new, *expected_current)
                        .map(|_| ())
                }),
                DraftOp::Delete {
                    leaf,
                    expected_current,
                } => replay.flush(this.base).and_then(|()| {
                    this.base
                        .update_hashed(*leaf, this.base.hasher.genesis(), *expected_current)
                        .map(|_| ())
                }),
                DraftOp::Nullify { leaf, depth } => replay.nullify(this.base, *leaf, *depth),
            };
            if let Err(error) = applied {
                return Err(CommitFailure { error, draft: this });
            }
            match op {
                DraftOp::Append(_) => appended += 1,
                DraftOp::Update { .. } | DraftOp::Delete { .. } => edits += 1,
                DraftOp::Nullify { .. } => nullifications += 1,
            }
        }
        if let Err(error) = replay.flush(this.base) {
            return Err(CommitFailure { error, draft: this });
        }

        Ok(CommitReport {
            appended: LeafCount::new(appended),
            edits,
            nullifications,
            root: this.base.state.root(&this.base.hasher),
        })
    }

    /// Throws the draft and its buffered log away.
    ///
    /// Consuming `self` makes use-after-discard unrepresentable.
    pub fn discard(self) {}
}

impl<'m, H: Hasher, S: Store + Clone, K: super::Kind, M: Stackable, Id: TreeId>
    Draft<'m, H, S, K, M, Id>
{
    /// Applies the log as a **new stacked layer** on top of the base instead
    /// of replaying it into the base.
    ///
    /// Only exists for [`Stackable`] base modes: a draft on an
    /// [`Editable`] base cannot commit as a stack — the new layer would
    /// pin an editable MMR (compile-time).
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
    #[expect(
        clippy::result_large_err,
        reason = "CommitFailure deliberately carries the full draft back; losing the log would be worse than the large error"
    )]
    pub fn commit_as_stacked(
        self,
        hasher: H,
        store: S,
        id: Id,
        optimise: Optimise,
    ) -> StackedCommitResult<'m, H, S, K, M, Id> {
        let this = self;
        let ops = match optimise {
            Optimise::Off => Vec::clone(&this.ops),
            Optimise::On => fold::<H>(&this.ops, this.base.state.leaf_count),
        };

        // The base becomes the bottom-most pinned layer of the new stack; a
        // stacked base contributes its own sub-views first.
        let mut subs: Vec<super::stacked::SubView<S, Id, H::Output>> = Vec::new();
        subs.extend(
            this.base
                .subs
                .iter()
                .map(super::stacked::SubView::relayered_clone),
        );
        subs.push(super::stacked::SubView::single(
            this.base.id,
            S::clone(&this.base.store),
            this.base.state.node_count,
        ));

        // Validate before anything is written: a rejection here must not
        // leave the log half-applied.
        if let Err(error) = super::stacked::validate_sub_views(&subs) {
            return Err(CommitFailure {
                error: super::MmrError::Stacking(error),
                draft: this,
            });
        }

        // The hasher's rendered identity is captured before `hasher` moves
        // into `stack` — the layer-hasher-mismatch arm reports it.
        let supplied = alloc::format!("{} ({})", hasher.id(), hasher.config());
        let mut stacked =
            match super::Mmr::<H, S, super::Stacked, M, Id>::stack(hasher, store, id, subs) {
                Ok(stacked) => stacked,
                Err(super::stacked::StackingError::Store(err)) => {
                    return Err(CommitFailure {
                        error: super::MmrError::Store(err),
                        draft: this,
                    });
                }
                Err(super::stacked::StackingError::SubViews(error)) => {
                    return Err(CommitFailure {
                        error: super::MmrError::Stacking(error),
                        draft: this,
                    });
                }
                Err(super::stacked::StackingError::UnrepresentableHasher) => {
                    return Err(CommitFailure {
                        error: super::MmrError::UnrepresentableHasher,
                        draft: this,
                    });
                }
                Err(super::stacked::StackingError::LayerHasherMismatch { stored }) => {
                    // Same finding `Mmr::stack` reports as a corrupted
                    // hasher record.
                    return Err(CommitFailure {
                        error: super::MmrError::Corrupted(super::Corrupted::HasherMismatch {
                            stored,
                            supplied,
                        }),
                        draft: this,
                    });
                }
            };

        // Same batching contract as [`Self::commit`].
        let mut replay = BatchedReplay::default();
        for op in &ops {
            // Edits cannot exist here: they require an Editable base,
            // which cannot be pinned.
            let outcome = match op {
                DraftOp::Append(hash) => replay.append(&mut stacked, *hash),
                DraftOp::Update { leaf, .. } | DraftOp::Delete { leaf, .. } => replay
                    .flush(&mut stacked)
                    .and_then(|()| Err(super::MmrError::UpdateMismatch { leaf: *leaf })),
                DraftOp::Nullify { leaf, depth } => replay.nullify(&mut stacked, *leaf, *depth),
            };
            if let Err(error) = outcome {
                return Err(CommitFailure { error, draft: this });
            }
        }
        if let Err(error) = replay.flush(&mut stacked) {
            return Err(CommitFailure { error, draft: this });
        }

        Ok(stacked)
    }
}

/// Coalescing replay buffer for draft commits ([`Draft::commit`] and
/// [`Draft::commit_as_stacked`]): consecutive appends batch into **one**
/// batched append write, and each run of nullifications batches per target
/// store. The two queues never hold data at once — an arriving append
/// flushes the pending nullifier run first, and an arriving nullification
/// flushes the pending appends first — so each segment's nullifier records
/// see exactly the base state (and the "size at nullification") the
/// sequential replay would have given them.
struct BatchedReplay<H: Hasher> {
    appends: Vec<H::Output>,
    nullifies: Vec<(LeafIndex, NullifierDepth)>,
}

impl<H: Hasher> Default for BatchedReplay<H> {
    fn default() -> Self {
        Self {
            appends: Vec::new(),
            nullifies: Vec::new(),
        }
    }
}

impl<H: Hasher> BatchedReplay<H> {
    /// Buffers one append; a pending nullifier run is flushed first.
    fn append<S: Store, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut super::Mmr<H, S, K, M, Id>,
        hash: H::Output,
    ) -> Result<(), super::MmrError<S>> {
        self.flush_nullifies(base)?;
        self.appends.push(hash);
        Ok(())
    }

    /// Buffers one nullification; pending appends are flushed first so the
    /// record's size-at-nullification matches the sequential replay.
    fn nullify<S: Store, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut super::Mmr<H, S, K, M, Id>,
        leaf: LeafIndex,
        depth: NullifierDepth,
    ) -> Result<(), super::MmrError<S>> {
        self.flush_appends(base)?;
        self.nullifies.push((leaf, depth));
        Ok(())
    }

    /// Commits everything pending: appends as one batched write, nullifier
    /// records as one batched read + write per target store.
    fn flush<S: Store, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut super::Mmr<H, S, K, M, Id>,
    ) -> Result<(), super::MmrError<S>> {
        self.flush_appends(base)?;
        self.flush_nullifies(base)
    }

    fn flush_appends<S: Store, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut super::Mmr<H, S, K, M, Id>,
    ) -> Result<(), super::MmrError<S>> {
        if self.appends.is_empty() {
            return Ok(());
        }
        let hashes = core::mem::take(&mut self.appends);
        base.append_hashed_batch(&hashes).map(|_| ())
    }

    fn flush_nullifies<S: Store, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut super::Mmr<H, S, K, M, Id>,
    ) -> Result<(), super::MmrError<S>> {
        if self.nullifies.is_empty() {
            return Ok(());
        }
        let requests = core::mem::take(&mut self.nullifies);
        base.record_nullifiers(&requests)
    }
}

/// The lost-update gate carried by a folded edit op (update/delete).
///
/// # Panics
///
/// If `op` is not an edit — only edits carry gates, by construction.
fn edit_gate<O: HashValue>(op: &DraftOp<O>) -> Option<O> {
    match op {
        DraftOp::Update {
            expected_current, ..
        }
        | DraftOp::Delete {
            expected_current, ..
        } => *expected_current,
        _ => unreachable!("only edits carry gates"),
    }
}

/// Folds one edit (update/delete) of a pre-existing leaf onto its folded
/// chain: an existing edit chain collapses to `retarget(gate)` — the chain's
/// final value with its earliest gate — otherwise the edit starts a new chain.
fn collapse_edit<O: HashValue>(
    folded: &mut Vec<Option<DraftOp<O>>>,
    last_edit: &mut BTreeMap<u64, usize>,
    leaf_value: u64,
    op: &DraftOp<O>,
    retarget: impl FnOnce(Option<O>) -> DraftOp<O>,
) {
    if let Some(&slot) = last_edit.get(&leaf_value)
        && matches!(
            &folded[slot],
            Some(DraftOp::Update { .. } | DraftOp::Delete { .. })
        )
    {
        // Chain collapse: final value, earliest gate.
        #[expect(
            clippy::expect_used,
            reason = "last_edit is maintained in lockstep with folded slot occupancy"
        )]
        let slot_op = folded[slot]
            .as_ref()
            .expect("last_edit only indexes present slots");
        folded[slot] = Some(retarget(edit_gate(slot_op)));
    } else {
        folded.push(Some(op.clone()));
        last_edit.insert(leaf_value, folded.len() - 1);
    }
}

/// Folds the log to its net effect ([`Optimise::On`]).
///
/// `base_leaf_count` splits pre-existing leaves (indexes stay stable) from
/// draft-appended leaves (whose folded indexes shift down as appends are
/// erased — folded appends carry no leaf index at all; replay assigns them
/// sequentially, so surviving appends replay in log order).
///
/// Draft-leaf ops arrive gate-free (evaluated and stripped in
/// `buffer_edit`), so the fold reduces to pure value transitions: an edit
/// rewrites the pending append's value, a delete/nullify annihilates it,
/// and a later update re-occupies an annihilated leaf (the append
/// resurrects with the new value).
///
/// Crate-internal: the async draft's commit reuses this fold verbatim —
/// the net-effect semantics are store-independent.
pub(crate) fn fold<H: Hasher>(
    ops: &[DraftOp<H::Output>],
    base_leaf_count: LeafCount,
) -> Vec<DraftOp<H::Output>> {
    // Folded slots; `None` = erased (append skipped by a later delete/nullify).
    let mut folded: Vec<Option<DraftOp<H::Output>>> = Vec::with_capacity(ops.len());
    // Buffer-time leaf index → folded slot of the in-draft append, if any.
    let mut append_slot: BTreeMap<u64, usize> = BTreeMap::new();
    // Last folded slot touching a pre-existing leaf (edits/nullifies).
    let mut last_edit: BTreeMap<u64, usize> = BTreeMap::new();
    // Buffer-time leaves whose in-draft append was annihilated.
    let mut erased: BTreeSet<u64> = BTreeSet::new();
    // Buffer-time leaf index of the next append.
    let mut next_leaf = base_leaf_count.get();

    for op in ops {
        match op {
            DraftOp::Append(_) => {
                append_slot.insert(next_leaf, folded.len());
                next_leaf += 1;
                folded.push(Some(op.clone()));
            }
            DraftOp::Update { leaf, new, .. } => {
                let leaf_value = leaf.get();
                if leaf_value >= base_leaf_count.get() {
                    // Draft-appended leaf: rewrite the pending append's
                    // value; after an annihilating delete, re-occupy the
                    // leaf (the append resurrects with the new value).
                    if let Some(&slot) = append_slot.get(&leaf_value) {
                        folded[slot] = Some(DraftOp::Append(*new));
                    } else if erased.remove(&leaf_value) {
                        folded.push(Some(DraftOp::Append(*new)));
                        append_slot.insert(leaf_value, folded.len() - 1);
                    }
                    continue;
                }
                collapse_edit(&mut folded, &mut last_edit, leaf_value, op, |gate| {
                    DraftOp::Update {
                        leaf: *leaf,
                        new: *new,
                        expected_current: gate,
                    }
                });
            }
            DraftOp::Delete {
                leaf,
                expected_current: _,
            } => {
                let leaf_value = leaf.get();
                if leaf_value >= base_leaf_count.get() {
                    // Gate-free by construction (stripped at buffer time):
                    // the append and the delete annihilate.
                    if let Some(slot) = append_slot.remove(&leaf_value) {
                        folded[slot] = None;
                        erased.insert(leaf_value);
                    }
                    continue;
                }
                // Chain collapse to the delete; the chain keeps its earliest
                // gate.
                collapse_edit(&mut folded, &mut last_edit, leaf_value, op, |gate| {
                    DraftOp::Delete {
                        leaf: *leaf,
                        expected_current: gate,
                    }
                });
            }
            DraftOp::Nullify { leaf, depth } => {
                let leaf_value = leaf.get();
                if leaf_value >= base_leaf_count.get() {
                    // An append nullified in the same draft: skip both —
                    // the leaf never existed in any committed state.
                    // (Nullifying drafts have no edit ops, so nothing can
                    // re-occupy the leaf afterwards.)
                    if let Some(slot) = append_slot.remove(&leaf_value) {
                        folded[slot] = None;
                        erased.insert(leaf_value);
                    }
                    continue;
                }
                fold_nullify(&mut folded, &mut last_edit, leaf_value, *leaf, *depth, op);
            }
        }
    }

    folded.into_iter().flatten().collect()
}

/// Folds a nullification of a pre-existing leaf. Records only strengthen:
/// deep upgrades shallow; shallow on shallow keeps the first (most
/// restrictive) record.
fn fold_nullify<O: HashValue>(
    folded: &mut Vec<Option<DraftOp<O>>>,
    last_edit: &mut BTreeMap<u64, usize>,
    leaf_value: u64,
    leaf: LeafIndex,
    depth: NullifierDepth,
    op: &DraftOp<O>,
) {
    if let Some(&slot) = last_edit.get(&leaf_value)
        && matches!(&folded[slot], Some(DraftOp::Nullify { .. }))
    {
        if depth == NullifierDepth::Deep {
            folded[slot] = Some(DraftOp::Nullify {
                leaf,
                depth: NullifierDepth::Deep,
            });
        }
        // Shallow over an existing record: keep the first (most restrictive)
        // one.
    } else {
        folded.push(Some(op.clone()));
        last_edit.insert(leaf_value, folded.len() - 1);
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
///
/// `Debug` (a state summary) makes `Result::unwrap` usable on
/// [`CommitResult`]:
///
/// ```
/// # #[cfg(feature = "draft_mmr")]
/// # fn commit_result_unwraps() {
/// use accumulators::hashers::KeccakSolHasher;
/// use accumulators::ids::AccumulatorId;
/// use accumulators::mmr::{Mmr, Optimise};
/// use accumulators::store::memory::InMemoryStore;
///
/// let mut mmr: Mmr<KeccakSolHasher, _> =
///     Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO).unwrap();
/// let mut draft = mmr.start_draft();
/// draft.append(b"element").unwrap();
/// let report = draft.commit(Optimise::Off).unwrap();
/// assert_eq!(report.appended.get(), 1);
/// # }
/// ```
pub struct CommitFailure<'m, H: Hasher, S: Store, K, M, Id> {
    /// What went wrong.
    pub error: super::MmrError<S>,
    /// The draft with its (possibly partially applied) log.
    pub draft: Draft<'m, H, S, K, M, Id>,
}

impl<H: Hasher, S: Store + core::fmt::Debug, K, M, Id: TreeId> core::fmt::Debug
    for CommitFailure<'_, H, S, K, M, Id>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CommitFailure")
            .field("error", &self.error)
            .field("draft", &self.draft)
            .finish()
    }
}
