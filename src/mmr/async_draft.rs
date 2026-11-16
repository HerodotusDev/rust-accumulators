//! The async draft: the sync [`Draft`](super::draft::Draft) overlay over
//! the async MMR shell.
//!
//! Same op-log semantics, same buffering rules, same commit contract — see
//! [`super::draft`] for the full documentation. This module shares the
//! sync draft's pure machinery (`DraftOp`, the [`Optimise`] fold) verbatim
//! and differs only in the fetch/commit plumbing: composed-view node reads
//! and the replay's writes go through the base's async store, exactly like
//! the sync/async handle shells split.
//!
//! A failed [`AsyncDraft::commit`] returns the draft (and its log) via
//! [`AsyncCommitFailure`]; a mid-commit failure can leave earlier store
//! segments applied (deep nullifier records cross stores), documented on
//! the sync draft too.

use super::AppendBatchOutcome;
use super::AppendOutcome;
use super::MmrError;
use super::async_mmr::AsyncMmr;
use super::draft::{CommitReport, DraftOp, Optimise, fold};
use super::kinds::{DeepNullifiable, EditableKind};
use super::layout::{LeafCount, MmrSize, NodeIndex, PathStep, Side, peaks_of, sibling_path};
use super::mode::{Editable, Mode, Nullifying, Stackable};
use super::nullifiers::{NullifierDepth, NullifierRecord};
use super::proof::MultiProof;
use super::state::{MmrState, Provenance};
use crate::hashers::{Hasher, HasherError};
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::LeafIndex;
use crate::store::AsyncStore;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// An in-memory draft over a base async MMR. Created with
/// [`AsyncMmr::start_draft`](super::async_mmr::AsyncMmr::start_draft); the
/// draft holds the base by mutable borrow so its commit can update the
/// base's cached state. See [`Draft`](super::draft::Draft) for the full
/// op-log contract.
pub struct AsyncDraft<'m, H: Hasher, S, K, M = super::AppendOnly, Id = AccumulatorId> {
    pub(crate) base: &'m mut AsyncMmr<H, S, K, M, Id>,
    pub(crate) ops: Vec<DraftOp<H::Output>>,
    /// Composed (base + log) state, maintained at buffer time.
    pub(crate) state: MmrState<H>,
    /// Current values of nodes written by the draft (appended nodes, edited
    /// paths) — read parity without touching the base.
    pub(crate) overlay: BTreeMap<u64, H::Output>,
    /// Leaves with a buffered nullification, mapped to the record the replay
    /// will write (see the sync draft).
    pub(crate) buffered_nullified: BTreeMap<LeafIndex, NullifierRecord>,
}

// Summary of the composed state; op-log/overlay internals are not rendered.
impl<H: Hasher, S, K, M, Id: TreeId> core::fmt::Debug for AsyncDraft<'_, H, S, K, M, Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsyncDraft")
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

impl<H: Hasher, S: AsyncStore, K: super::Kind, M: Mode, Id: TreeId> AsyncDraft<'_, H, S, K, M, Id> {
    /// Appends one element to the draft (in memory — no store writes).
    ///
    /// # Errors
    ///
    /// [`HasherError`] for malformed elements.
    pub fn append(&mut self, element: &[u8]) -> Result<AppendOutcome<H::Output>, HasherError> {
        let element_hash = self.base.hasher.hash_leaf(element)?;
        Ok(self.append_hashed(element_hash))
    }

    /// Appends many elements to the draft in memory. See
    /// [`Draft::append_batch`](super::draft::Draft::append_batch).
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
    /// composed view's provenance, which drafts never change.
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
    /// [`Draft::leaf_hash`](super::draft::Draft::leaf_hash).
    ///
    /// # Errors
    ///
    /// As the sync draft's, plus store failures.
    pub async fn leaf_hash(&self, leaf: LeafIndex) -> Result<Option<H::Output>, MmrError<S>> {
        self.check_provable(leaf)?;
        let mut loaded = self.resolve_nodes(&[leaf.node()]).await?;
        Ok(loaded.pop().flatten())
    }

    /// Inclusion proof over the composed (base + draft) view. See
    /// [`Draft::proof`](super::draft::Draft::proof).
    ///
    /// # Errors
    ///
    /// As the sync draft's.
    pub async fn proof(
        &self,
        leaf: LeafIndex,
    ) -> Result<super::proof::Proof<H::Output>, MmrError<S>> {
        self.check_provable(leaf)?;
        self.check_nullified(leaf).await?;

        let path = sibling_path(leaf, self.state.node_count);
        let mut indexes: Vec<NodeIndex> = Vec::with_capacity(path.len() + 1);
        indexes.push(leaf.node());
        indexes.extend(path.iter().map(|step| step.sibling));

        let loaded = self.resolve_nodes(&indexes).await?;
        let missing = || {
            MmrError::Corrupted(super::Corrupted::MissingRecord {
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
    #[must_use]
    pub fn peaks(&self) -> &[H::Output] {
        &self.state.peaks
    }

    /// Builds a multiproof for many leaves over the composed (base + draft)
    /// view with a deduplicated sibling pool. See
    /// [`Draft::multiproof`](super::draft::Draft::multiproof).
    ///
    /// # Errors
    ///
    /// As [`Self::proof`].
    pub async fn multiproof<I>(&self, leaves: I) -> Result<MultiProof<H::Output>, MmrError<S>>
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
                    return Err(MmrError::LeafNullified { leaf });
                }
            }
            let base_leaves: Vec<LeafIndex> = leaves
                .iter()
                .copied()
                .filter(|leaf| leaf.get() < self.base.state.leaf_count.get())
                .collect();
            let resolved = self.base.resolve_nullifiers(&base_leaves).await?;
            for (leaf, record) in base_leaves.iter().zip(&resolved) {
                if record.is_some() {
                    return Err(MmrError::LeafNullified { leaf: *leaf });
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
        let loaded = self.resolve_nodes(&indexes).await?;
        let (loaded_elements, loaded_pool) = loaded.split_at(element_indexes.len());
        let missing = || {
            MmrError::Corrupted(super::Corrupted::MissingRecord {
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

    /// Builds a consistency proof over the composed (base + draft) view.
    /// See [`Draft::consistency_proof`](super::draft::Draft::consistency_proof)
    /// for the composed-view semantics — the async twin differs only in the
    /// fetch plumbing.
    ///
    /// # Errors
    ///
    /// As the sync draft's.
    pub async fn consistency_proof(
        &self,
        prev_size: MmrSize,
    ) -> Result<super::proof::ConsistencyProof<H::Output>, MmrError<S>> {
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
                let loaded = self.resolve_nodes(&indexes).await?;
                super::proof::consistency_from_loaded(prev_size, current, &loaded, peak_count)
                    .map_err(MmrError::Corrupted)
            }
        }
    }

    /// Verifies a proof against the draft's *current* root (the composed
    /// base + draft view). Synchronous: pure over the proof and the
    /// composed state — no store, no await. See
    /// [`Draft::verify`](super::draft::Draft::verify).
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof is structurally inconsistent.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify(
        &self,
        proof: &super::proof::Proof<H::Output>,
        element: &[u8],
    ) -> Result<bool, MmrError<S>> {
        let valid = super::proof::verify_proof(&self.base.hasher, proof, element)?;
        Ok(valid && proof.root == self.root())
    }

    /// Verifies a multiproof against the draft's *current* root.
    /// Synchronous. See [`Draft::verify_multi`](super::draft::Draft::verify_multi).
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof or the element set is
    /// structurally inconsistent.
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
        let valid = super::proof::verify_multi_proof(&self.base.hasher, proof, elements)?;
        Ok(valid && proof.root == self.root())
    }

    /// Verifies a consistency proof whose target is the draft's *current*
    /// composed root. Synchronous. See
    /// [`Draft::verify_consistency`](super::draft::Draft::verify_consistency).
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof is structurally inconsistent.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify_consistency(
        &self,
        proof: &super::proof::ConsistencyProof<H::Output>,
        prev_root: H::Output,
    ) -> Result<bool, MmrError<S>> {
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
    fn check_provable(&self, leaf: LeafIndex) -> Result<(), MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get()
            || (leaf.get() < self.base.state.leaf_count.get() && !self.base.state.is_provable(leaf))
        {
            return Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from: self.base.state.provenance.first_provable_leaf(),
            });
        }
        Ok(())
    }

    /// Nullifier gate over the composed view: buffered nullifications resolve
    /// immediately (own records always do), base records through the base's
    /// layer resolution.
    async fn check_nullified(&self, leaf: LeafIndex) -> Result<(), MmrError<S>> {
        if M::NULLIFYING
            && (self.buffered_nullified.contains_key(&leaf)
                || self.base.resolve_nullifier(leaf).await?.is_some())
        {
            return Err(MmrError::LeafNullified { leaf });
        }
        Ok(())
    }

    /// Resolves node values over the composed view: draft overlay first,
    /// base (with layer routing) underneath.
    async fn resolve_nodes(
        &self,
        nodes: &[NodeIndex],
    ) -> Result<Vec<Option<H::Output>>, MmrError<S>> {
        let unresolved: Vec<NodeIndex> = nodes
            .iter()
            .copied()
            .filter(|node| !self.overlay.contains_key(&node.get()))
            .collect();
        let base_values = self.base.load_nodes(&unresolved).await?;
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
    async fn apply_edit(&mut self, leaf: LeafIndex, new_hash: H::Output) -> Result<(), MmrError<S>>
    where
        S: AsyncStore,
    {
        let path = sibling_path(leaf, self.state.node_count);
        let indexes: Vec<NodeIndex> = path.iter().map(|step| step.sibling).collect();
        let siblings = self.resolve_nodes(&indexes).await?;

        let missing = || {
            MmrError::Corrupted(super::Corrupted::MissingRecord {
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

impl<H: Hasher, S: AsyncStore, K: EditableKind, Id: TreeId> AsyncDraft<'_, H, S, K, Editable, Id> {
    /// Buffers an in-place rewrite of `leaf` (in memory — no store writes).
    /// See [`Draft::update`](super::draft::Draft::update) for the gate
    /// semantics (buffer-time on draft leaves, commit-time on base leaves).
    ///
    /// # Errors
    ///
    /// As the sync draft's.
    pub async fn update(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
        expected_current: Option<H::Output>,
    ) -> Result<(), MmrError<S>> {
        let new_hash = self.base.hasher.hash_leaf(element)?;
        self.buffer_edit(
            leaf,
            DraftOp::Update {
                leaf,
                new: new_hash,
                expected_current,
            },
        )
        .await
    }

    /// Buffers an in-place clear of `leaf`. See
    /// [`Draft::delete`](super::draft::Draft::delete).
    ///
    /// # Errors
    ///
    /// As [`Self::update`].
    pub async fn delete(
        &mut self,
        leaf: LeafIndex,
        expected_current: Option<H::Output>,
    ) -> Result<(), MmrError<S>> {
        self.buffer_edit(
            leaf,
            DraftOp::Delete {
                leaf,
                expected_current,
            },
        )
        .await
    }

    /// Shared edit buffering: scope check, draft-leaf gate evaluation,
    /// composed-state path recompute.
    async fn buffer_edit(
        &mut self,
        leaf: LeafIndex,
        mut op: DraftOp<H::Output>,
    ) -> Result<(), MmrError<S>> {
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
                    return Err(MmrError::UpdateMismatch { leaf });
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
        self.apply_edit(leaf, new_hash).await?;
        self.ops.push(op);
        Ok(())
    }
}

impl<H: Hasher, S: AsyncStore, K: super::Kind, Id: TreeId> AsyncDraft<'_, H, S, K, Nullifying, Id> {
    /// Buffers a **shallow** nullification (in memory — no store writes).
    /// Range-checked at buffer time; see
    /// [`Draft::nullify_shallow`](super::draft::Draft::nullify_shallow).
    ///
    /// # Errors
    ///
    /// [`MmrError::LeafOutOfRange`] when `leaf` is at or beyond the
    /// composed leaf count.
    pub fn nullify_shallow(&mut self, leaf: LeafIndex) -> Result<(), MmrError<S>> {
        self.buffer_nullify(leaf, NullifierDepth::Shallow)
    }

    /// The nullifier record for `leaf` over the composed (base + draft)
    /// view. See
    /// [`Draft::nullifier_record`](super::draft::Draft::nullifier_record).
    ///
    /// # Errors
    ///
    /// Base nullifier resolution failures ([`MmrError::Nullifier`]).
    pub async fn nullifier_record(
        &self,
        leaf: LeafIndex,
    ) -> Result<Option<NullifierRecord>, MmrError<S>> {
        if let Some(&record) = self.buffered_nullified.get(&leaf) {
            return Ok(Some(record));
        }
        self.base.resolve_nullifier(leaf).await
    }

    /// Buffers a **shallow** nullification of the old leaf **and** an append
    /// of the new element. See
    /// [`Draft::replace_shallow`](super::draft::Draft::replace_shallow).
    ///
    /// # Errors
    ///
    /// As [`Self::append`] and [`Self::nullify_shallow`].
    pub fn replace_shallow(&mut self, leaf: LeafIndex, element: &[u8]) -> Result<(), MmrError<S>> {
        self.nullify_shallow(leaf)?;
        self.append(element).map_err(MmrError::Hasher)?;
        Ok(())
    }

    /// Shared nullify buffering: composed range check. The rejection is
    /// [`MmrError::LeafOutOfRange`]: nullifier records are index-keyed, so
    /// only the range itself — not a provenance floor — rejects here.
    fn buffer_nullify(
        &mut self,
        leaf: LeafIndex,
        depth: NullifierDepth,
    ) -> Result<(), MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() {
            return Err(MmrError::LeafOutOfRange {
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

impl<H: Hasher, S: AsyncStore, K: DeepNullifiable, Id: TreeId>
    AsyncDraft<'_, H, S, K, Nullifying, Id>
{
    /// Buffers a **deep** nullification. Available only on bases that are
    /// [`Plain`](super::Plain) or [`Stacked`](super::Stacked) — a
    /// `WithPeaks` draft cannot deep-nullify (compile-time, see
    /// [`DeepNullifiable`]).
    ///
    /// Range-checked at buffer time, like [`Self::nullify_shallow`].
    ///
    /// # Errors
    ///
    /// [`MmrError::LeafOutOfRange`] when `leaf` is at or beyond the
    /// composed leaf count.
    pub fn nullify_deep(&mut self, leaf: LeafIndex) -> Result<(), MmrError<S>> {
        self.buffer_nullify(leaf, NullifierDepth::Deep)
    }

    /// Buffers a **deep** nullification of the old leaf **and** an append
    /// of the new element. See
    /// [`Draft::replace_deep`](super::draft::Draft::replace_deep).
    ///
    /// # Errors
    ///
    /// As [`Self::append`] and [`Self::nullify_deep`].
    pub fn replace_deep(&mut self, leaf: LeafIndex, element: &[u8]) -> Result<(), MmrError<S>> {
        self.nullify_deep(leaf)?;
        self.append(element).map_err(MmrError::Hasher)?;
        Ok(())
    }
}

impl<'m, H: Hasher, S: AsyncStore, K: super::Kind, M: Mode, Id: TreeId>
    AsyncDraft<'m, H, S, K, M, Id>
{
    /// Replays the buffered log into the base and updates its cached state.
    /// See [`Draft::commit`](super::draft::Draft::commit) — one batch write
    /// per store segment, `CommitFailure` returns the draft.
    ///
    /// # Errors
    ///
    /// As the sync draft's.
    #[expect(
        clippy::result_large_err,
        reason = "AsyncCommitFailure deliberately carries the full draft back; losing the log would be worse than the large error"
    )]
    pub async fn commit(self, optimise: Optimise) -> AsyncCommitResult<'m, H, S, K, M, Id> {
        let this = self;
        let ops = match optimise {
            Optimise::Off => Vec::clone(&this.ops),
            Optimise::On => fold::<H>(&this.ops, this.base.state.leaf_count),
        };

        let mut appended = 0_u64;
        let mut edits = 0_usize;
        let mut nullifications = 0_usize;
        let mut replay = AsyncBatchedReplay::default();
        for op in &ops {
            let applied = match op {
                DraftOp::Append(hash) => replay.append(this.base, *hash).await,
                DraftOp::Update {
                    leaf,
                    new,
                    expected_current,
                } => replay_edit(&mut replay, this.base, *leaf, *new, *expected_current).await,
                DraftOp::Delete {
                    leaf,
                    expected_current,
                } => {
                    let genesis = this.base.hasher.genesis();
                    replay_edit(&mut replay, this.base, *leaf, genesis, *expected_current).await
                }
                DraftOp::Nullify { leaf, depth } => replay.nullify(this.base, *leaf, *depth).await,
            };
            if let Err(error) = applied {
                return Err(AsyncCommitFailure { error, draft: this });
            }
            match op {
                DraftOp::Append(_) => appended += 1,
                DraftOp::Update { .. } | DraftOp::Delete { .. } => edits += 1,
                DraftOp::Nullify { .. } => nullifications += 1,
            }
        }
        if let Err(error) = replay.flush(this.base).await {
            return Err(AsyncCommitFailure { error, draft: this });
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

impl<'m, H: Hasher, S: AsyncStore + Clone, K: super::Kind, M: Stackable, Id: TreeId>
    AsyncDraft<'m, H, S, K, M, Id>
{
    /// Applies the log as a **new stacked layer** on top of the base instead
    /// of replaying it into the base. See
    /// [`Draft::commit_as_stacked`](super::draft::Draft::commit_as_stacked)
    /// — the new layer is a separate accumulator; `hasher`, `store`, and
    /// `id` are taken explicitly.
    ///
    /// # Errors
    ///
    /// As the sync draft's.
    #[expect(
        clippy::result_large_err,
        reason = "AsyncCommitFailure deliberately carries the full draft back; losing the log would be worse than the large error"
    )]
    pub async fn commit_as_stacked(
        self,
        hasher: H,
        store: S,
        id: Id,
        optimise: Optimise,
    ) -> AsyncStackedCommitResult<'m, H, S, K, M, Id> {
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
        subs.push(super::stacked::SubView::single_async(
            this.base.id,
            S::clone(&this.base.store),
            this.base.state.node_count,
        ));

        // Validate before anything is written: a rejection here must not
        // leave the log half-applied.
        if let Err(error) = super::stacked::validate_sub_views(&subs) {
            return Err(AsyncCommitFailure {
                error: MmrError::Stacking(error),
                draft: this,
            });
        }

        // The hasher's rendered identity is captured before `hasher` moves
        // into `stack` — the layer-hasher-mismatch arm reports it.
        let supplied = alloc::format!("{} ({})", hasher.id(), hasher.config());
        let mut stacked =
            match AsyncMmr::<H, S, super::Stacked, M, Id>::stack(hasher, store, id, subs).await {
                Ok(stacked) => stacked,
                Err(super::stacked::StackingError::Store(err)) => {
                    return Err(AsyncCommitFailure {
                        error: MmrError::Store(err),
                        draft: this,
                    });
                }
                Err(super::stacked::StackingError::SubViews(error)) => {
                    return Err(AsyncCommitFailure {
                        error: MmrError::Stacking(error),
                        draft: this,
                    });
                }
                Err(super::stacked::StackingError::UnrepresentableHasher) => {
                    return Err(AsyncCommitFailure {
                        error: MmrError::UnrepresentableHasher,
                        draft: this,
                    });
                }
                Err(super::stacked::StackingError::LayerHasherMismatch { stored }) => {
                    // Same finding `AsyncMmr::stack` reports as a corrupted
                    // hasher record.
                    return Err(AsyncCommitFailure {
                        error: MmrError::Corrupted(super::Corrupted::HasherMismatch {
                            stored,
                            supplied,
                        }),
                        draft: this,
                    });
                }
            };

        // Same batching contract as [`Self::commit`].
        let mut replay = AsyncBatchedReplay::default();
        for op in &ops {
            // Edits cannot exist here: they require an Editable base,
            // which cannot be pinned.
            let outcome = match op {
                DraftOp::Append(hash) => replay.append(&mut stacked, *hash).await,
                DraftOp::Update { leaf, .. } | DraftOp::Delete { leaf, .. } => replay
                    .flush(&mut stacked)
                    .await
                    .and_then(|()| Err(MmrError::UpdateMismatch { leaf: *leaf })),
                DraftOp::Nullify { leaf, depth } => {
                    replay.nullify(&mut stacked, *leaf, *depth).await
                }
            };
            if let Err(error) = outcome {
                return Err(AsyncCommitFailure { error, draft: this });
            }
        }
        if let Err(error) = replay.flush(&mut stacked).await {
            return Err(AsyncCommitFailure { error, draft: this });
        }

        Ok(stacked)
    }
}

/// Coalescing replay buffer for async draft commits — the async twin of the
/// sync draft's engine. Consecutive appends batch into **one** batched
/// append write, and each run of nullifications batches per target store;
/// the two queues never hold data at once, so each segment's nullifier
/// records see exactly the base state the sequential replay would have
/// given them.
struct AsyncBatchedReplay<H: Hasher> {
    appends: Vec<H::Output>,
    nullifies: Vec<(LeafIndex, NullifierDepth)>,
}

impl<H: Hasher> Default for AsyncBatchedReplay<H> {
    fn default() -> Self {
        Self {
            appends: Vec::new(),
            nullifies: Vec::new(),
        }
    }
}

impl<H: Hasher> AsyncBatchedReplay<H> {
    /// Buffers one append; a pending nullifier run is flushed first.
    async fn append<S: AsyncStore, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut AsyncMmr<H, S, K, M, Id>,
        hash: H::Output,
    ) -> Result<(), MmrError<S>> {
        self.flush_nullifies(base).await?;
        self.appends.push(hash);
        Ok(())
    }

    /// Buffers one nullification; pending appends are flushed first so the
    /// record's size-at-nullification matches the sequential replay.
    async fn nullify<S: AsyncStore, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut AsyncMmr<H, S, K, M, Id>,
        leaf: LeafIndex,
        depth: NullifierDepth,
    ) -> Result<(), MmrError<S>> {
        self.flush_appends(base).await?;
        self.nullifies.push((leaf, depth));
        Ok(())
    }

    /// Commits everything pending: appends as one batched write, nullifier
    /// records as one batched read + write per target store.
    async fn flush<S: AsyncStore, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut AsyncMmr<H, S, K, M, Id>,
    ) -> Result<(), MmrError<S>> {
        self.flush_appends(base).await?;
        self.flush_nullifies(base).await
    }

    async fn flush_appends<S: AsyncStore, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut AsyncMmr<H, S, K, M, Id>,
    ) -> Result<(), MmrError<S>> {
        if self.appends.is_empty() {
            return Ok(());
        }
        let hashes = core::mem::take(&mut self.appends);
        base.append_hashed_batch(&hashes).await.map(|_| ())
    }

    async fn flush_nullifies<S: AsyncStore, K: super::Kind, M: Mode, Id: TreeId>(
        &mut self,
        base: &mut AsyncMmr<H, S, K, M, Id>,
    ) -> Result<(), MmrError<S>> {
        if self.nullifies.is_empty() {
            return Ok(());
        }
        let requests = core::mem::take(&mut self.nullifies);
        base.record_nullifiers(&requests).await
    }
}

/// One replayed edit (update/delete): the pending append/nullifier run is
/// flushed first (so the edit's store write lands after it), then the edit
/// itself — short-circuiting on the flush failure, exactly like the
/// sequential replay.
async fn replay_edit<H: Hasher, S: AsyncStore, K: super::Kind, M: Mode, Id: TreeId>(
    replay: &mut AsyncBatchedReplay<H>,
    base: &mut AsyncMmr<H, S, K, M, Id>,
    leaf: LeafIndex,
    new_hash: H::Output,
    expected_current: Option<H::Output>,
) -> Result<(), MmrError<S>> {
    replay.flush(base).await?;
    base.update_hashed(leaf, new_hash, expected_current)
        .await
        .map(|_| ())
}

/// Result of an async draft [`AsyncDraft::commit`]: the report, or the
/// failure carrying the draft (and its buffered log) back.
pub type AsyncCommitResult<'m, H, S, K, M, Id> =
    Result<CommitReport<<H as Hasher>::Output>, AsyncCommitFailure<'m, H, S, K, M, Id>>;

/// Result of [`AsyncDraft::commit_as_stacked`]: the new stacked layer, or
/// the failure carrying the draft (and its buffered log) back.
pub type AsyncStackedCommitResult<'m, H, S, K, M, Id> =
    Result<AsyncMmr<H, S, super::Stacked, M, Id>, AsyncCommitFailure<'m, H, S, K, M, Id>>;

/// A failed [`AsyncDraft::commit`] / [`AsyncDraft::commit_as_stacked`] —
/// the async twin of [`CommitFailure`](super::draft::CommitFailure): the
/// error plus the draft back, so the buffered log is never silently lost to
/// a failed store write.
///
/// The draft may be *partially applied* when deep nullifier records were in
/// play (they cross stores and are not atomic with the rest) — inspect
/// [`Self::error`] before deciding to retry or [`AsyncDraft::discard`].
pub struct AsyncCommitFailure<'m, H: Hasher, S: AsyncStore, K, M, Id> {
    /// What went wrong.
    pub error: MmrError<S>,
    /// The draft with its (possibly partially applied) log.
    pub draft: AsyncDraft<'m, H, S, K, M, Id>,
}

impl<H: Hasher, S: AsyncStore + core::fmt::Debug, K, M, Id: TreeId> core::fmt::Debug
    for AsyncCommitFailure<'_, H, S, K, M, Id>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsyncCommitFailure")
            .field("error", &self.error)
            .field("draft", &self.draft)
            .finish()
    }
}
