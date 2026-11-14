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
use super::layout::{LeafCount, MmrSize, NodeIndex, PathStep, Side, peaks_of, sibling_path};
use super::mode::{Editable, Mode, Nullifying, Stackable};
use super::nullifiers::NullifierDepth;
use super::proof::MultiProof;
use super::state::MmrState;
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
    /// **Lost-update gates survive folding, fail-closed.** Gates on
    /// pre-existing leaves are preserved: a folded edit chain keeps the
    /// *earliest* gate of its chain, and an append+delete pair whose delete
    /// carries a gate is pre-checked at fold time — a gate that could not
    /// pass fails the commit up front. Gates on *draft-appended* leaves are
    /// trivially satisfied (the value is draft-local; no concurrent writer
    /// can exist) and fold away.
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
pub struct Draft<'m, H: Hasher, S, K, M = super::AppendOnly, Id = AccumulatorId> {
    pub(crate) base: &'m mut super::Mmr<H, S, K, M, Id>,
    pub(crate) ops: Vec<DraftOp<H::Output>>,
    /// Composed (base + log) state, maintained at buffer time.
    pub(crate) state: MmrState<H>,
    /// Current values of nodes written by the draft (appended nodes, edited
    /// paths) — read parity without touching the base.
    pub(crate) overlay: BTreeMap<u64, H::Output>,
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
        let mut first_leaf = None;
        let mut appended = 0_u64;
        for element in elements {
            let element_hash = self.base.hasher.hash_leaf(element.as_ref())?;
            let outcome = self.append_hashed(element_hash);
            if first_leaf.is_none() {
                first_leaf = Some(outcome.leaf);
            }
            appended += 1;
        }
        Ok(AppendBatchOutcome {
            first_leaf: first_leaf.unwrap_or_else(|| self.state.leaf_count.next_leaf()),
            appended: LeafCount::new(appended),
            root: self.root(),
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

    /// Draft root: base state composed with the buffered log, from memory.
    ///
    /// Infallible: composition folds [`Hasher::hash_pair`] calls, which are
    /// infallible by contract.
    #[must_use]
    pub fn root(&self) -> H::Output {
        self.state.root(&self.base.hasher)
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
        let mut leaves: Vec<LeafIndex> = leaves.into_iter().collect();
        leaves.sort_unstable();
        leaves.dedup();
        for &leaf in &leaves {
            self.check_provable(leaf)?;
            self.check_nullified(leaf)?;
        }

        let paths: Vec<Vec<PathStep>> = leaves
            .iter()
            .map(|leaf| sibling_path(*leaf, self.state.node_count))
            .collect();
        let (pool_indexes, pool_refs) = super::proof::build_sibling_pool(&paths);

        let element_indexes: Vec<NodeIndex> = leaves.iter().map(|leaf| leaf.node()).collect();
        let loaded_elements = self.resolve_nodes(&element_indexes)?;
        let loaded_pool = self.resolve_nodes(&pool_indexes)?;
        let missing = || {
            super::MmrError::Corrupted(super::Corrupted::MissingRecord {
                table: crate::store::keys::Table::Nodes,
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
            root: self.state.root(&self.base.hasher),
            size: self.state.node_count,
        })
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
        if M::NULLIFYING {
            let buffered = self
                .ops
                .iter()
                .any(|op| matches!(op, DraftOp::Nullify { leaf: target, .. } if *target == leaf));
            if buffered || self.base.resolve_nullifier(leaf)?.is_some() {
                return Err(super::MmrError::LeafNullified { leaf });
            }
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

impl<H: Hasher, S: Store, K: super::Kind, Id: TreeId> Draft<'_, H, S, K, Editable, Id> {
    /// Buffers an in-place rewrite of `leaf` (in memory — no store writes).
    ///
    /// `expected_current` is evaluated **at commit time** against the base's
    /// then-current state (lost-update gate between draft start and commit).
    ///
    /// # Errors
    ///
    /// [`HasherError`] for malformed elements,
    /// [`super::MmrError::UnprovableLeaf`] for out-of-scope leaves.
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

    /// Shared edit buffering: scope check, composed-state path recompute.
    fn buffer_edit(
        &mut self,
        leaf: LeafIndex,
        op: DraftOp<H::Output>,
    ) -> Result<(), super::MmrError<S>> {
        self.check_provable(leaf)?;
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
    /// [`super::MmrError::UnprovableLeaf`] when `leaf` is at or beyond the
    /// composed leaf count.
    pub fn nullify_shallow(&mut self, leaf: LeafIndex) -> Result<(), super::MmrError<S>> {
        self.buffer_nullify(leaf, NullifierDepth::Shallow)
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
        self.nullify_shallow(leaf)?;
        self.append(element).map_err(super::MmrError::Hasher)?;
        Ok(())
    }

    /// Shared nullify buffering: composed range check.
    fn buffer_nullify(
        &mut self,
        leaf: LeafIndex,
        depth: NullifierDepth,
    ) -> Result<(), super::MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() {
            return Err(super::MmrError::UnprovableLeaf {
                leaf,
                provable_from: LeafIndex::FIRST,
            });
        }
        self.ops.push(DraftOp::Nullify { leaf, depth });
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
    /// [`super::MmrError::UnprovableLeaf`] when `leaf` is at or beyond the
    /// composed leaf count.
    pub fn nullify_deep(&mut self, leaf: LeafIndex) -> Result<(), super::MmrError<S>> {
        self.buffer_nullify(leaf, NullifierDepth::Deep)
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
        self.nullify_deep(leaf)?;
        self.append(element).map_err(super::MmrError::Hasher)?;
        Ok(())
    }
}

impl<'m, H: Hasher, S: Store, K: super::Kind, M: Mode, Id: TreeId> Draft<'m, H, S, K, M, Id> {
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
        for op in &ops {
            if let Err(error) = apply(this.base, op) {
                return Err(CommitFailure { error, draft: this });
            }
            match op {
                DraftOp::Append(_) => appended += 1,
                DraftOp::Update { .. } | DraftOp::Delete { .. } => edits += 1,
                DraftOp::Nullify { .. } => nullifications += 1,
            }
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
            Store::locator(&this.base.store),
        ));

        // Validate before touching anything: the pins come from validated
        // handles, so a rejection here is a caller bug, but it must not leave
        // the log half-applied.
        if let Err(error) = super::stacked::validate_sub_views(&subs) {
            return Err(CommitFailure {
                error: super::MmrError::Stacking(error),
                draft: this,
            });
        }

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
            };

        for op in &ops {
            // Only appends and nullifications can exist for Stackable modes:
            // edits require an Editable base, which cannot be pinned.
            let outcome = match op {
                DraftOp::Append(hash) => stacked.append_hashed(*hash).map(|_| ()),
                DraftOp::Update { leaf, .. } | DraftOp::Delete { leaf, .. } => {
                    Err(super::MmrError::UpdateMismatch { leaf: *leaf })
                }
                DraftOp::Nullify { leaf, depth } => {
                    stacked.record_nullifier(*leaf, *depth).map(|_| ())
                }
            };
            if let Err(error) = outcome {
                return Err(CommitFailure { error, draft: this });
            }
        }

        Ok(stacked)
    }
}

/// Applies one planned op to the base.
fn apply<H: Hasher, S: Store, K: super::Kind, M: Mode, Id: TreeId>(
    base: &mut super::Mmr<H, S, K, M, Id>,
    op: &DraftOp<H::Output>,
) -> Result<(), super::MmrError<S>> {
    match op {
        DraftOp::Append(hash) => base.append_hashed(*hash).map(|_| ()),
        DraftOp::Update {
            leaf,
            new,
            expected_current,
        } => base
            .update_hashed(*leaf, *new, *expected_current)
            .map(|_| ()),
        DraftOp::Delete {
            leaf,
            expected_current,
        } => base
            .update_hashed(*leaf, base.hasher.genesis(), *expected_current)
            .map(|_| ()),
        DraftOp::Nullify { leaf, depth } => base.record_nullifier(*leaf, *depth).map(|_| ()),
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
/// sequentially).
fn fold<H: Hasher>(
    ops: &[DraftOp<H::Output>],
    base_leaf_count: LeafCount,
) -> Vec<DraftOp<H::Output>> {
    // Folded slots; `None` = erased (append skipped by a later delete/nullify).
    let mut folded: Vec<Option<DraftOp<H::Output>>> = Vec::with_capacity(ops.len());
    // Buffer-time leaf index → folded slot of the in-draft append, if any.
    let mut append_slot: BTreeMap<u64, usize> = BTreeMap::new();
    // Last folded slot touching a pre-existing leaf (edits/nullifies).
    let mut last_edit: BTreeMap<u64, usize> = BTreeMap::new();
    // Buffer-time leaves whose in-draft append was erased.
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
                    // In-draft appended leaf: rewrite the append's value.
                    // Gates fold away — the value is draft-local.
                    if let Some(&slot) = append_slot.get(&leaf_value)
                        && !erased.contains(&leaf_value)
                    {
                        folded[slot] = Some(DraftOp::Append(*new));
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
                expected_current,
            } => {
                let leaf_value = leaf.get();
                if leaf_value >= base_leaf_count.get() {
                    if let Some(&slot) = append_slot.get(&leaf_value)
                        && !erased.contains(&leaf_value)
                    {
                        if expected_current.is_some() {
                            // The gate refers to a draft-local value; keep
                            // both ops so it is evaluated fail-closed.
                            folded.push(Some(op.clone()));
                            last_edit.insert(leaf_value, folded.len() - 1);
                        } else {
                            // The append and the delete annihilate.
                            folded[slot] = None;
                            erased.insert(leaf_value);
                        }
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
                    // An append nullified in the same draft: skip both — the
                    // leaf never existed in any committed state.
                    if let Some(&slot) = append_slot.get(&leaf_value)
                        && !erased.contains(&leaf_value)
                    {
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
pub struct CommitFailure<'m, H: Hasher, S: Store, K, M, Id> {
    /// What went wrong.
    pub error: super::MmrError<S>,
    /// The draft with its (possibly partially applied) log.
    pub draft: Draft<'m, H, S, K, M, Id>,
}

impl<H: Hasher, S: Store, K, M, Id> CommitFailure<'_, H, S, K, M, Id> {
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
