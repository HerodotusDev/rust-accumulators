//! The async shell over the same pure [`super::state`] core.
//!
//! Mirrors [`super::Mmr`] method-for-method, generic over
//! [`AsyncStore`] instead of
//! [`Store`](crate::store::Store). All algorithms live in the state
//! core (sync, pure), so each method is "fetch state → pure transform → one
//! batch write"; the residual duplication is the fetch/commit plumbing
//! itself (the metadata load/validate sequence), kept parallel to the sync
//! loader because the store contracts differ.
//!
#![cfg_attr(
    feature = "draft_mmr",
    doc = "Full surface parity with the sync shell: the stacked machinery\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "(`pin`/`stack`/`open_stacked` — re-open through\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "[`AsyncRetrievable`]), the draft overlay\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "([`AsyncDraft`](super::async_draft::AsyncDraft) over the same op-log core\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "as the sync [`Draft`](super::Draft)), and the\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "[`AsyncNullifierSet`] accessor all exist here. The async `pin` is\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "synchronous like the sync one (no store access — it clones the backend\n"
)]
#![cfg_attr(
    feature = "draft_mmr",
    doc = "handle and captures the locator); `stack` and `open_stacked` await\n"
)]
#![cfg_attr(feature = "draft_mmr", doc = "their store reads/writes.\n")]
//!
//! Errors are unified with the sync shell: [`MmrError`] is generic over
//! [`Storage`](crate::store::Storage), which both
//! [`Store`](crate::store::Store) and [`AsyncStore`] require as a
//! supertrait. No wrapper types, no duplicated error enums, and a backend
//! implementing both contracts reports the same error type through either.
//!
//! Send-bounds: the shell's futures are `Send` when the type parameters and
//! their auto traits propagate into them. For the `&self` methods (proofs,
//! verification, leaf reads) the future borrows `self`, which requires
//! `S: Sync`, `H: Sync` and `Id: Sync` on top of each parameter's `Send`;
//! the `&mut self` methods (appends, edits, nullifications) additionally
//! require the values they move — `H::Output` — to be `Send`/`Sync`
//! (the [`HashValue`] trait carries no
//! Send/Sync supertraits, so they must be required explicitly). The full
//! per-method set — `S: AsyncStore + Send + Sync + 'static`,
//! `H: Hasher + Send + Sync` with `H::Output: Send + Sync`,
//! `Id: TreeId + Send + Sync` — is asserted by a compile-time test
//! (`tests/async_mmr.rs`); construct the handle with those bounds to spawn
//! its methods on a multi-thread runtime.
//!
//! Note on runtimes: the trait uses native async-fn-in-trait; no
//! `async-trait` boxing anywhere. `no_std` targets use the sync
//! [`Mmr`](super::Mmr) with a sync store instead. Distinct stores in a
//! stacked MMR are read concurrently: the per-store batches (same grouping
//! as the sync shell) run as joined plain futures with the sequential error
//! identity — see the crate-internal fan-out helper.

#[cfg(feature = "stacked_mmr")]
use super::kinds::SingleLayerKind;
use super::kinds::{DeepNullifiable, EditableKind};
use super::layout::{
    LeafCount, MmrSize, NodeIndex, PathStep, Side, bag_peaks, peaks_of, root_from, sibling_path,
};
#[cfg(feature = "stacked_mmr")]
use super::mode::Stackable;
use super::mode::{Editable, Mode, Nullifying};
use super::nullifiers::{
    AsyncNullifierSet, NullifierDepth, NullifierError, NullifierRecord, nullify_record_async,
    read_records_async,
};
use super::proof::{MultiProof, Proof};
use super::stacked::parse_node_value;
#[cfg(feature = "stacked_mmr")]
use super::stacked::{
    InvalidSubViews, LayerView, SubView, first_layer_hasher_mismatch_async, validate_sub_views,
};
use super::state::Provenance;
use super::{
    AppendBatchOutcome, AppendOutcome, Kind, MmrError, NullifyOutcome, ReplaceOutcome,
    UpdateOutcome, fanout,
};
use crate::hashers::Hasher;
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::{HashValue, LeafIndex};
#[cfg(feature = "stacked_mmr")]
use crate::store::AsyncRetrievable;
use crate::store::{AsyncStore, Batch, keys, keys::Table, record};
use alloc::boxed::Box;
#[cfg(feature = "draft_mmr")]
use alloc::collections::BTreeMap;
use alloc::vec;
use alloc::vec::Vec;

/// One batched nullifier read from one sub-layer store: the keys to read
/// there and, per key, the position it fills in the result plus the pin
/// size of the consulted layer.
struct AsyncLayerRead<'a, S> {
    store: &'a S,
    keys: Vec<Vec<u8>>,
    targets: Vec<(usize, u64)>,
}

/// One batched nullifier write for one target store: pre-encoded keys and
/// the records to write under them. Only the async draft replay's batched
/// commit uses it.
#[cfg(feature = "draft_mmr")]
struct AsyncRecordTarget<'a, S> {
    store: &'a S,
    keys: Vec<Vec<u8>>,
    records: Vec<NullifierRecord>,
}

/// One routed group's batched node read, parsed positionally — the single
/// fan-out branch of [`AsyncMmr::load_nodes`](super::async_mmr::AsyncMmr).
async fn read_group<S: AsyncStore, O: HashValue>(
    group: &super::stacked::RouteGroup<'_, S>,
) -> Result<Vec<Option<O>>, MmrError<S>> {
    let refs: Vec<&[u8]> = group.keys.iter().map(Vec::as_slice).collect();
    group
        .store
        .read(&refs)
        .await
        .map_err(MmrError::Store)?
        .into_iter()
        .map(parse_node_value)
        .collect()
}

/// Parses one store's raw nullifier values positionally; a present-but-
/// unparsable record is corruption, never "not nullified" (fail-open).
fn parse_nullifier_values<S: crate::store::Storage>(
    values: Vec<Option<Vec<u8>>>,
) -> Result<Vec<Option<NullifierRecord>>, MmrError<S>> {
    values
        .into_iter()
        .map(|value| match value {
            None => Ok(None),
            Some(bytes) => NullifierRecord::parse(&bytes)
                .map(Some)
                .ok_or(MmrError::Nullifier(NullifierError::MalformedRecord)),
        })
        .collect()
}

/// An async MMR handle. Semantics identical to [`Mmr`](super::Mmr) — see that
/// type for the full method contract, including the mode and id axes.
pub struct AsyncMmr<H: Hasher, S, K = super::Plain, M = super::AppendOnly, Id = AccumulatorId> {
    pub(crate) hasher: H,
    pub(crate) store: S,
    pub(crate) id: Id,
    pub(crate) state: super::state::MmrState<H>,
    /// Pinned sub-views — populated only for the [`Stacked`](crate::mmr::Stacked)
    /// kind; always empty otherwise.
    pub(crate) subs: Vec<super::stacked::SubView<S, Id, H::Output>>,
    pub(crate) _kind: core::marker::PhantomData<fn() -> K>,
    pub(crate) _mode: core::marker::PhantomData<fn() -> M>,
}

// State summary only: the store and sub-views are never rendered.
impl<H: Hasher, S, K, M, Id: TreeId> core::fmt::Debug for AsyncMmr<H, S, K, M, Id> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsyncMmr")
            .field("id", &self.id)
            .field("leaf_count", &self.state.leaf_count())
            .field("size", &self.state.node_count())
            .field("provenance", &self.state.provenance())
            .field("root", &self.state.root(&self.hasher))
            .finish_non_exhaustive()
    }
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
        self.state.root(&self.hasher)
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
        let element_hash = self.hasher.hash_leaf(element)?;
        self.append_hashed(element_hash).await
    }

    /// Appends many elements in one batch write. See
    /// [`Mmr::append_batch`](super::Mmr::append_batch).
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
        let root = self.append_hashed_batch(&element_hashes).await?;

        Ok(AppendBatchOutcome {
            first_leaf,
            appended: LeafCount::new(element_hashes.len() as u64),
            root,
        })
    }

    /// Batch-append engine for already-hashed elements: one
    /// [`apply_append_batch`](super::state::apply_append_batch) pass and one
    /// batch write, returning the root after the batch. Crate-internal: the
    /// async draft's commit replay coalesces buffered appends through it
    /// (the async twin of the sync shell's engine of the same name).
    pub(crate) async fn append_hashed_batch(
        &mut self,
        element_hashes: &[H::Output],
    ) -> Result<H::Output, MmrError<S>> {
        if element_hashes.is_empty() {
            return Ok(self.state.root(&self.hasher));
        }
        let delta = super::state::apply_append_batch(&self.hasher, &self.state, element_hashes);

        let mut batch = Batch::new();
        self.push_delta(&mut batch, &delta);
        self.store.write(batch).await.map_err(MmrError::Store)?;
        self.state = delta.state;

        Ok(delta.root)
    }

    /// Builds an inclusion proof. See [`Mmr::proof`](super::Mmr::proof).
    ///
    /// # Errors
    ///
    /// As [`Mmr::proof`](super::Mmr::proof).
    pub async fn proof(&self, leaf: LeafIndex) -> Result<Proof<H::Output>, MmrError<S>> {
        self.check_provable(leaf)?;
        self.check_nullified(leaf).await?;

        let path = sibling_path(leaf, self.state.node_count);
        let mut indexes: Vec<NodeIndex> = Vec::with_capacity(path.len() + 1);
        indexes.push(leaf.node());
        indexes.extend(path.iter().map(|step| step.sibling));

        let loaded = self.load_nodes(&indexes).await?;
        let missing = || {
            MmrError::Corrupted(super::Corrupted::MissingRecord {
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
        let mut leaves: Vec<LeafIndex> = leaves.into_iter().collect();
        leaves.sort_unstable();
        leaves.dedup();
        for &leaf in &leaves {
            self.check_provable(leaf)?;
        }
        // One batched nullifier resolution for all leaves.
        if M::NULLIFYING {
            let resolved = self.resolve_nullifiers(&leaves).await?;
            for (leaf, record) in leaves.iter().zip(&resolved) {
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

        // One batched read: element nodes first, then the pool — split
        // positionally.
        let element_indexes: Vec<NodeIndex> = leaves.iter().map(|leaf| leaf.node()).collect();
        let mut indexes = Vec::with_capacity(element_indexes.len() + pool_indexes.len());
        indexes.extend_from_slice(&element_indexes);
        indexes.extend_from_slice(&pool_indexes);
        let loaded = self.load_nodes(&indexes).await?;
        let (loaded_elements, loaded_pool) = loaded.split_at(element_indexes.len());
        let missing = || {
            MmrError::Corrupted(super::Corrupted::MissingRecord {
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

    /// Builds a consistency proof. See
    /// [`Mmr::consistency_proof`](super::Mmr::consistency_proof).
    ///
    /// # Errors
    ///
    /// As [`Mmr::consistency_proof`](super::Mmr::consistency_proof).
    pub async fn consistency_proof(
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
                let loaded = self.load_nodes(&indexes).await?;
                super::proof::consistency_from_loaded(prev_size, current, &loaded, peak_count)
                    .map_err(MmrError::Corrupted)
            }
        }
    }

    /// Verifies a proof against this MMR's *current* root. Synchronous: the
    /// check is pure over the proof and the cached state — no store, no
    /// await. See [`Mmr::verify`](super::Mmr::verify).
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof is structurally inconsistent.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify(&self, proof: &Proof<H::Output>, element: &[u8]) -> Result<bool, MmrError<S>> {
        let valid = super::proof::verify_proof(&self.hasher, proof, element)?;
        Ok(valid && proof.root == self.state.root(&self.hasher))
    }

    /// Verifies a multiproof against this MMR's *current* root. Synchronous;
    /// see [`Mmr::verify_multi`](super::Mmr::verify_multi).
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

    /// The stored hash of a leaf, if it is occupied and readable. See
    /// [`Mmr::leaf_hash`](super::Mmr::leaf_hash).
    ///
    /// # Errors
    ///
    /// As [`Mmr::leaf_hash`](super::Mmr::leaf_hash).
    pub async fn leaf_hash(&self, leaf: LeafIndex) -> Result<Option<H::Output>, MmrError<S>> {
        self.check_provable(leaf)?;
        let mut loaded = self.load_nodes(&[leaf.node()]).await?;
        Ok(loaded.pop().flatten())
    }

    /// Whether `leaf` is inside the provable range of this MMR.
    fn check_provable(&self, leaf: LeafIndex) -> Result<(), MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() || !self.state.is_provable(leaf) {
            return Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from: self.state.provenance.first_provable_leaf(),
            });
        }
        Ok(())
    }

    /// Nullifier gate for [`Nullifying`] mode; see the sync shell.
    async fn check_nullified(&self, leaf: LeafIndex) -> Result<(), MmrError<S>> {
        if M::NULLIFYING && self.resolve_nullifier(leaf).await?.is_some() {
            return Err(MmrError::LeafNullified { leaf });
        }
        Ok(())
    }

    /// Persists one already-hashed element: the pure append delta computed
    /// from cached state, applied as a single batch write. Shared by
    /// `append` and `replace` (the async draft replays its buffered appends
    /// through the batch engine below).
    pub(crate) async fn append_hashed(
        &mut self,
        element_hash: H::Output,
    ) -> Result<AppendOutcome<H::Output>, MmrError<S>> {
        let leaf = self.state.leaf_count.next_leaf();
        let leaf_node = leaf.node();
        let delta = super::state::apply_append(&self.hasher, &self.state, element_hash);

        let mut batch = Batch::new();
        self.push_delta(&mut batch, &delta);
        self.store.write(batch).await.map_err(MmrError::Store)?;
        self.state = delta.state;

        Ok(AppendOutcome {
            leaf,
            node: leaf_node,
            root: delta.root,
        })
    }

    /// Resolves the nullifier record for `leaf` across layers; see the sync
    /// shell for the rules.
    pub(crate) async fn resolve_nullifier(
        &self,
        leaf: LeafIndex,
    ) -> Result<Option<super::nullifiers::NullifierRecord>, MmrError<S>> {
        Ok(self
            .resolve_nullifiers(&[leaf])
            .await?
            .into_iter()
            .next()
            .flatten())
    }

    /// Resolves nullifier records for many leaves across all layers — one
    /// batched read per distinct store (own records and every covering
    /// sub-layer together). Mirrors the sync shell's
    /// [`Mmr::resolve_nullifiers`](super::Mmr): every layer whose pin covers
    /// a leaf's node is consulted and the strongest resolution wins (deep
    /// overrides shallow; among shallows the smaller — more restrictive —
    /// size wins). That merge is a max over a totally-ordered record set, so
    /// grouped batched reads yield exactly the sequential walk's result; the
    /// per-store reads run concurrently and merge in group order.
    pub(crate) async fn resolve_nullifiers(
        &self,
        leaves: &[LeafIndex],
    ) -> Result<Vec<Option<NullifierRecord>>, MmrError<S>> {
        if leaves.is_empty() {
            return Ok(Vec::new());
        }

        // Sub records resolve through each view's layer chain (own records
        // of the sub always; deeper layers under the pin-size rule). With
        // strictly increasing pins at most one view covers a leaf, but
        // collecting the strongest keeps this correct even for views whose
        // content was not validated at construction. Reads are grouped per
        // distinct store; the per-record merge cannot depend on grouping
        // order.
        let mut reads: Vec<AsyncLayerRead<'_, S>> = Vec::new();
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
                        .find(|read| AsyncStore::same_store(read.store, layer.store_ref()))
                    {
                        Some(read) => {
                            read.keys.push(key);
                            read.targets.push((position, layer.pinned_size.get()));
                        }
                        None => reads.push(AsyncLayerRead {
                            store: layer.store_ref(),
                            keys: vec![key],
                            targets: vec![(position, layer.pinned_size.get())],
                        }),
                    }
                }
            }
        }

        // The own-store read joins the fan-out as group 0, so its error —
        // mapped to the `Nullifier` variant like the sequential path — wins
        // over every group error. Parsing happens inside each future (the
        // trait's own `Send` future is boxed, so no `Sync` bound on the
        // store is needed) and results merge in fan-out order.
        let own_keys: Vec<Vec<u8>> = leaves
            .iter()
            .map(|leaf| keys::encode(&self.id, Table::Nullifiers, leaf.get()))
            .collect();
        let own_refs: Vec<&[u8]> = own_keys.iter().map(Vec::as_slice).collect();
        let group_refs: Vec<Vec<&[u8]>> = reads
            .iter()
            .map(|read| read.keys.iter().map(Vec::as_slice).collect())
            .collect();

        let mut futures: Vec<fanout::BatchFuture<'_, Vec<Option<NullifierRecord>>, MmrError<S>>> =
            Vec::with_capacity(reads.len() + 1);
        {
            let own_read = self.store.read(&own_refs);
            futures.push(Box::pin(async move {
                let values = own_read
                    .await
                    .map_err(|error| MmrError::Nullifier(NullifierError::Store(error)))?;
                parse_nullifier_values(values)
            }));
        }
        for (read, refs) in reads.iter().zip(&group_refs) {
            let store_read = read.store.read(refs);
            futures.push(Box::pin(async move {
                let values = store_read.await.map_err(MmrError::Store)?;
                parse_nullifier_values(values)
            }));
        }
        let loaded = fanout::join_ordered(futures).await?;

        // Own records resolve unconditionally; group records under their
        // pin gate. Strongest wins per leaf.
        let mut resolved: Vec<Option<NullifierRecord>> = Vec::with_capacity(leaves.len());
        for record in &loaded[0] {
            resolved.push(*record);
        }
        for (values, read) in loaded[1..].iter().zip(&reads) {
            for (record, (position, pin)) in values.iter().zip(&read.targets) {
                let Some(record) = record else { continue };
                if record.resolves_at(*pin) {
                    resolved[*position] = Some(match resolved[*position] {
                        Some(existing) => existing.stronger(*record),
                        None => *record,
                    });
                }
            }
        }
        Ok(resolved)
    }

    /// Reads node hashes with layer routing; see the sync shell. One batched
    /// read per distinct store; stores beyond the first are read
    /// concurrently and the parsed results are assembled in group order.
    pub(crate) async fn load_nodes(
        &self,
        nodes: &[NodeIndex],
    ) -> Result<Vec<Option<H::Output>>, MmrError<S>> {
        if self.subs.is_empty() {
            return Self::read_nodes(&self.store, self.id, nodes).await;
        }
        let groups =
            super::stacked::plan_node_reads(&self.subs, &self.store, self.id, nodes, |a, b| {
                AsyncStore::same_store(a, b)
            });

        let mut results: Vec<Option<H::Output>> = vec![None; nodes.len()];
        if groups.is_empty() {
            return Ok(results);
        }
        let loaded: Vec<Vec<Option<H::Output>>> = if groups.len() == 1 {
            // One store (the whole stack on a shared backend): the plain
            // batched read, no fan-out machinery.
            vec![read_group::<S, H::Output>(&groups[0]).await?]
        } else {
            // Distinct stores: the read-and-parse runs inside each future —
            // the trait's own `Send` future is boxed, so no `Sync` bound on
            // the store is needed — and the first group's error wins.
            let key_refs: Vec<Vec<&[u8]>> = groups
                .iter()
                .map(|group| group.keys.iter().map(Vec::as_slice).collect())
                .collect();
            #[expect(
                clippy::type_complexity,
                reason = "the boxed per-store batch type is named once at use"
            )]
            let mut futures: Vec<
                fanout::BatchFuture<'_, Vec<Option<H::Output>>, MmrError<S>>,
            > = Vec::with_capacity(groups.len());
            for (group, refs) in groups.iter().zip(&key_refs) {
                let read = group.store.read(refs);
                futures.push(Box::pin(async move {
                    read.await
                        .map_err(MmrError::Store)?
                        .into_iter()
                        .map(parse_node_value::<S, H::Output>)
                        .collect()
                }));
            }
            fanout::join_ordered(futures).await?
        };
        for (group, values) in groups.iter().zip(loaded) {
            for (parsed, slots) in values.into_iter().zip(&group.slots) {
                for &position in slots {
                    results[position] = parsed;
                }
            }
        }
        Ok(results)
    }

    /// Batched node read from one store under one id.
    async fn read_nodes(
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
            .await
            .map_err(MmrError::Store)?
            .into_iter()
            .map(parse_node_value)
            .collect()
    }

    /// The shared edit engine; see the sync shell. Kind-generic: the
    /// draft replay uses it directly (the public surface gates it on
    /// [`Editable`] + [`EditableKind`]).
    pub(crate) async fn update_hashed(
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
        let mut loaded = self.load_nodes(&indexes).await?;
        let current = loaded.first().copied().flatten();
        let siblings = loaded.split_off(1);
        // An edit onto an absent leaf node is corruption (the structure is
        // dense), not a gate mismatch: it must fail as a missing record
        // regardless of the gate, never "repair" the state by writing over
        // nothing.
        let Some(current) = current else {
            return Err(MmrError::Corrupted(super::Corrupted::MissingRecord {
                table: Table::Nodes,
            }));
        };
        if let Some(expected) = expected_current
            && current != expected
        {
            return Err(MmrError::UpdateMismatch { leaf });
        }
        let missing = || {
            MmrError::Corrupted(super::Corrupted::MissingRecord {
                table: Table::Nodes,
            })
        };

        let mut hash = new_hash;
        let mut changed = vec![(leaf.node(), new_hash)];
        let mut node = leaf.node();
        for (step, sibling) in path.iter().zip(&siblings) {
            let sibling = sibling.ok_or_else(missing)?;
            hash = match step.side {
                Side::Left => self.hasher.hash_pair(sibling, hash),
                Side::Right => self.hasher.hash_pair(hash, sibling),
            };
            node = node.parent().ok_or_else(missing)?;
            changed.push((node, hash));
        }
        let peaks_nodes = peaks_of(self.state.node_count);
        let peak_index = peaks_nodes
            .iter()
            .position(|peak| peak.get() == node.get())
            .ok_or_else(missing)?;
        let new_peak = hash;

        let mut peaks = Vec::clone(&self.state.peaks);
        peaks[peak_index] = new_peak;
        let mut batch = Batch::new();
        for (changed_node, changed_hash) in &changed {
            batch.put_owned(
                keys::encode(&self.id, Table::Nodes, changed_node.get()),
                record::hash_value(changed_hash),
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
        self.store.write(batch).await.map_err(MmrError::Store)?;

        self.state.peaks[peak_index] = new_peak;
        Ok(UpdateOutcome {
            leaf,
            previous: Some(current),
            root: self.state.root(&self.hasher),
        })
    }

    /// Resolves the store + id that own a deep record for `leaf`, or `None`
    /// when this MMR's own layer owns it; see the sync shell.
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

    /// One batched write for a run of nullifier requests: existing records
    /// are read in one batched call per distinct target store, requests for
    /// the same leaf merge (strongest wins), and every store group commits
    /// in one atomic batch. Crate-internal: the async draft's commit replay
    /// uses it so a run of nullifications costs one read + one write per
    /// store, not one round trip per record (the async twin of the sync
    /// shell's engine of the same name).
    #[cfg(feature = "draft_mmr")]
    pub(crate) async fn record_nullifiers(
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
        let mut groups: Vec<AsyncRecordTarget<'_, S>> = Vec::new();
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
                .find(|group| AsyncStore::same_store(group.store, store))
            {
                Some(group) => {
                    group.keys.push(key);
                    group.records.push(record);
                }
                None => groups.push(AsyncRecordTarget {
                    store,
                    keys: vec![key],
                    records: vec![record],
                }),
            }
        }

        for group in groups {
            super::nullifiers::write_records_async(group.store, group.keys, group.records)
                .await
                .map_err(MmrError::Nullifier)?;
        }
        Ok(())
    }

    /// Pushes an append delta's nodes and counters onto a batch.
    fn push_delta(&self, batch: &mut Batch<'_>, delta: &super::state::AppendDelta<H>) {
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
}

impl<H: Hasher, S: AsyncStore, M: Mode, Id: TreeId> AsyncMmr<H, S, super::Plain, M, Id> {
    /// Creates a fresh, empty MMR and persists its genesis metadata. See
    /// [`Mmr::create`](super::Mmr::create).
    ///
    /// # Errors
    ///
    /// As [`Mmr::create`](super::Mmr::create).
    pub async fn create(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::create_with_state(hasher, store, id, super::state::MmrState::empty()).await
    }

    /// Re-opens an existing MMR from the store, validating all persisted
    /// metadata. See [`Mmr::open`](super::Mmr::open) — a store whose
    /// provenance record says peaks-only is rejected; open it as a
    /// [`WithPeaks`](super::WithPeaks) async MMR
    /// ([`AsyncMmr::open`](AsyncMmr::open) on that kind) to restore the seed
    /// floor.
    ///
    /// # Errors
    ///
    /// As [`Mmr::open`](super::Mmr::open).
    pub async fn open(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let (hasher, store, id, state) = Self::load(hasher, store, id, M::NAME).await?;
        // A Plain handle claims full history; a peaks-only store would
        // silently lose its proof floor here.
        if state.provenance() != Provenance::Full {
            return Err(MmrError::Corrupted(super::Corrupted::MalformedRecord {
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

impl<H: Hasher, S: AsyncStore, M: Mode, Id: TreeId> AsyncMmr<H, S, super::WithPeaks, M, Id> {
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

        Self::create_with_state(
            hasher,
            store,
            id,
            super::state::MmrState::from_peaks(size, peaks),
        )
        .await
    }
}

impl<H: Hasher, S: AsyncStore, K: Kind, M: Mode, Id: TreeId> AsyncMmr<H, S, K, M, Id> {
    /// Shared genesis writer; see the sync shell. Kind-generic: used by
    /// `create` ([`super::Plain`]) and `from_peaks` ([`super::WithPeaks`]).
    async fn create_with_state(
        hasher: H,
        store: S,
        id: Id,
        state: super::state::MmrState<H>,
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
            super::state::encode_provenance(state.provenance),
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
        store.write(batch).await.map_err(MmrError::Store)?;

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
    /// [`Self::load`] and `open_stack` (the async twin of the sync shell's
    /// helper of the same name).
    async fn read_metadata(
        hasher: &H,
        store: &S,
        id: Id,
        declared_mode: &'static str,
    ) -> Result<(super::state::Metadata, Vec<u8>), MmrError<S>> {
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
        let values = store.read(&refs).await.map_err(MmrError::Store)?;

        let missing = |table| MmrError::Corrupted(super::Corrupted::MissingRecord { table });
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
        let parsed = super::state::validate_metadata(hasher, metadata, declared_mode)
            .map_err(MmrError::Corrupted)?;

        Ok((parsed, value(5, Table::Root)?.to_vec()))
    }

    /// Shared loader; see the sync shell — one shared validation helper
    /// (`state::validate_metadata`), then the peaks and the root. Kind-
    /// generic: both kind-specific `open`s use it.
    pub(crate) async fn load(
        hasher: H,
        store: S,
        id: Id,
        declared_mode: &'static str,
    ) -> Result<(H, S, Id, super::state::MmrState<H>), MmrError<S>> {
        let (
            super::state::Metadata {
                leaf_count,
                node_count,
                provenance,
            },
            root_record,
        ) = Self::read_metadata(&hasher, &store, id, declared_mode).await?;

        let peak_nodes = peaks_of(node_count);
        let peak_values = Self::read_nodes(&store, id, &peak_nodes).await?;
        let peaks: Vec<H::Output> = peak_values
            .into_iter()
            .map(|value| {
                value.ok_or_else(|| {
                    MmrError::Corrupted(super::Corrupted::MissingRecord {
                        table: Table::Nodes,
                    })
                })
            })
            .collect::<Result<_, _>>()?;

        let state = super::state::MmrState {
            leaf_count,
            node_count,
            peaks,
            provenance,
        };
        if record::hash_value(&state.root(&hasher)).as_slice() != root_record.as_slice() {
            return Err(MmrError::Corrupted(super::Corrupted::RootMismatch));
        }

        Ok((hasher, store, id, state))
    }
}

impl<H: Hasher, S: AsyncStore, M: Mode, Id: TreeId> AsyncMmr<H, S, super::WithPeaks, M, Id> {
    /// Re-opens an existing peaks-only MMR from the store, reconstructing
    /// the seed floor from the persisted provenance record. Async twin of
    /// [`Mmr::open`](super::Mmr::open) on the
    /// [`WithPeaks`](super::WithPeaks) kind. A store whose provenance record
    /// says full history is rejected — open it as a Plain async MMR instead.
    ///
    /// # Errors
    ///
    /// As [`Mmr::open`](super::Mmr::open).
    pub async fn open(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let (hasher, store, id, state) = Self::load(hasher, store, id, M::NAME).await?;
        // A WithPeaks handle needs the seed floor; a full-history store has
        // nothing to floor.
        if !matches!(state.provenance(), Provenance::FromPeaks { .. }) {
            return Err(MmrError::Corrupted(super::Corrupted::MalformedRecord {
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

impl<H: Hasher, S: AsyncStore, Id: TreeId> AsyncMmr<H, S, super::WithPeaks, Editable, Id> {
    /// [`AsyncMmr::open`](Self::open) declaring an [`Editable`]
    /// base. See [`Mmr::open_editable`](super::Mmr::open_editable).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open_editable`](super::Mmr::open_editable).
    pub async fn open_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::open(hasher, store, id).await
    }
}

impl<H: Hasher, S: AsyncStore, Id: TreeId> AsyncMmr<H, S, super::WithPeaks, Nullifying, Id> {
    /// [`AsyncMmr::open`](Self::open) declaring a [`Nullifying`]
    /// base. See [`Mmr::open_nullifying`](super::Mmr::open_nullifying).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open_nullifying`](super::Mmr::open_nullifying).
    pub async fn open_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::open(hasher, store, id).await
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
        Self::create(hasher, store, id).await
    }

    /// [`AsyncMmr::open`](Self::open) declaring an [`Editable`]
    /// base. See [`Mmr::open_editable`](super::Mmr::open_editable).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open_editable`](super::Mmr::open_editable).
    pub async fn open_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::open(hasher, store, id).await
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
        Self::create(hasher, store, id).await
    }

    /// [`AsyncMmr::open`](Self::open) declaring a [`Nullifying`]
    /// base. See [`Mmr::open_nullifying`](super::Mmr::open_nullifying).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open_nullifying`](super::Mmr::open_nullifying).
    pub async fn open_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        Self::open(hasher, store, id).await
    }
}

impl<H: Hasher, S: AsyncStore, K: EditableKind, Id: TreeId> AsyncMmr<H, S, K, Editable, Id> {
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
        let new_hash = self.hasher.hash_leaf(element)?;
        self.update_hashed(leaf, new_hash, expected_current).await
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
        self.update_hashed(leaf, self.hasher.genesis(), expected_current)
            .await
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
        let record = self.record_nullifier(leaf, NullifierDepth::Shallow).await?;
        Ok(NullifyOutcome { leaf, record })
    }

    /// Shallow nullification of the old leaf and append of the new element.
    /// See [`Mmr::replace_shallow`](super::Mmr::replace_shallow) — the
    /// element is hashed before the record is written, and the record and
    /// the append delta land in one atomic batch.
    ///
    /// # Errors
    ///
    /// As [`Mmr::replace_shallow`](super::Mmr::replace_shallow).
    pub async fn replace_shallow(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let element_hash = self.hasher.hash_leaf(element)?;
        self.replace_hashed(leaf, element_hash, NullifierDepth::Shallow)
            .await
    }

    /// Borrowed view of this MMR's own nullifier records. See
    /// [`Mmr::nullifier_set`](super::Mmr::nullifier_set).
    #[must_use]
    pub fn nullifier_set(&self) -> AsyncNullifierSet<'_, S, Id> {
        AsyncNullifierSet {
            store: &self.store,
            id: self.id,
        }
    }

    /// The shared nullifier writer; see the sync shell.
    pub(crate) async fn record_nullifier(
        &mut self,
        leaf: LeafIndex,
        depth: NullifierDepth,
    ) -> Result<super::nullifiers::NullifierRecord, MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() {
            return Err(MmrError::LeafOutOfRange {
                leaf,
                leaf_count: self.state.leaf_count,
            });
        }
        match depth {
            NullifierDepth::Shallow => {
                let at = self.state.node_count;
                nullify_record_async(
                    &self.store,
                    self.id,
                    leaf,
                    super::nullifiers::NullifierRecord::Shallow { at },
                )
                .await
                .map_err(MmrError::Nullifier)?;
                Ok(super::nullifiers::NullifierRecord::Shallow { at })
            }
            NullifierDepth::Deep => {
                // Deep records land in the store of the layer that holds the
                // value, so every stack above sees them. Through a stacked
                // sub-view, the owner is the covering layer of the chain.
                let (store, id) = self.deep_owner(leaf).unwrap_or((&self.store, self.id));
                nullify_record_async(store, id, leaf, super::nullifiers::NullifierRecord::Deep)
                    .await
                    .map_err(MmrError::Nullifier)?;
                Ok(super::nullifiers::NullifierRecord::Deep)
            }
        }
    }

    /// The shared replace engine; see the sync shell — hash-first, and the
    /// record coalesces with the append delta into one batch whenever both
    /// target this MMR's own store. A sub-layer-owned deep record is a
    /// separate, earlier write (cross-store, not atomic with the append).
    async fn replace_hashed(
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
            NullifierDepth::Shallow => super::nullifiers::NullifierRecord::Shallow { at },
            NullifierDepth::Deep => super::nullifiers::NullifierRecord::Deep,
        };

        let owner = match depth {
            NullifierDepth::Shallow => None,
            NullifierDepth::Deep => self.deep_owner(leaf),
        };

        match owner {
            None => {
                // One batched read of the existing record (strengthen-only
                // rule), then one atomic batch: record + append delta.
                let existing = read_records_async(&self.store, self.id, &[leaf])
                    .await
                    .map_err(MmrError::Nullifier)?
                    .into_iter()
                    .next()
                    .flatten();
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
                self.store.write(batch).await.map_err(MmrError::Store)?;
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
                // Cross-store deep record: written first, not atomic with
                // the append (documented limitation; see the sync shell).
                nullify_record_async(owner_store, owner_id, leaf, record)
                    .await
                    .map_err(MmrError::Nullifier)?;
                let appended = self.append_hashed(element_hash).await?;
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

impl<H: Hasher, S: AsyncStore, K: DeepNullifiable, Id: TreeId> AsyncMmr<H, S, K, Nullifying, Id> {
    /// Marks a leaf as no longer valid with a **deep** record. Available for
    /// [`Plain`](crate::mmr::Plain) and [`Stacked`](crate::mmr::Stacked)
    /// only — see [`Mmr::nullify_deep`](super::Mmr::nullify_deep).
    ///
    /// # Errors
    ///
    /// As [`Mmr::nullify_deep`](super::Mmr::nullify_deep).
    pub async fn nullify_deep(&mut self, leaf: LeafIndex) -> Result<NullifyOutcome, MmrError<S>> {
        let record = self.record_nullifier(leaf, NullifierDepth::Deep).await?;
        Ok(NullifyOutcome { leaf, record })
    }

    /// Deep nullification of the old leaf and append of the new element. See
    /// [`Mmr::replace_deep`](super::Mmr::replace_deep) — hash-first; one
    /// batch when this layer owns the value, cross-store two writes
    /// otherwise.
    ///
    /// # Errors
    ///
    /// As [`Mmr::replace_deep`](super::Mmr::replace_deep).
    pub async fn replace_deep(
        &mut self,
        leaf: LeafIndex,
        element: &[u8],
    ) -> Result<ReplaceOutcome<H::Output>, MmrError<S>> {
        let element_hash = self.hasher.hash_leaf(element)?;
        self.replace_hashed(leaf, element_hash, NullifierDepth::Deep)
            .await
    }
}

#[cfg(feature = "stacked_mmr")]
impl<H: Hasher, S: AsyncStore + Clone, K: SingleLayerKind, M: Mode + Stackable, Id: TreeId>
    AsyncMmr<H, S, K, M, Id>
{
    /// Pinned, read-only view of this MMR at its current size, for use as a
    /// stacking layer. The view does not follow later growth of this MMR.
    /// See [`Mmr::pin`](super::Mmr::pin) — the async twin is synchronous
    /// too: it clones the backend handle and captures the locator, touching
    /// no storage.
    ///
    /// Only exists for [`Stackable`] modes: an [`Editable`]
    /// MMR cannot be pinned or stacked upon (compile-time).
    #[must_use]
    pub fn pin(&self) -> SubView<S, Id, H::Output> {
        SubView {
            layers: vec![LayerView {
                id: self.id,
                store: S::clone(&self.store),
                pinned_size: self.state.node_count,
                locator: AsyncStore::locator(&self.store),
                _output: core::marker::PhantomData,
            }],
            pinned_size: self.state.node_count,
            _output: core::marker::PhantomData,
        }
    }
}

#[cfg(feature = "stacked_mmr")]
impl<H: Hasher, S: AsyncStore + Clone, M: Stackable, Id: TreeId>
    AsyncMmr<H, S, super::Stacked, M, Id>
{
    /// Pinned, read-only view of this stacked MMR at its current size,
    /// carrying the whole flattened layer chain. See
    /// [`Mmr::pin`](super::Mmr::pin) on the sync [`Stacked`](super::Stacked)
    /// kind — the async twin is synchronous too.
    #[must_use]
    pub fn pin(&self) -> SubView<S, Id, H::Output> {
        let mut layers: Vec<LayerView<S, Id, H::Output>> = self
            .subs
            .iter()
            .flat_map(|sub| {
                sub.layers
                    .iter()
                    .map(|layer| LayerView {
                        id: layer.id,
                        store: S::clone(layer.store_ref()),
                        pinned_size: layer.pinned_size,
                        locator: layer.locator.clone(),
                        _output: core::marker::PhantomData,
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        layers.push(LayerView {
            id: self.id,
            store: S::clone(&self.store),
            pinned_size: self.state.node_count,
            locator: AsyncStore::locator(&self.store),
            _output: core::marker::PhantomData,
        });
        SubView {
            layers,
            pinned_size: self.state.node_count,
            _output: core::marker::PhantomData,
        }
    }

    /// Builds a stacked MMR over validated sub-views. See
    /// [`Mmr::stack`](super::Mmr::stack) — the async twin persists the same
    /// genesis metadata and sub-view record in one batch write.
    ///
    /// # Errors
    ///
    /// As [`Mmr::stack`](super::Mmr::stack).
    pub async fn stack<I>(
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
            state: super::state::MmrState::empty(),
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        };
        handle.init_stack(subs).await.map(|()| handle)
    }

    /// Shared stack bootstrap: reads routed peaks, persists genesis metadata
    /// and the sub-view record. Used by [`Self::stack`] (the async twin of
    /// the sync shell's engine of the same name).
    ///
    /// Errors are [`StackingError`]s because every failure here is either a
    /// store failure or a sub-view whose content does not back its pin.
    pub(crate) async fn init_stack(
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
            .await
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
        if let Some(stored) = first_layer_hasher_mismatch_async(&self.subs, &self.hasher).await {
            return Err(super::stacked::StackingError::LayerHasherMismatch { stored });
        }

        self.state = super::state::MmrState {
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
            super::state::encode_provenance(self.state.provenance),
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
            .await
            .map_err(super::stacked::StackingError::Store)
    }
}

#[cfg(feature = "stacked_mmr")]
impl<H: Hasher, S: AsyncStore, M: Stackable, Id: TreeId> AsyncMmr<H, S, super::Stacked, M, Id> {
    /// Re-open path shared with [`open_stacked`]: validates the sub-view
    /// list, the persisted metadata (through the shared
    /// `state::validate_metadata` helper), every layer's hasher, then loads
    /// routed peaks for the reconstructed sub-views (the async twin of the
    /// sync shell's engine of the same name).
    pub(crate) async fn open_stack(
        hasher: H,
        store: S,
        id: Id,
        subs: Vec<SubView<S, Id, H::Output>>,
    ) -> Result<Self, MmrError<S>> {
        let mut handle = Self {
            hasher,
            store,
            id,
            state: super::state::MmrState::empty(),
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        };

        // The sub-view list is validated exactly like at construction
        // ([`AsyncMmr::stack`]): it is persisted data, so unsorted or
        // duplicate pins must not route reads to the wrong layer.
        validate_sub_views(&subs).map_err(MmrError::Stacking)?;

        // Cross-layer hasher validation — same gate as
        // [`AsyncMmr::stack`].
        if let Some(stored) = first_layer_hasher_mismatch_async(&subs, &handle.hasher).await {
            return Err(MmrError::Corrupted(super::Corrupted::HasherMismatch {
                stored,
                supplied: alloc::format!("{} ({})", handle.hasher.id(), handle.hasher.config()),
            }));
        }

        // Metadata validation (the routed peaks need the subs, so they are
        // loaded after the sub-views are installed).
        let (
            super::state::Metadata {
                leaf_count,
                node_count,
                provenance,
            },
            root_record,
        ) = Self::read_metadata(&handle.hasher, &handle.store, handle.id, M::NAME).await?;
        // A stacked layer's own provenance is always full history (stacks
        // start empty above their pins).
        if provenance != Provenance::Full {
            return Err(MmrError::Corrupted(super::Corrupted::MalformedRecord {
                table: Table::Provenance,
            }));
        }

        handle.subs = subs;
        let peak_nodes = peaks_of(node_count);
        let peaks: Vec<H::Output> = handle
            .load_nodes(&peak_nodes)
            .await?
            .into_iter()
            .map(|value| {
                value.ok_or_else(|| {
                    MmrError::Corrupted(super::Corrupted::MissingRecord {
                        table: Table::Nodes,
                    })
                })
            })
            .collect::<Result<_, _>>()?;
        handle.state = super::state::MmrState {
            leaf_count,
            node_count,
            peaks,
            provenance,
        };

        if record::hash_value(&handle.state.root(&handle.hasher)).as_slice()
            != root_record.as_slice()
        {
            return Err(MmrError::Corrupted(super::Corrupted::RootMismatch));
        }
        Ok(handle)
    }
}

/// Re-opens a stacked async MMR from its persisted sub-view metadata
/// ([`Table::Subviews`]): each layer's id, pin size, and store locator.
///
/// `store` is the **top layer's store** — the one holding the `Subviews`
/// record under the stacked MMR's own id. Every sub-layer is re-opened via
/// [`AsyncRetrievable::open`] with the same `S` — persistent stacks
/// therefore require a concrete retrievable async store type (erased stacks
/// are session-local). The declared mode `M` and the hasher identity/config
/// are validated against the persisted metadata, and pin sizes are
/// cross-checked against each layer's own counters.
///
/// # Errors
///
/// Store re-open failures or missing/corrupt metadata
/// ([`MmrError::Corrupted`]).
#[cfg(feature = "stacked_mmr")]
pub async fn open_stacked<H: Hasher, S: AsyncRetrievable, M: Stackable, Id: TreeId>(
    hasher: H,
    store: S,
    id: Id,
) -> Result<AsyncMmr<H, S, super::Stacked, M, Id>, MmrError<S>> {
    use crate::store::record::parse_counter;

    // Layer list first: it tells us where every counter lives.
    let subviews_key = keys::encode(&id, Table::Subviews, 0);
    let mut values = store
        .read(&[&subviews_key])
        .await
        .map_err(MmrError::Store)?;
    let Some(raw) = values.pop().flatten() else {
        return Err(MmrError::Corrupted(super::Corrupted::MissingRecord {
            table: Table::Subviews,
        }));
    };
    let layers = super::stacked::parse_subviews(&raw).ok_or(MmrError::Corrupted(
        super::Corrupted::MalformedRecord {
            table: Table::Subviews,
        },
    ))?;

    // Reconstruct the sub-views exactly as `pin()` had them: distinct pin
    // sizes (ascending) are the view boundaries, and a view with pin P
    // carries every flattened layer whose pin is ≤ P, in bottom → top order
    // (a view's pin is always its top layer's pinned size). Rebuilding one
    // single-layer view per record instead would produce duplicate pins —
    // which `validate_sub_views` (run by `open_stack`) rightly rejects.
    let mut pins: Vec<u64> = layers.iter().map(|layer| layer.pinned_size).collect();
    pins.sort_unstable();
    pins.dedup();

    let mut subs = Vec::with_capacity(pins.len());
    for &pin in &pins {
        let mut chain: Vec<LayerView<S, Id, H::Output>> = Vec::new();
        // Opens stay sequential (each materializes a fresh store handle);
        // the chain's counters then read concurrently, one future per
        // layer, results validated in layer order.
        let mut opened: Vec<(S, &super::stacked::PersistedLayer<Id>)> = Vec::new();
        for layer in &layers {
            if layer.pinned_size > pin {
                continue;
            }
            let layer_store = S::open(&layer.locator).await.map_err(MmrError::Store)?;
            opened.push((layer_store, layer));
        }

        let count_keys: Vec<Vec<u8>> = opened
            .iter()
            .map(|(_, layer)| keys::encode(&layer.id, Table::NodeCount, 0))
            .collect();
        let key_refs: Vec<[&[u8]; 1]> = count_keys.iter().map(|key| [key.as_slice()]).collect();
        let stored: Vec<Option<Vec<u8>>> = if opened.len() <= 1 {
            let mut stored = Vec::with_capacity(opened.len());
            for ((layer_store, _), refs) in opened.iter().zip(&key_refs) {
                stored.push(
                    layer_store
                        .read(refs)
                        .await
                        .map_err(MmrError::Store)?
                        .into_iter()
                        .next()
                        .flatten(),
                );
            }
            stored
        } else {
            #[expect(
                clippy::type_complexity,
                reason = "the boxed per-store batch type is named once at use"
            )]
            let mut futures: Vec<
                fanout::BatchFuture<'_, Vec<Option<Vec<u8>>>, S::Error>,
            > = Vec::with_capacity(opened.len());
            for ((layer_store, _), refs) in opened.iter().zip(&key_refs) {
                futures.push(Box::pin(layer_store.read(refs)));
            }
            fanout::join_ordered(futures)
                .await
                .map_err(MmrError::Store)?
                .into_iter()
                .map(|values| values.into_iter().next().flatten())
                .collect()
        };

        for ((layer_store, layer), count) in opened.into_iter().zip(stored) {
            // Cross-check: the layer must actually hold at least the pinned
            // size.
            let node_count =
                count
                    .as_deref()
                    .and_then(parse_counter)
                    .ok_or(MmrError::Corrupted(super::Corrupted::MissingRecord {
                        table: Table::NodeCount,
                    }))?;
            if node_count < layer.pinned_size {
                return Err(MmrError::Corrupted(super::Corrupted::PinSizeMismatch {
                    pinned: MmrSize::new_unchecked(layer.pinned_size),
                    layer_size: MmrSize::new_unchecked(node_count),
                }));
            }
            chain.push(LayerView {
                id: layer.id,
                store: layer_store,
                pinned_size: MmrSize::new_unchecked(layer.pinned_size),
                locator: Some(layer.locator.clone()),
                _output: core::marker::PhantomData,
            });
        }
        subs.push(SubView {
            layers: chain,
            pinned_size: MmrSize::new_unchecked(pin),
            _output: core::marker::PhantomData,
        });
    }

    AsyncMmr::open_stack(hasher, store, id, subs).await
}

/// Re-opens a stacked async MMR whose top layer is
/// [`AppendOnly`](super::AppendOnly) — the
/// named alternative to the four-parameter [`open_stacked`] turbofish.
///
/// # Errors
///
/// As [`open_stacked`].
#[cfg(feature = "stacked_mmr")]
pub async fn open_stacked_append_only<H: Hasher, S: AsyncRetrievable, Id: TreeId>(
    hasher: H,
    store: S,
    id: Id,
) -> Result<AsyncMmr<H, S, super::Stacked, super::AppendOnly, Id>, MmrError<S>> {
    open_stacked::<H, S, super::AppendOnly, Id>(hasher, store, id).await
}

/// Re-opens a stacked async MMR whose top layer is [`Nullifying`] — the
/// named alternative to the four-parameter [`open_stacked`] turbofish.
///
/// # Errors
///
/// As [`open_stacked`].
#[cfg(feature = "stacked_mmr")]
pub async fn open_stacked_nullifying<H: Hasher, S: AsyncRetrievable, Id: TreeId>(
    hasher: H,
    store: S,
    id: Id,
) -> Result<AsyncMmr<H, S, super::Stacked, super::Nullifying, Id>, MmrError<S>> {
    open_stacked::<H, S, super::Nullifying, Id>(hasher, store, id).await
}

#[cfg(feature = "draft_mmr")]
impl<H: Hasher, S: AsyncStore, K: Kind, M: Mode, Id: TreeId> AsyncMmr<H, S, K, M, Id> {
    /// Opens an in-memory draft over this MMR. See
    /// [`Mmr::start_draft`](super::Mmr::start_draft) — the async draft
    /// offers the same operations per this MMR's [`Mode`] and shares the
    /// sync draft's op-log/overlay machinery; only the fetch/commit
    /// plumbing is async.
    #[must_use]
    pub fn start_draft(&mut self) -> super::async_draft::AsyncDraft<'_, H, S, K, M, Id> {
        let state = self.state.clone();
        super::async_draft::AsyncDraft {
            base: self,
            ops: Vec::new(),
            state,
            overlay: BTreeMap::new(),
            buffered_nullified: BTreeMap::new(),
        }
    }
}
