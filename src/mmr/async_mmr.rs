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
//! Sync-only surface (not yet on this shell): the draft overlay
//! (`start_draft`/`commit_as_stacked`), `pin`/`stack` construction of
//! `Stacked` handles, `open_stacked`, and a `NullifierSet` accessor exist
//! on the sync [`Mmr`](super::Mmr) only.
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
//! (the [`HashValue`](crate::primitives::HashValue) trait carries no
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
//! stacked MMR are read sequentially for now (same grouping as the sync
//! shell); a parallel fan-out is future work.

use super::kinds::{DeepNullifiable, EditableKind};
use super::layout::{
    LeafCount, MmrSize, NodeIndex, PathStep, Side, bag_peaks, peaks_of, root_from, sibling_path,
};
use super::mode::{Editable, Mode, Nullifying};
use super::nullifiers::{NullifierDepth, nullify_record_async, read_records_async};
use super::proof::{MultiProof, Proof};
use super::stacked::parse_node_value;
use super::state::Provenance;
use super::{
    AppendBatchOutcome, AppendOutcome, Kind, MmrError, NullifyOutcome, ReplaceOutcome,
    UpdateOutcome,
};
use crate::hashers::Hasher;
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::LeafIndex;
use crate::store::{AsyncStore, Batch, keys, keys::Table, record};
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
        let delta = super::state::apply_append_batch(&self.hasher, &self.state, &element_hashes);

        let mut batch = Batch::new();
        self.push_delta(&mut batch, &delta);
        self.store.write(batch).await.map_err(MmrError::Store)?;
        self.state = delta.state;

        Ok(AppendBatchOutcome {
            first_leaf,
            appended: LeafCount::new(element_hashes.len() as u64),
            root: delta.root,
        })
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
        if prev_size.leaf_count().is_none() || prev_size > current {
            return Err(MmrError::InvalidPrevSize {
                prev_size,
                provable_from: floor,
                current,
            });
        }
        // The degenerate sizes need no history: the trivial prefix uses the
        // cached peaks, and the empty prefix's root is a public constant.
        if prev_size == current {
            return Ok(super::proof::ConsistencyProof {
                prev_size,
                size: current,
                prev_peaks: Vec::clone(&self.state.peaks),
                path: Vec::new(),
            });
        }
        if prev_size == MmrSize::ZERO {
            return Ok(super::proof::ConsistencyProof {
                prev_size,
                size: current,
                prev_peaks: Vec::new(),
                path: Vec::clone(&self.state.peaks),
            });
        }
        if prev_size < floor {
            return Err(MmrError::InvalidPrevSize {
                prev_size,
                provable_from: floor,
                current,
            });
        }

        // One batched read: the earlier peaks, then the bridge nodes —
        // split positionally.
        let bridge_nodes = super::proof::consistency_bridge_nodes(prev_size, current);
        let mut indexes = peaks_of(prev_size);
        let peak_count = indexes.len();
        indexes.extend_from_slice(&bridge_nodes);
        let loaded = self.load_nodes(&indexes).await?;
        let (peaks_loaded, bridge_loaded) = loaded.split_at(peak_count);
        let missing = || {
            MmrError::Corrupted(super::Corrupted::MissingRecord {
                table: Table::Nodes,
            })
        };

        Ok(super::proof::ConsistencyProof {
            prev_size,
            size: current,
            prev_peaks: peaks_loaded
                .iter()
                .copied()
                .map(|value| value.ok_or_else(missing))
                .collect::<Result<Vec<_>, _>>()?,
            path: bridge_loaded
                .iter()
                .copied()
                .map(|value| value.ok_or_else(missing))
                .collect::<Result<Vec<_>, _>>()?,
        })
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
    /// `append` and `replace` (the draft replays its buffered appends
    /// through the sync twin of this method).
    async fn append_hashed(
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
    async fn resolve_nullifier(
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
    /// grouped batched reads yield exactly the sequential walk's result.
    async fn resolve_nullifiers(
        &self,
        leaves: &[LeafIndex],
    ) -> Result<Vec<Option<super::nullifiers::NullifierRecord>>, MmrError<S>> {
        if leaves.is_empty() {
            return Ok(Vec::new());
        }

        // Own (topmost) records always resolve — no pin gates them.
        let mut resolved = read_records_async(&self.store, self.id, leaves)
            .await
            .map_err(MmrError::Nullifier)?;

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
        for read in reads {
            let refs: Vec<&[u8]> = read.keys.iter().map(Vec::as_slice).collect();
            let values = read.store.read(&refs).await.map_err(MmrError::Store)?;
            for (value, (position, pin)) in values.into_iter().zip(&read.targets) {
                let record = match value {
                    None => continue,
                    Some(bytes) => super::nullifiers::NullifierRecord::parse(&bytes).ok_or(
                        MmrError::Nullifier(super::nullifiers::NullifierError::MalformedRecord),
                    )?,
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

    /// Reads node hashes with layer routing; see the sync shell.
    async fn load_nodes(&self, nodes: &[NodeIndex]) -> Result<Vec<Option<H::Output>>, MmrError<S>> {
        if self.subs.is_empty() {
            return Self::read_nodes(&self.store, self.id, nodes).await;
        }
        let groups =
            super::stacked::plan_node_reads(&self.subs, &self.store, self.id, nodes, |a, b| {
                AsyncStore::same_store(a, b)
            });

        let mut results: Vec<Option<H::Output>> = vec![None; nodes.len()];
        for group in &groups {
            let refs: Vec<&[u8]> = group.keys.iter().map(Vec::as_slice).collect();
            let values = group.store.read(&refs).await.map_err(MmrError::Store)?;
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

    /// Shared loader; see the sync shell — one shared validation helper
    /// (`state::validate_metadata`), then the peaks and the root. Kind-
    /// generic: both kind-specific `open`s use it.
    pub(crate) async fn load(
        hasher: H,
        store: S,
        id: Id,
        declared_mode: &'static str,
    ) -> Result<(H, S, Id, super::state::MmrState<H>), MmrError<S>> {
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
        let super::state::Metadata {
            leaf_count,
            node_count,
            provenance,
        } = super::state::validate_metadata(&hasher, metadata, declared_mode)
            .map_err(MmrError::Corrupted)?;

        let peak_nodes = peaks_of(node_count);
        let peak_values = Self::read_nodes(&store, id, &peak_nodes).await?;
        let peaks: Vec<H::Output> = peak_values
            .into_iter()
            .map(|value| value.ok_or_else(|| missing(Table::Nodes)))
            .collect::<Result<_, _>>()?;

        let state = super::state::MmrState {
            leaf_count,
            node_count,
            peaks,
            provenance,
        };
        if record::hash_value(&state.root(&hasher)).as_slice() != value(5, Table::Root)? {
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

    /// The shared edit engine; see the sync shell.
    async fn update_hashed(
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

    /// The shared nullifier writer; see the sync shell.
    async fn record_nullifier(
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
