//! The async shell over the same pure [`super::state`] core.
//!
//! Mirrors [`super::Mmr`] method-for-method, generic over
//! [`AsyncStore`] instead of
//! [`Store`](crate::store::Store). All algorithms live in the state
//! core (sync, pure), so each method is just "fetch state → pure transform
//! → one batch write"; the residual duplication is the fetch/commit plumbing
//! itself (the metadata load/validate sequence), kept parallel to the sync
//! loader because the store contracts differ.
//!
//! Errors are unified with the sync shell: [`MmrError`] is generic over
//! [`Storage`](crate::store::Storage), which both
//! [`Store`](crate::store::Store) and [`AsyncStore`] require as a
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
//! [`Mmr`](super::Mmr) with a sync store instead. Distinct stores in a
//! stacked MMR are read sequentially for now (same grouping as the sync
//! shell); a parallel fan-out is future work.

use super::kinds::{DeepNullifiable, EditableKind};
use super::layout::{
    LeafCount, MmrSize, NodeIndex, PathStep, Side, bag_peaks, peaks_of, root_from, sibling_path,
};
use super::mode::{Editable, Mode, Nullifying};
use super::nullifiers::{NullifierDepth, nullify_record_async, read_record_async};
use super::proof::{MultiProof, Proof};
use super::state::Provenance;
use super::{
    AppendBatchOutcome, AppendOutcome, Kind, MmrError, NullifyOutcome, ReplaceOutcome,
    UpdateOutcome,
};
use crate::hashers::Hasher;
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::{HashValue, LeafIndex};
use crate::store::{AsyncStore, Batch, keys, keys::Table, record};
use alloc::vec;
use alloc::vec::Vec;

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
            root: self.state.root(&self.hasher),
        })
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
            root: self.state.root(&self.hasher),
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
        for &leaf in &leaves {
            self.check_nullified(leaf).await?;
        }

        let paths: Vec<Vec<PathStep>> = leaves
            .iter()
            .map(|leaf| sibling_path(*leaf, self.state.node_count))
            .collect();
        let (pool_indexes, pool_refs) = super::proof::build_sibling_pool(&paths);

        let element_indexes: Vec<NodeIndex> = leaves.iter().map(|leaf| leaf.node()).collect();
        let loaded_elements = self.load_nodes(&element_indexes).await?;
        let loaded_pool = self.load_nodes(&pool_indexes).await?;
        let missing = || {
            MmrError::Corrupted(super::Corrupted::MissingRecord {
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

    /// Verifies a proof against this MMR's *current* root. Synchronous: the
    /// check is pure over the proof and the cached state — no store, no
    /// await. See [`Mmr::verify`](super::Mmr::verify).
    ///
    /// # Errors
    ///
    /// [`MmrError::Verify`] when the proof is structurally inconsistent.
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

    /// In-memory append shared by appends and replaces.
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
            root: self.state.root(&self.hasher),
        })
    }

    /// Resolves the nullifier record for `leaf` across layers; see the sync
    /// shell for the rules.
    async fn resolve_nullifier(
        &self,
        leaf: LeafIndex,
    ) -> Result<Option<super::nullifiers::NullifierRecord>, MmrError<S>> {
        let own = read_record_async(&self.store, self.id, leaf)
            .await
            .map_err(MmrError::Store)?;
        if own.is_some() {
            return Ok(own);
        }

        if self.subs.is_empty() {
            return Ok(None);
        }
        let node = leaf.node().get();
        for sub in &self.subs {
            if node <= sub.pinned_size().get()
                && let Some(layer) = sub.route(node)
                && let Some(record) = read_record_async(layer.store_ref(), layer.id_ref(), leaf)
                    .await
                    .map_err(MmrError::Store)?
                && record.resolves_at(layer.pinned_size.get())
            {
                return Ok(Some(record));
            }
            if node <= sub.pinned_size().get() {
                return Ok(None);
            }
        }
        Ok(None)
    }

    /// Reads node hashes with layer routing; see the sync shell.
    async fn load_nodes(&self, nodes: &[NodeIndex]) -> Result<Vec<Option<H::Output>>, MmrError<S>> {
        // One routing group per distinct store: keys to read there and the
        // positions they fill in the result.
        struct AsyncGroup<'a, S> {
            store: &'a S,
            keys: Vec<Vec<u8>>,
            positions: Vec<usize>,
        }

        if self.subs.is_empty() {
            return Self::read_nodes(&self.store, self.id, nodes)
                .await
                .map_err(MmrError::Store);
        }

        let mut groups: Vec<AsyncGroup<'_, S>> = Vec::new();
        for (position, node) in nodes.iter().enumerate() {
            let mut routed = None;
            for sub in &self.subs {
                if node.get() <= sub.pinned_size().get() {
                    if let Some(layer) = sub.route(node.get()) {
                        routed = Some((layer.store_ref(), layer.id_ref()));
                    }
                    break;
                }
            }
            let (store, id) = routed.unwrap_or((&self.store, self.id));
            match groups
                .iter_mut()
                .find(|group| AsyncStore::same_store(group.store, store))
            {
                Some(group) => {
                    group.keys.push(keys::encode(&id, Table::Nodes, node.get()));
                    group.positions.push(position);
                }
                None => groups.push(AsyncGroup {
                    store,
                    keys: vec![keys::encode(&id, Table::Nodes, node.get())],
                    positions: vec![position],
                }),
            }
        }

        let mut results: Vec<Option<H::Output>> = vec![None; nodes.len()];
        for group in &groups {
            let refs: Vec<&[u8]> = group.keys.iter().map(Vec::as_slice).collect();
            let values = group.store.read(&refs).await.map_err(MmrError::Store)?;
            for (value, position) in values.into_iter().zip(&group.positions) {
                results[*position] = value.and_then(|bytes| H::Output::from_bytes(&bytes));
            }
        }
        Ok(results)
    }

    /// Batched node read from one store under one id.
    async fn read_nodes(
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
            .read(&refs)
            .await?
            .into_iter()
            .map(|value| value.and_then(|bytes| H::Output::from_bytes(&bytes)))
            .collect())
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
            record::hash_value(&delta.state.root(&self.hasher)),
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
    /// metadata. See [`Mmr::open`](super::Mmr::open).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open`](super::Mmr::open).
    pub async fn open(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        let (hasher, store, id, state) = Self::load(hasher, store, id, M::NAME).await?;
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

        let plain = Self::create_with_state(
            hasher,
            store,
            id,
            super::state::MmrState::from_peaks(size, peaks),
        )
        .await?;
        Ok(AsyncMmr {
            hasher: plain.hasher,
            store: plain.store,
            id: plain.id,
            state: plain.state,
            subs: Vec::new(),
            _kind: core::marker::PhantomData,
            _mode: core::marker::PhantomData,
        })
    }

    /// Shared genesis writer; see the sync shell.
    async fn create_with_state(
        hasher: H,
        store: S,
        id: Id,
        state: super::state::MmrState<H>,
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

    /// Shared loader; see the sync shell.
    async fn load(
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
            Table::Root,
        ]
        .iter()
        .map(|table| keys::encode(&id, *table, 0))
        .collect();
        let refs: Vec<&[u8]> = metadata_keys.iter().map(Vec::as_slice).collect();
        let values = store.read(&refs).await.map_err(MmrError::Store)?;

        let missing = |table| MmrError::Corrupted(super::Corrupted::MissingRecord { table });
        let malformed = |table| MmrError::Corrupted(super::Corrupted::MalformedRecord { table });
        let value = |index: usize, table| -> Result<&[u8], MmrError<S>> {
            values
                .get(index)
                .and_then(Option::as_deref)
                .ok_or_else(|| missing(table))
        };

        let (stored_id, stored_config) = record::parse_hasher_info(value(0, Table::HasherInfo)?)
            .ok_or_else(|| malformed(Table::HasherInfo))?;
        if stored_id != hasher.id() || stored_config != hasher.config() {
            return Err(MmrError::Corrupted(super::Corrupted::HasherMismatch {
                stored: alloc::format!("{stored_id} ({stored_config})"),
                supplied: "",
            }));
        }
        let stored_mode =
            record::parse_text(value(1, Table::Mode)?).ok_or_else(|| malformed(Table::Mode))?;
        if stored_mode != declared_mode {
            return Err(MmrError::Corrupted(super::Corrupted::ModeMismatch {
                stored: stored_mode,
                declared: declared_mode,
            }));
        }
        let leaf_count = record::parse_counter(value(2, Table::LeafCount)?)
            .ok_or_else(|| malformed(Table::LeafCount))?;
        let node_count = record::parse_counter(value(3, Table::NodeCount)?)
            .ok_or_else(|| malformed(Table::NodeCount))?;
        let (leaf_count, node_count) = match super::state::checked_counters(leaf_count, node_count)
        {
            super::state::CounterCheck::Ok(leaves, nodes) => (leaves, nodes),
            super::state::CounterCheck::MalformedNodeCount => {
                return Err(malformed(Table::NodeCount));
            }
            super::state::CounterCheck::Mismatch => {
                return Err(MmrError::Corrupted(super::Corrupted::PeaksMismatch {
                    expected: node_count.count_ones() as usize,
                    found: leaf_count.count_ones() as usize,
                }));
            }
        };

        let peak_nodes = peaks_of(node_count);
        let peak_values = Self::read_nodes(&store, id, &peak_nodes)
            .await
            .map_err(MmrError::Store)?;
        let peaks: Vec<H::Output> = peak_values
            .into_iter()
            .map(|value| value.ok_or_else(|| missing(Table::Nodes)))
            .collect::<Result<_, _>>()?;

        let state = super::state::MmrState {
            leaf_count,
            node_count,
            peaks,
            provenance: Provenance::Full,
        };
        let stored_root = value(4, Table::Root)?;
        if record::hash_value(&state.root(&hasher)).as_slice() != stored_root {
            return Err(MmrError::Corrupted(super::Corrupted::RootMismatch));
        }

        Ok((hasher, store, id, state))
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
        AsyncMmr::create(hasher, store, id).await
    }

    /// [`AsyncMmr::open`](Self::open) declaring an [`Editable`]
    /// base. See [`Mmr::open_editable`](super::Mmr::open_editable).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open_editable`](super::Mmr::open_editable).
    pub async fn open_editable(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        AsyncMmr::open(hasher, store, id).await
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
        AsyncMmr::create(hasher, store, id).await
    }

    /// [`AsyncMmr::open`](Self::open) declaring a [`Nullifying`]
    /// base. See [`Mmr::open_nullifying`](super::Mmr::open_nullifying).
    ///
    /// # Errors
    ///
    /// As [`Mmr::open_nullifying`](super::Mmr::open_nullifying).
    pub async fn open_nullifying(hasher: H, store: S, id: Id) -> Result<Self, MmrError<S>> {
        AsyncMmr::open(hasher, store, id).await
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

        let mut loaded = self.load_nodes(&[leaf.node()]).await?;
        let current = loaded.pop().flatten();
        if let Some(expected) = expected_current
            && current != Some(expected)
        {
            return Err(MmrError::UpdateMismatch { leaf });
        }

        let path = sibling_path(leaf, self.state.node_count);
        let indexes: Vec<NodeIndex> = path.iter().map(|step| step.sibling).collect();
        let siblings = if indexes.is_empty() {
            Vec::new()
        } else {
            self.load_nodes(&indexes).await?
        };
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
            previous: current,
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
        let nullified = self.nullify_shallow(leaf).await?;
        let element_hash = self.hasher.hash_leaf(element)?;
        let appended = self.append_hashed(element_hash).await?;
        Ok(ReplaceOutcome {
            root: appended.root,
            nullified: nullified.leaf,
            record: nullified.record,
            appended,
        })
    }

    /// The shared nullifier writer; see the sync shell.
    async fn record_nullifier(
        &mut self,
        leaf: LeafIndex,
        depth: NullifierDepth,
    ) -> Result<super::nullifiers::NullifierRecord, MmrError<S>> {
        if leaf.get() >= self.state.leaf_count.get() {
            return Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from: LeafIndex::FIRST,
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
                .map_err(MmrError::Store)?;
                Ok(super::nullifiers::NullifierRecord::Shallow { at })
            }
            NullifierDepth::Deep => {
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
                match owner {
                    Some((store, id)) => {
                        nullify_record_async(
                            store,
                            id,
                            leaf,
                            super::nullifiers::NullifierRecord::Deep,
                        )
                        .await
                        .map_err(MmrError::Store)?;
                    }
                    None => {
                        nullify_record_async(
                            &self.store,
                            self.id,
                            leaf,
                            super::nullifiers::NullifierRecord::Deep,
                        )
                        .await
                        .map_err(MmrError::Store)?;
                    }
                }
                Ok(super::nullifiers::NullifierRecord::Deep)
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
        let nullified = self.nullify_deep(leaf).await?;
        let element_hash = self.hasher.hash_leaf(element)?;
        let appended = self.append_hashed(element_hash).await?;
        Ok(ReplaceOutcome {
            root: appended.root,
            nullified: nullified.leaf,
            record: nullified.record,
            appended,
        })
    }
}
