//! Incremental Merkle tree: sparse storage, zero-hash ladder,
//! self-contained proofs, and an async twin.
//!
//! The tree is a *sparse* incremental tree of fixed capacity `2^depth`:
//! leaves are set in place (the usual usage in proving systems), the
//! root updates incrementally, and unoccupied leaves hash to the null leaf.
//! Only occupied leaves and their ancestors are stored — creating a tree
//! writes a constant number of records, and an empty tree stores nothing
//! beyond metadata.
//!
//! Unoccupied (virtual) siblings are *computable*, not stored: the
//! zero-hash ladder ([`ZeroLadder`](crate::merkle::ZeroLadder)) supplies their hashes, so proofs for
//! any index within capacity always succeed. Depth, null leaf and hasher
//! identity are persisted at creation and validated on re-open (same
//! mechanism as the MMR).
//!
//! Nodes live under the [`Table::TreeNode`](crate::store::keys::Table::TreeNode) table keyed by the **1-based
//! heap index** (root `1`, leaf `i` at `2^depth + i`); the root is heap node
//! `1`. Unoccupied nodes are never written — reads fall back to the
//! zero-hash ladder.
//!
//! # Proofs are self-contained (like MMR proofs)
//!
//! A single-leaf [`IncrementalMerkleTree::proof`](crate::merkle::IncrementalMerkleTree::proof) returns a
//! [`TreeProof`](crate::merkle::TreeProof) — the sibling path, the depth that shapes it, and the root
//! it commits to. Verification needs no tree and no store:
//! [`verify_proof`](crate::merkle::verify_proof) folds the path with a hasher
//! alone, so a proof travels and verifies
//! anywhere. The handle-level [`IncrementalMerkleTree::verify`](crate::merkle::IncrementalMerkleTree::verify)
//! additionally pins the proof to the tree's *current* root — a proof taken
//! before later writes no longer verifies there; use the standalone
//! verifier for historical checks. Structural truncation is a typed error
//! ([`TreeVerifyError::Inconsistent`](crate::merkle::TreeVerifyError::Inconsistent)); a tampered path simply folds to
//! something other than the proof's own root — `Ok(false)`, never a panic.
//!
//! # Sync core, async shell
//!
//! All state math (metadata validation, the set/proof walks) lives in the
//! pure functions of this module;
//! [`AsyncIncrementalMerkleTree`](crate::merkle::AsyncIncrementalMerkleTree)
//! is the same tree over an [`AsyncStore`](crate::store::AsyncStore),
//! differing only in fetch/commit plumbing — one batched read and one
//! atomic batch write per operation, exactly like the sync shell.

mod async_tree;

pub use async_tree::AsyncIncrementalMerkleTree;

use crate::hashers::HasherError;
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::{HashValue, LeafIndex};
use crate::store::{Batch, Storage, Store, keys, keys::Table, record};
use alloc::vec;
use alloc::vec::Vec;

/// An incremental Merkle tree of fixed capacity `2^depth`.
///
/// Generic over the id type like the MMR handle (`crate::mmr::Mmr`) — the
/// default [`AccumulatorId`] covers the common case.
#[expect(
    missing_debug_implementations,
    reason = "generic over non-Debug store types"
)]
pub struct IncrementalMerkleTree<H: crate::hashers::Hasher, S, Id = AccumulatorId> {
    pub(crate) hasher: H,
    pub(crate) store: S,
    pub(crate) id: Id,
    pub(crate) depth: u8,
    pub(crate) null_leaf: H::Output,
    pub(crate) ladder: ZeroLadder<H::Output>,
    /// Current root — the heap-1 value, maintained on writes and persisted,
    /// so a re-opened tree continues from where the last write left it.
    pub(crate) root: H::Output,
}

/// Precomputed hashes of unoccupied subtrees at every level.
///
/// `ladder[0]` is the null leaf; `ladder[i + 1] = H(ladder[i], ladder[i])`.
/// This is what makes virtual siblings computable without storing them.
#[derive(Clone, Debug)]
pub struct ZeroLadder<O: HashValue> {
    pub(crate) levels: Vec<O>,
}

impl<O: HashValue> ZeroLadder<O> {
    /// Builds the ladder for `depth` levels from a null leaf.
    ///
    /// Infallible: the ladder folds [`crate::hashers::Hasher::hash_pair`]
    /// calls, which are infallible by contract.
    #[must_use]
    pub fn new<H: crate::hashers::Hasher<Output = O>>(hasher: &H, depth: u8, null_leaf: O) -> Self {
        let mut levels = Vec::with_capacity(depth as usize + 1);
        levels.push(null_leaf);
        for level in 0..depth {
            let previous = levels[level as usize];
            levels.push(hasher.hash_pair(previous, previous));
        }
        Self { levels }
    }

    /// Hash of an unoccupied subtree at the given level.
    ///
    /// # Panics
    ///
    /// Panics when `level` exceeds the ladder's depth — the ladder only
    /// holds `depth + 1` levels (0..=depth), and `levels` is built in
    /// [`Self::new`] exactly that long.
    #[must_use]
    pub fn at(&self, level: u8) -> O {
        self.levels[level as usize]
    }
}

/// Outcome of setting a leaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SetOutcome<O: HashValue> {
    /// The leaf that was written.
    pub index: LeafIndex,
    /// Previous hash at this leaf: the leaf's stored value, or the zero-
    /// ladder null leaf when the leaf was unoccupied. Use
    /// [`IncrementalMerkleTree::leaf_hash`] to distinguish an occupied leaf
    /// from an unoccupied one (a leaf can legitimately hold the null value).
    pub previous: O,
    /// New root after the write.
    pub root: O,
}

/// Tree-level errors. Generic over [`Storage`] — shares the sync/async
/// error-unification model of the MMR's `MmrError`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TreeError<S: Storage> {
    /// Store I/O failed.
    #[error("store error")]
    Store(#[source] S::Error),

    /// Element ingestion failed.
    #[error("invalid element")]
    Hasher(#[from] HasherError),

    /// Index at or beyond capacity `2^depth`.
    #[error("leaf {index} is beyond capacity {capacity}")]
    IndexOutOfRange {
        /// The rejected leaf.
        index: LeafIndex,
        /// The tree's capacity.
        capacity: u64,
    },

    /// Update rejected because the supplied current value doesn't match.
    #[error("update rejected: leaf {index} is not occupied by the expected value")]
    UpdateMismatch {
        /// The rejected leaf.
        index: LeafIndex,
    },

    /// Caller-supplied depth is out of range (valid: 1..=63).
    #[error("invalid tree depth {depth}: must be between 1 and 63")]
    InvalidDepth {
        /// The rejected depth.
        depth: u8,
    },

    /// A multiproof of zero leaves was requested — there is nothing to
    /// prove, and the verifier could never reproduce a root from an empty
    /// proof.
    #[error("multiproof of zero leaves")]
    EmptyProof,

    /// Persisted metadata is missing or inconsistent.
    #[error("tree metadata is missing or inconsistent: {0}")]
    Corrupted(#[source] TreeCorrupted),

    /// Proof verification could not be attempted.
    #[error("could not verify proof: {0}")]
    Proof(#[from] TreeVerifyError),

    /// The caller-supplied hasher's identity/config cannot be represented in
    /// the persisted metadata (an over-long hasher name/config) — rejected
    /// at creation instead of persisting a record that would brick every
    /// later open. Distinct from [`TreeError::Corrupted`]: the store is
    /// fine, the input is not.
    #[error("hasher identity cannot be represented in the persisted metadata")]
    UnrepresentableHasher,
}

/// Specific corruption findings when re-opening a tree — the granular
/// counterpart of the MMR's `Corrupted` error kind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TreeCorrupted {
    /// Required metadata records are absent.
    #[error("metadata records missing")]
    MissingMetadata,
    /// A metadata record exists but cannot be parsed (wrong length, invalid
    /// hasher tag, out-of-range depth).
    #[error("metadata record is malformed")]
    MalformedMetadata,
    /// Persisted hasher id/config differs from the hasher in use.
    #[error("hasher mismatch: store has {stored}, caller supplied {supplied}")]
    HasherMismatch {
        /// Hasher identity/config recorded at creation (read from the store).
        stored: alloc::string::String,
        /// Hasher passed to the constructor, rendered as `id (config)`.
        supplied: alloc::string::String,
    },
    /// A node value exists but cannot be parsed as a hash value — a corrupt
    /// record, distinct from an unoccupied node (which is the zero ladder).
    #[error("tree node value is malformed")]
    MalformedNode,
}

// ------------------------------------------------------------- pure core

/// Heap index of leaf `i` in a tree of `depth` levels.
pub(crate) const fn leaf_heap(depth: u8, index: LeafIndex) -> u64 {
    (1_u64 << depth) + index.get()
}

/// Validates a caller-supplied tree depth (valid: 1..=63).
pub(crate) fn check_depth<S: Storage>(depth: u8) -> Result<(), TreeError<S>> {
    if depth == 0 || depth > 63 {
        return Err(TreeError::InvalidDepth { depth });
    }
    Ok(())
}

/// Rejects a leaf index at or beyond `capacity`.
pub(crate) fn check_index<S: Storage>(capacity: u64, index: LeafIndex) -> Result<(), TreeError<S>> {
    if index.get() >= capacity {
        return Err(TreeError::IndexOutOfRange { index, capacity });
    }
    Ok(())
}

/// Builds the genesis batch: hasher identity, depth/null-leaf metadata, and
/// the empty root (the ladder's top, persisted as heap node 1). Returns the
/// batch and the ladder it was built from. Pure — the shells only write it.
///
/// # Errors
///
/// [`TreeError::UnrepresentableHasher`] when the hasher's identity/config
/// cannot be represented in the persisted metadata.
pub(crate) fn create_batch<S: Storage, H: crate::hashers::Hasher, Id: TreeId>(
    hasher: &H,
    tree_id: &Id,
    depth: u8,
    null_leaf: H::Output,
) -> Result<(Batch<'static>, ZeroLadder<H::Output>), TreeError<S>> {
    let ladder = ZeroLadder::new(hasher, depth, null_leaf);

    let mut batch = Batch::new();
    batch.put_owned(
        keys::encode(tree_id, Table::HasherInfo, 0),
        record::hasher_info(hasher).ok_or(TreeError::UnrepresentableHasher)?,
    );
    batch.put_owned(keys::encode(tree_id, Table::TreeMeta, 0), {
        let mut meta = Vec::with_capacity(1 + H::Output::LEN);
        meta.push(depth);
        meta.extend_from_slice(null_leaf.to_vec().as_slice());
        meta
    });
    // The empty root: heap node 1 = the top of the ladder.
    batch.put_owned(
        keys::encode(tree_id, Table::TreeNode, 1),
        record::hash_value(&ladder.at(depth)),
    );
    Ok((batch, ladder))
}

/// The persisted-metadata keys, in read order: hasher info, tree meta, root.
pub(crate) fn metadata_keys<Id: TreeId>(id: &Id) -> Vec<Vec<u8>> {
    vec![
        keys::encode(id, Table::HasherInfo, 0),
        keys::encode(id, Table::TreeMeta, 0),
        keys::encode(id, Table::TreeNode, 1),
    ]
}

/// Validates the persisted metadata triple against the supplied hasher:
/// hasher identity/config byte-for-byte, depth in 1..=63, null leaf and
/// root parsing as hash values. Returns the tree's shape and cached root.
///
/// # Errors
///
/// [`TreeCorrupted::HasherMismatch`] or [`TreeCorrupted::MalformedMetadata`].
pub(crate) fn validate_metadata<H: crate::hashers::Hasher>(
    hasher: &H,
    hasher_info: &[u8],
    tree_meta: &[u8],
    root: &[u8],
) -> Result<(u8, H::Output, H::Output), TreeCorrupted> {
    let malformed = || TreeCorrupted::MalformedMetadata;
    let (stored_id, stored_config) =
        record::parse_hasher_info(hasher_info).ok_or_else(malformed)?;
    if stored_id != hasher.id() || stored_config != hasher.config() {
        return Err(TreeCorrupted::HasherMismatch {
            stored: alloc::format!("{stored_id} ({stored_config})"),
            supplied: alloc::format!("{} ({})", hasher.id(), hasher.config()),
        });
    }

    let depth = *tree_meta.first().ok_or_else(malformed)?;
    if depth == 0 || depth > 63 {
        return Err(malformed());
    }
    // `from_bytes` validates the exact length.
    let Some(null_bytes) = tree_meta.get(1..) else {
        return Err(malformed());
    };
    let null_leaf = H::Output::from_bytes(null_bytes).ok_or_else(malformed)?;

    // The root is whatever the last write left; its shape is validated
    // by the HashValue parse.
    let root = H::Output::from_bytes(root).ok_or_else(malformed)?;
    Ok((depth, null_leaf, root))
}

/// Parses one loaded node record: `None` for unoccupied, the hash value for
/// a present record, [`TreeCorrupted::MalformedNode`] for a present-but-
/// unparsable one — it must never read as unoccupied (the caller would
/// silently substitute the ladder's zero hash, producing a wrong proof and
/// a corrupted root on the next write).
pub(crate) fn parse_node_value<O: HashValue>(
    value: Option<Vec<u8>>,
) -> Result<Option<O>, TreeCorrupted> {
    match value {
        None => Ok(None),
        Some(bytes) => O::from_bytes(&bytes)
            .map(Some)
            .ok_or(TreeCorrupted::MalformedNode),
    }
}

/// The pure result of planning a leaf write from the loaded nodes:
/// everything the one batch write commits, plus the gate's `previous` value.
pub(crate) struct SetPlan<O: HashValue> {
    /// Previous hash at the leaf: the leaf's stored value, or the ladder's
    /// null leaf when the leaf was unoccupied.
    pub previous: O,
    /// Every changed `(heap index, value)` pair, leaf → root.
    pub changed: Vec<(u64, O)>,
    /// The new root (heap node 1).
    pub root: O,
}

/// The heap indexes a `set_leaf` must read: the leaf plus every sibling on
/// its path to the root.
pub(crate) fn set_read_heaps(depth: u8, index: LeafIndex) -> Vec<u64> {
    let mut needed: Vec<u64> = Vec::with_capacity(depth as usize + 1);
    let mut heap = leaf_heap(depth, index);
    needed.push(heap);
    for _ in 0..depth {
        needed.push(heap ^ 1);
        heap >>= 1;
    }
    needed
}

/// Plans a leaf write from the loaded nodes ([`set_read_heaps`] order):
/// the `expected_current` gate, then the walk up collecting every changed
/// node; unoccupied siblings come from the ladder. Pure — the shells gate,
/// then commit [`SetPlan::changed`] as one atomic batch.
///
/// # Errors
///
/// [`TreeError::UpdateMismatch`] when the gate rejects.
pub(crate) fn plan_set<S: Storage, H: crate::hashers::Hasher>(
    hasher: &H,
    depth: u8,
    index: LeafIndex,
    ladder: &ZeroLadder<H::Output>,
    loaded: &[Option<H::Output>],
    new_hash: H::Output,
    expected_current: Option<H::Output>,
) -> Result<SetPlan<H::Output>, TreeError<S>> {
    // Occupied → stored value; unoccupied → the zero-ladder null leaf
    // (see `SetOutcome::previous`).
    let previous = loaded[0].unwrap_or_else(|| ladder.at(0));
    if let Some(expected) = expected_current
        && previous != expected
    {
        return Err(TreeError::UpdateMismatch { index });
    }

    // Walk up: sibling from the batched read or the ladder; collect
    // every changed node for the one batch write.
    let mut hash = new_hash;
    let mut heap = leaf_heap(depth, index);
    let mut changed = vec![(heap, hash)];
    for (level, sibling) in loaded[1..].iter().enumerate() {
        // `level < siblings.len() == depth`, and depth <= 63 is
        // validated at create/open, so it always fits in u8.
        #[expect(
            clippy::cast_possible_truncation,
            reason = "level < depth <= 63 (validated at create/open)"
        )]
        let level = level as u8;
        let sibling = sibling.unwrap_or_else(|| ladder.at(level));
        hash = if heap & 1 == 1 {
            // Node is the right child: sibling sits on the left.
            hasher.hash_pair(sibling, hash)
        } else {
            hasher.hash_pair(hash, sibling)
        };
        heap >>= 1;
        changed.push((heap, hash));
    }

    Ok(SetPlan {
        previous,
        changed,
        root: hash,
    })
}

/// The sibling heap indexes of a leaf's proof path, bottom-up.
pub(crate) fn proof_read_heaps(depth: u8, index: LeafIndex) -> Vec<u64> {
    let mut heap = leaf_heap(depth, index);
    (0..depth)
        .map(|_| {
            let sibling = heap ^ 1;
            heap >>= 1;
            sibling
        })
        .collect()
}

/// Materializes a proof from the loaded sibling records (in
/// [`proof_read_heaps`] order): unoccupied siblings are substituted from
/// the ladder. Pure.
pub(crate) fn build_proof<O: HashValue>(
    depth: u8,
    index: LeafIndex,
    loaded: Vec<Option<O>>,
    ladder: &ZeroLadder<O>,
    root: O,
) -> TreeProof<O> {
    let siblings = loaded
        .into_iter()
        .enumerate()
        .map(|(level, value)| {
            // `level < siblings.len() == depth`, and depth <= 63 is
            // validated at create/open, so it always fits in u8.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "level < depth <= 63 (validated at create/open)"
            )]
            let level = level as u8;
            value.unwrap_or_else(|| ladder.at(level))
        })
        .collect();
    TreeProof {
        index,
        siblings,
        root,
        depth,
    }
}

/// Normalizes the requested indexes (ascending, unique, in range) and
/// collects the heap indexes of the minimal sibling set covering all of
/// them. Pure; the shells load exactly these nodes.
///
/// # Errors
///
/// [`TreeError::EmptyProof`] for an empty index set,
/// [`TreeError::IndexOutOfRange`] for any index at or beyond `capacity`.
pub(crate) fn plan_multiproof<S: Storage>(
    depth: u8,
    capacity: u64,
    indexes: impl IntoIterator<Item = LeafIndex>,
) -> Result<(Vec<LeafIndex>, Vec<u64>), TreeError<S>> {
    let mut indexes: Vec<LeafIndex> = indexes.into_iter().collect();
    if indexes.is_empty() {
        return Err(TreeError::EmptyProof);
    }
    indexes.sort_unstable();
    indexes.dedup();
    for &index in &indexes {
        check_index::<S>(capacity, index)?;
    }
    let needed = multiproof_walk(depth, &indexes);
    Ok((indexes, needed))
}

/// The pure multiproof walk: the minimal sibling-set heap indexes covering
/// `indexes`, bottom-up, level by level, left to right within a level.
/// Siblings already in the claimed set are merged, not proven. The walk is
/// deterministic in `depth` and the indexes alone — the verifier replays it
/// to check the proof's sibling budget.
pub(crate) fn multiproof_walk(depth: u8, indexes: &[LeafIndex]) -> Vec<u64> {
    let mut current: Vec<u64> = indexes.iter().map(|i| leaf_heap(depth, *i)).collect();
    let mut needed: Vec<u64> = Vec::new();
    for _ in 0..depth {
        let mut next = Vec::with_capacity(current.len());
        for &node in &current {
            let sibling = node ^ 1;
            if current.binary_search(&sibling).is_err() {
                needed.push(sibling);
            }
            let parent = node >> 1;
            if next.last() != Some(&parent) {
                next.push(parent);
            }
        }
        current = next;
    }
    needed
}

/// Materializes the multiproof from the loaded records (in
/// [`multiproof_walk`] order): unoccupied nodes come from the ladder at
/// `depth − ilog2(heap)`. Pure.
pub(crate) fn build_multiproof<O: HashValue>(
    depth: u8,
    indexes: Vec<LeafIndex>,
    needed: Vec<u64>,
    loaded: Vec<Option<O>>,
    ladder: &ZeroLadder<O>,
    root: O,
) -> TreeMultiProof<O> {
    let siblings = needed
        .into_iter()
        .zip(loaded)
        .map(|(heap, value)| {
            // The ladder is indexed from the leaf: a node at heap index
            // `h` covers a subtree of height `depth − ilog2(h)`, so its
            // unoccupied hash is `ladder[depth − ilog2(h)]`. Every heap
            // node here is >= 1, so ilog2() <= depth <= 63.
            #[expect(
                clippy::cast_possible_truncation,
                reason = "heap >= 1 so ilog2() <= depth <= 63, which fits in u8"
            )]
            let level = depth - heap.ilog2() as u8;
            value.unwrap_or_else(|| ladder.at(level))
        })
        .collect();

    TreeMultiProof {
        indexes,
        siblings,
        depth,
        root,
    }
}

// ------------------------------------------------------- the sync shell

impl<H: crate::hashers::Hasher, S: Store, Id: TreeId> IncrementalMerkleTree<H, S, Id> {
    /// Creates a new tree and persists its metadata (a constant number of
    /// writes; the empty tree stores nothing beyond the null root).
    ///
    /// # Errors
    ///
    /// Store failures, hasher failures (the null leaf is hashed into the
    /// ladder), or an out-of-range `depth` ([`TreeError::InvalidDepth`]).
    pub fn create(
        hasher: H,
        store: S,
        id: Id,
        depth: u8,
        null_leaf: H::Output,
    ) -> Result<Self, TreeError<S>> {
        check_depth::<S>(depth)?;
        let (batch, ladder) = create_batch::<S, H, Id>(&hasher, &id, depth, null_leaf)?;
        store.write(batch).map_err(TreeError::Store)?;

        let root = ladder.at(depth);
        Ok(Self {
            hasher,
            store,
            id,
            depth,
            null_leaf,
            ladder,
            root,
        })
    }

    /// Re-opens an existing tree, validating persisted depth/null/hasher
    /// metadata against the supplied hasher.
    ///
    /// # Errors
    ///
    /// [`TreeError::Corrupted`] or store failures.
    pub fn open(hasher: H, store: S, id: Id) -> Result<Self, TreeError<S>> {
        let encoded = metadata_keys(&id);
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        let values = store.read(&refs).map_err(TreeError::Store)?;

        let missing = || TreeError::Corrupted(TreeCorrupted::MissingMetadata);
        let value = |index: usize| -> Result<&[u8], TreeError<S>> {
            values
                .get(index)
                .and_then(Option::as_deref)
                .ok_or_else(missing)
        };

        let (depth, null_leaf, root) = validate_metadata(&hasher, value(0)?, value(1)?, value(2)?)
            .map_err(TreeError::Corrupted)?;

        let ladder = ZeroLadder::new(&hasher, depth, null_leaf);
        Ok(Self {
            hasher,
            store,
            id,
            depth,
            null_leaf,
            ladder,
            root,
        })
    }

    /// Current root (incremental — recomputed on writes, read from cache).
    #[must_use]
    pub const fn root(&self) -> H::Output {
        self.root
    }

    /// The tree's capacity: `2^depth`.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        1_u64 << self.depth
    }

    /// The null leaf — the hash unoccupied leaves contribute.
    #[must_use]
    pub const fn null_leaf(&self) -> H::Output {
        self.null_leaf
    }

    /// The stored hash of a leaf, or `None` when the leaf is unoccupied
    /// (never the ladder's null value — an occupied leaf may legitimately
    /// hold it, so the `Option` is the only honest occupied/unoccupied
    /// distinction). Mirrors the MMR's `leaf_hash` and sources
    /// [`Self::set_leaf`]'s `expected_current` gate; one single-key read.
    ///
    /// # Errors
    ///
    /// [`TreeError::IndexOutOfRange`] beyond capacity, a malformed node
    /// record, or store failures.
    pub fn leaf_hash(&self, index: LeafIndex) -> Result<Option<H::Output>, TreeError<S>> {
        check_index::<S>(self.capacity(), index)?;
        Ok(self
            .load_nodes(&[leaf_heap(self.depth, index)])?
            .pop()
            .flatten())
    }

    /// Sets a leaf in place. Writing over an occupied leaf requires the
    /// current value.
    ///
    /// Gate semantics: `None` writes unconditionally (including over an
    /// occupied leaf); `Some(expected)` is a compare-and-swap — the write
    /// proceeds only when the leaf's current value equals `expected`
    /// ([`Self::leaf_hash`] sources it; an unoccupied leaf's current value
    /// is [`Self::null_leaf`]). Like the nullifier records, the gate reads
    /// and writes through `&self`-style non-atomic access: the check and the
    /// write are **not** a single atomic transaction, so the gate protects
    /// against acting on stale reads, not against concurrent writers to the
    /// same tree. **Single-writer per tree** is the operating assumption —
    /// concurrent `set_leaf` calls through separate handles can lose updates
    /// (last write wins at the store).
    ///
    /// # Errors
    ///
    /// [`TreeError::UpdateMismatch`] when `expected_current` doesn't match,
    /// [`TreeError::IndexOutOfRange`] beyond capacity, store/hasher failures
    /// otherwise.
    pub fn set_leaf(
        &mut self,
        index: LeafIndex,
        element: &[u8],
        expected_current: Option<H::Output>,
    ) -> Result<SetOutcome<H::Output>, TreeError<S>> {
        check_index::<S>(self.capacity(), index)?;
        let new_hash = self.hasher.hash_leaf(element)?;

        // One batched read for the leaf and all its siblings; unoccupied
        // nodes fall back to the zero ladder.
        let loaded = self.load_nodes(&set_read_heaps(self.depth, index))?;
        let plan = plan_set(
            &self.hasher,
            self.depth,
            index,
            &self.ladder,
            &loaded,
            new_hash,
            expected_current,
        )?;

        let mut batch = Batch::new();
        for (node, value) in &plan.changed {
            batch.put_owned(
                keys::encode(&self.id, Table::TreeNode, *node),
                record::hash_value(value),
            );
        }
        self.store.write(batch).map_err(TreeError::Store)?;
        self.root = plan.root;

        Ok(SetOutcome {
            index,
            previous: plan.previous,
            root: plan.root,
        })
    }

    /// Inclusion proof for a leaf: sibling hashes leaf→root, virtual
    /// siblings materialized from the ladder. Always succeeds within
    /// capacity. The proof is self-contained — it carries the root it
    /// commits to (see the module note) and verifies with no store.
    ///
    /// # Errors
    ///
    /// [`TreeError::IndexOutOfRange`] or store failures.
    pub fn proof(&self, index: LeafIndex) -> Result<TreeProof<H::Output>, TreeError<S>> {
        check_index::<S>(self.capacity(), index)?;
        let loaded = self.load_nodes(&proof_read_heaps(self.depth, index))?;
        Ok(build_proof(
            self.depth,
            index,
            loaded,
            &self.ladder,
            self.root,
        ))
    }

    /// Verifies a proof against this tree's *current* root. No store access.
    ///
    /// The proof's own commitment is validated standalone (see
    /// [`verify_proof`]) and its root must equal the current one — a proof
    /// taken before later writes no longer verifies here; use
    /// [`verify_proof`] for historical checks.
    ///
    /// # Errors
    ///
    /// [`TreeError::Proof`] when the proof is structurally inconsistent
    /// (truncation is a typed error, not a negative result); hasher
    /// failures.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify(
        &self,
        proof: &TreeProof<H::Output>,
        element: &[u8],
    ) -> Result<bool, TreeError<S>> {
        let valid = verify_proof(&self.hasher, proof, element)?;
        Ok(valid && proof.root == self.root)
    }

    /// Multi-leaf proof: minimal sibling set covering all requested leaves,
    /// returned as an explicit structure. Self-contained like [`TreeProof`]:
    /// the proof carries the root its replayed paths must reproduce.
    ///
    /// An empty index set is rejected: a proof of zero leaves carries no
    /// commitment, and letting the producer accept it while the verifier
    /// returns `Ok(false)` would be a self-inconsistency between the two
    /// halves.
    ///
    /// # Errors
    ///
    /// [`TreeError::IndexOutOfRange`] or store failures;
    /// [`TreeError::EmptyProof`] for an empty index set.
    pub fn multiproof<I>(&self, indexes: I) -> Result<TreeMultiProof<H::Output>, TreeError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let (indexes, needed) = plan_multiproof::<S>(self.depth, self.capacity(), indexes)?;
        let loaded = self.load_nodes(&needed)?;
        Ok(build_multiproof(
            self.depth,
            indexes,
            needed,
            loaded,
            &self.ladder,
            self.root,
        ))
    }

    /// Verifies a multi-leaf proof against this tree's *current* root —
    /// consuming the proof's structural contract (see [`TreeMultiProof`]'s
    /// ordering documentation). No store access.
    ///
    /// The standalone check (see [`verify_multi_proof`]) is validated first;
    /// the proof's root must then equal the current one. A captured
    /// multiproof verifies against historical roots through
    /// [`verify_multi_proof`]. An empty proof (zero indexes — hand-built;
    /// [`Self::multiproof`] rejects producing one) never verifies.
    ///
    /// `elements` must align positionally with the proof's indexes.
    ///
    /// # Errors
    ///
    /// [`TreeError::Proof`] when the proof is structurally inconsistent;
    /// hasher failures.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify_multi<I>(
        &self,
        proof: &TreeMultiProof<H::Output>,
        elements: I,
    ) -> Result<bool, TreeError<S>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let valid = verify_multi_proof(&self.hasher, proof, elements)?;
        Ok(valid && proof.root == self.root)
    }

    /// Batched heap-node read from the store; the sync twin of the async
    /// shell's loader. Parsing goes through [`parse_node_value`].
    fn load_nodes(&self, heaps: &[u64]) -> Result<Vec<Option<H::Output>>, TreeError<S>> {
        let encoded: Vec<Vec<u8>> = heaps
            .iter()
            .map(|heap| keys::encode(&self.id, Table::TreeNode, *heap))
            .collect();
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        self.store
            .read(&refs)
            .map_err(TreeError::Store)?
            .into_iter()
            .map(parse_node_value)
            .collect::<Result<_, _>>()
            .map_err(TreeError::Corrupted)
    }
}

// ------------------------------------------------- self-contained proofs

/// An inclusion proof for one leaf: a complete, standalone commitment.
///
/// Carries the root it was taken at and the depth that shapes its path, so
/// verification needs no tree and no store — mirroring the MMR's
/// [`crate::mmr::Proof`]. [`verify_proof`] folds the path with a hasher
/// alone; the handle-level [`IncrementalMerkleTree::verify`] additionally
/// pins the proof to the tree's *current* root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeProof<O: HashValue> {
    /// The proven leaf.
    pub index: LeafIndex,
    /// Sibling hashes bottom-up, leaf → root; exactly `depth` of them.
    /// Unoccupied siblings are materialized from the zero ladder at
    /// generation time — the verifier never needs the ladder.
    pub siblings: Vec<O>,
    /// The root at proof time: the commitment this path terminates against.
    pub root: O,
    /// Tree depth the proof was built at (path length and capacity bound:
    /// `index` must be below `2^depth`).
    pub depth: u8,
}

/// Multi-leaf proof with explicit structure.
///
/// # Ordering (part of this type's contract)
///
/// - `indexes` ascending, `elements` (supplied to the verifier) positionally
///   paired with them,
/// - `siblings` emitted bottom-up, level by level, left to right within a
///   level; the verifier walks levels front-to-back, pairing each merge with
///   the next sibling it needs from the front of the list.
///
/// Self-contained like [`TreeProof`]: `root` is the commitment the replayed
/// paths must reproduce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeMultiProof<O: HashValue> {
    /// Proven leaf indexes, ascending.
    pub indexes: Vec<LeafIndex>,
    /// The minimal sibling hash set — bottom-up, level by level, left to
    /// right within a level (see the ordering contract above).
    pub siblings: Vec<O>,
    /// Tree depth the proof was built at.
    pub depth: u8,
    /// The root at proof time: the commitment the replay must reproduce.
    pub root: O,
}

/// Proof verification failures that are *not* negative results.
///
/// A path that folds somewhere other than the proof's own root is
/// `Ok(false)` — tamper, not error. Errors here mean "verification could
/// not be attempted": the proof contradicts its own structure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TreeVerifyError {
    /// The proof is internally inconsistent (see [`TreeProofInconsistent`]).
    #[error("proof is internally inconsistent: {0}")]
    Inconsistent(#[source] TreeProofInconsistent),

    /// Hasher rejected an input while re-deriving hashes.
    #[error("hasher rejected proof data")]
    Hasher(#[from] HasherError),
}

/// Ways a tree proof can be structurally invalid before any hashing.
///
/// Exhaustive over the structural contract of [`TreeProof`] and
/// [`TreeMultiProof`]. A standalone `Ok(true)` means the proof is
/// *self-consistent* — its path(s) reproduce its own root; it authenticates
/// nothing by itself. Authentication is the root comparison: the
/// handle-level `verify`/`verify_multi` pin the proof to the tree's current
/// root, and standalone users compare `proof.root` against a root they
/// trust from elsewhere. Verification re-derives every conclusion and never
/// trusts the proof's own claims, so a fabricated proof can at worst
/// produce `Ok(false)` — never a panic and never a false `Ok(true)` relative
/// to the compared roots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TreeProofInconsistent {
    /// Proof depth outside the valid range 1..=63 — no real tree can have
    /// produced it.
    #[error("proof depth {depth} is outside the valid range 1..=63")]
    InvalidDepth {
        /// The rejected depth.
        depth: u8,
    },
    /// Sibling count does not match the path length implied by the proof's
    /// depth (a truncated or over-long sibling list).
    #[error(
        "sibling count {siblings} does not match the path length {expected} implied by depth {depth}"
    )]
    PathLengthMismatch {
        /// Actual sibling count.
        siblings: usize,
        /// Expected path length (`depth`).
        expected: usize,
        /// The proof's claimed depth.
        depth: u8,
    },
    /// The proven leaf is at or beyond the capacity `2^depth` its depth
    /// implies.
    #[error("leaf {index} is beyond the proof's capacity {capacity}")]
    LeafOutOfRange {
        /// The out-of-range leaf.
        index: LeafIndex,
        /// Capacity implied by the proof depth.
        capacity: u64,
    },
    /// The supplied element set does not align with the proof's indexes.
    #[error("{leaves} proven leaves but {elements} elements supplied")]
    ElementCountMismatch {
        /// Number of leaves in the proof.
        leaves: usize,
        /// Number of elements supplied for verification.
        elements: usize,
    },
    /// A multiproof lists the same leaf twice.
    #[error("leaf {index} appears more than once in the multiproof")]
    DuplicateLeaf {
        /// The duplicated leaf.
        index: LeafIndex,
    },
    /// A multiproof's leaves are not ascending (the canonical order
    /// [`TreeMultiProof::indexes`] documents).
    #[error("multiproof leaves must be ascending: {first} then {second}")]
    UnsortedLeaves {
        /// The earlier, larger leaf.
        first: LeafIndex,
        /// The later, smaller leaf.
        second: LeafIndex,
    },
    /// A multiproof's sibling count does not match the minimal set the
    /// claimed leaves need. The count is derivable from the indexes alone,
    /// so a disagreement is structural (truncation), not tamper.
    #[error("sibling count {siblings} does not match the {expected} the claimed leaves need")]
    SiblingCountMismatch {
        /// Actual sibling count.
        siblings: usize,
        /// Minimal sibling count for the claimed indexes.
        expected: usize,
    },
}

/// Verifies a single-leaf proof against its own commitment — no tree, no
/// store.
///
/// Recomputes the leaf hash, folds the sibling path (each step's side is
/// re-derived from the heap layout, never trusted from the proof), and
/// compares to the proof's root. `Ok(false)` means the proof is validly
/// structured but does not commit to `element`.
///
/// Trust model: `Ok(true)` certifies the proof is **self-consistent** —
/// internally coherent, authentic only relative to a root the verifier
/// trusts. The handle-level [`IncrementalMerkleTree::verify`] compares
/// against the tree's current root; standalone users compare `proof.root`
/// against a root obtained from a source they trust. A fabricated
/// self-consistent proof is not detected by this function alone.
///
/// # Errors
///
/// Structural inconsistency (see [`TreeVerifyError`]) or hasher failure.
pub fn verify_proof<H: crate::hashers::Hasher>(
    hasher: &H,
    proof: &TreeProof<H::Output>,
    element: &[u8],
) -> Result<bool, TreeVerifyError> {
    let inconsistent = |error| TreeVerifyError::Inconsistent(error);
    if !(1..=63).contains(&proof.depth) {
        return Err(inconsistent(TreeProofInconsistent::InvalidDepth {
            depth: proof.depth,
        }));
    }
    if proof.siblings.len() != usize::from(proof.depth) {
        return Err(inconsistent(TreeProofInconsistent::PathLengthMismatch {
            siblings: proof.siblings.len(),
            expected: usize::from(proof.depth),
            depth: proof.depth,
        }));
    }
    if proof.index.get() >= 1_u64 << proof.depth {
        return Err(inconsistent(TreeProofInconsistent::LeafOutOfRange {
            index: proof.index,
            capacity: 1_u64 << proof.depth,
        }));
    }

    let mut hash = hasher.hash_leaf(element)?;
    let mut heap = leaf_heap(proof.depth, proof.index);
    for sibling in &proof.siblings {
        hash = if heap & 1 == 1 {
            hasher.hash_pair(*sibling, hash)
        } else {
            hasher.hash_pair(hash, *sibling)
        };
        heap >>= 1;
    }
    Ok(hash == proof.root)
}

/// Verifies a multi-leaf proof against its own commitment — no tree, no
/// store. Consumes the proof's structural contract (see
/// [`TreeMultiProof`]'s ordering documentation).
///
/// `elements` must align positionally with the proof's indexes. The
/// multiproof's sibling budget is checked structurally before the replay:
/// the minimal sibling set for the claimed indexes is derivable from the
/// indexes alone, so a truncated sibling list is a typed error, while a
/// wrong sibling *value* simply folds to something other than the proof's
/// root (`Ok(false)`).
///
/// # Errors
///
/// Structural inconsistency (see [`TreeVerifyError`]) or hasher failure.
pub fn verify_multi_proof<H, I>(
    hasher: &H,
    proof: &TreeMultiProof<H::Output>,
    elements: I,
) -> Result<bool, TreeVerifyError>
where
    H: crate::hashers::Hasher,
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    // Element-count alignment first (before hashing — wasted work on a
    // misaligned call), then the structural contract, then the sibling
    // budget, and only then the hashed replay.
    let elements: Vec<I::Item> = elements.into_iter().collect();
    let inconsistent = |error| TreeVerifyError::Inconsistent(error);
    if elements.len() != proof.indexes.len() {
        return Err(inconsistent(TreeProofInconsistent::ElementCountMismatch {
            leaves: proof.indexes.len(),
            elements: elements.len(),
        }));
    }
    if !(1..=63).contains(&proof.depth) {
        return Err(inconsistent(TreeProofInconsistent::InvalidDepth {
            depth: proof.depth,
        }));
    }
    for pair in proof.indexes.windows(2) {
        if pair[0] == pair[1] {
            return Err(inconsistent(TreeProofInconsistent::DuplicateLeaf {
                index: pair[0],
            }));
        }
        if pair[0] > pair[1] {
            return Err(inconsistent(TreeProofInconsistent::UnsortedLeaves {
                first: pair[0],
                second: pair[1],
            }));
        }
    }
    for &index in &proof.indexes {
        if index.get() >= 1_u64 << proof.depth {
            return Err(inconsistent(TreeProofInconsistent::LeafOutOfRange {
                index,
                capacity: 1_u64 << proof.depth,
            }));
        }
    }

    // The sibling budget is validated before the replay: a malformed count
    // is an `Err` even when a replayed prefix would already fail to commit.
    let expected = multiproof_walk(proof.depth, &proof.indexes).len();
    if proof.siblings.len() != expected {
        return Err(inconsistent(TreeProofInconsistent::SiblingCountMismatch {
            siblings: proof.siblings.len(),
            expected,
        }));
    }

    // Replay the level walk: values per level for the claimed nodes. The
    // walk mirrors proof generation exactly, so with the budget enforced
    // above every needed sibling is consumed from the front of the list.
    let mut values: Vec<(u64, H::Output)> = Vec::with_capacity(proof.indexes.len());
    for (index, element) in proof.indexes.iter().zip(elements) {
        values.push((
            leaf_heap(proof.depth, *index),
            hasher.hash_leaf(element.as_ref())?,
        ));
    }
    let mut siblings = proof.siblings.iter().copied();

    for _ in 0..proof.depth {
        let mut next: Vec<(u64, H::Output)> = Vec::with_capacity(values.len());
        let mut index_into_values = 0;
        while index_into_values < values.len() {
            let (node, hash) = values[index_into_values];
            let sibling = node ^ 1;
            // The set is sorted; a merge partner sits next to it.
            if index_into_values + 1 < values.len() && values[index_into_values + 1].0 == sibling {
                let (_, sibling_hash) = values[index_into_values + 1];
                let parent_hash = if node & 1 == 1 {
                    hasher.hash_pair(sibling_hash, hash)
                } else {
                    hasher.hash_pair(hash, sibling_hash)
                };
                next.push((node >> 1, parent_hash));
                index_into_values += 2;
                continue;
            }
            // Needs a proof sibling: they appear left-to-right within the
            // level, matching this walk's order. Unreachable with the
            // budget enforced above — a defensive no-panic guard.
            let Some(proof_sibling) = siblings.next() else {
                return Ok(false);
            };
            let parent_hash = if node & 1 == 1 {
                hasher.hash_pair(proof_sibling, hash)
            } else {
                hasher.hash_pair(hash, proof_sibling)
            };
            next.push((node >> 1, parent_hash));
            index_into_values += 1;
        }
        values = next;
    }

    // Every proof sibling must be consumed, and the final single value
    // (heap node 1) is the proof's own root.
    if siblings.next().is_some() {
        return Ok(false);
    }
    Ok(values.len() == 1 && values[0].1 == proof.root)
}
