//! The tree's pure math: heap-index algebra, metadata codecs, and the
//! write/proof planners the shells share. No store access — every function
//! here takes loaded records and returns values or plans.

use super::{TreeCorrupted, TreeError, TreeMultiProof, TreeProof, ZeroLadder};
use crate::ids::TreeId;
use crate::primitives::{HashValue, LeafIndex};
use crate::store::keys::Table;
use crate::store::{Batch, Storage, keys, record};
use alloc::vec;
use alloc::vec::Vec;

/// Heap index of leaf `i` in a tree of `depth` levels: the 1-based heap
/// position under the root at `1` — root `1`, leaf `i` at `2^depth + i`.
/// This is the subkey the `TreeNode` table is keyed by (see the store's
/// key spec); [`heap_level_and_index`] decodes it back.
///
/// ```
/// # #[cfg(feature = "merkle_tree")]
/// # fn leaf_heap_decodes() {
/// use accumulators::merkle::math::leaf_heap;
/// use accumulators::primitives::LeafIndex;
///
/// // A depth-3 tree's leaves start at heap index 8.
/// assert_eq!(leaf_heap(3, LeafIndex::new(0)), 8);
/// assert_eq!(leaf_heap(3, LeafIndex::new(4)), 12);
/// # }
/// ```
#[must_use]
pub const fn leaf_heap(depth: u8, index: LeafIndex) -> u64 {
    (1_u64 << depth) + index.get()
}

/// Decodes a 1-based heap index into `(level, position)`: `level` counts
/// edges down from the root (root `0`, the leaf row `depth`), computed as
/// `63 − leading_zeros(idx)`, and `position` is the index within that
/// level, `idx − 2^level`. The inverse of [`leaf_heap`] — for a leaf,
/// `heap_level_and_index(leaf_heap(depth, i)) == (depth, i)` — and the
/// decode behind the `TreeNode` subkey semantics documented in the store's
/// key spec, so the math is public wherever the key layout is.
///
/// # Panics
///
/// Panics for `0` — heap indexes are 1-based, so `0` names no node.
///
/// ```
/// # #[cfg(feature = "merkle_tree")]
/// # fn heap_decode_round_trips() {
/// use accumulators::merkle::math::{heap_level_and_index, leaf_heap};
/// use accumulators::primitives::LeafIndex;
///
/// // Heap node 12 is depth-3 tree leaf 4.
/// assert_eq!(heap_level_and_index(12), (3, 4));
/// assert_eq!(heap_level_and_index(1), (0, 0), "the root is level 0");
/// assert_eq!(
///     heap_level_and_index(leaf_heap(8, LeafIndex::new(200))),
///     (8, 200),
/// );
/// # }
/// ```
#[must_use]
pub const fn heap_level_and_index(heap_index: u64) -> (u8, u64) {
    assert!(heap_index != 0, "heap indexes are 1-based: 0 names no node");
    #[expect(
        clippy::cast_possible_truncation,
        reason = "ilog2() ≤ 63 for any nonzero u64, which fits in u8"
    )]
    let level = heap_index.ilog2() as u8;
    (level, heap_index - (1_u64 << level))
}

/// Validates a caller-supplied tree depth (valid: 1..=63). The custom-shell
/// seam's gate — the same check
/// [`IncrementalMerkleTree::create`](crate::merkle::IncrementalMerkleTree::create) runs.
///
/// # Errors
///
/// [`TreeError::InvalidDepth`] for a depth outside 1..=63.
pub fn check_depth<S: Storage>(depth: u8) -> Result<(), TreeError<S>> {
    if depth == 0 || depth > 63 {
        return Err(TreeError::InvalidDepth { depth });
    }
    Ok(())
}

/// Rejects a leaf index at or beyond `capacity`. The custom-shell seam's
/// bounds check — the same one every shell method runs first.
///
/// # Errors
///
/// [`TreeError::IndexOutOfRange`] for an index at or beyond `capacity`.
pub fn check_index<S: Storage>(capacity: u64, index: LeafIndex) -> Result<(), TreeError<S>> {
    if index.get() >= capacity {
        return Err(TreeError::IndexOutOfRange { index, capacity });
    }
    Ok(())
}

/// Builds the genesis batch: hasher identity, depth/null-leaf metadata, and
/// the empty root (the ladder's top, persisted as heap node 1). Returns the
/// batch and the ladder it was built from. Pure — the shells only write it.
///
/// The persisted records it produces are the tree's on-disk format (see the
/// `store::keys` wire spec): the byte layout is a compatibility commitment,
/// and every shell — built-in or custom — must write exactly these records.
///
/// # Errors
///
/// [`TreeError::UnrepresentableHasher`] when the hasher's identity/config
/// cannot be represented in the persisted metadata.
pub fn create_batch<S: Storage, H: crate::hashers::Hasher, Id: TreeId>(
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
/// The custom-shell read list — load these, then run
/// [`validate_metadata`].
pub fn metadata_keys<Id: TreeId>(id: &Id) -> Vec<Vec<u8>> {
    vec![
        keys::encode(id, Table::HasherInfo, 0),
        keys::encode(id, Table::TreeMeta, 0),
        keys::encode(id, Table::TreeNode, 1),
    ]
}

/// Validates the persisted metadata triple against the supplied hasher:
/// hasher identity/config byte-for-byte, depth in 1..=63, null leaf and
/// root parsing as hash values. Returns the tree's shape and cached root.
/// The shared decoder of the tree's on-disk metadata (see the `store::keys`
/// wire spec) — custom shells open through it.
///
/// # Errors
///
/// [`TreeCorrupted::HasherMismatch`] or [`TreeCorrupted::MalformedMetadata`].
pub fn validate_metadata<H: crate::hashers::Hasher>(
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
/// a corrupted root on the next write). The custom-shell node decoder over
/// the `TreeNode` wire format.
///
/// # Errors
///
/// [`TreeCorrupted::MalformedNode`] for a present-but-unparsable record.
pub fn parse_node_value<O: HashValue>(value: Option<Vec<u8>>) -> Result<Option<O>, TreeCorrupted> {
    match value {
        None => Ok(None),
        Some(bytes) => O::from_bytes(&bytes)
            .map(Some)
            .ok_or(TreeCorrupted::MalformedNode),
    }
}

/// The pure result of planning a leaf write from the loaded nodes:
/// everything the one batch write commits, plus the gate's `previous` value.
#[derive(Debug)]
pub struct SetPlan<O: HashValue> {
    /// Previous hash at the leaf: the leaf's stored value, or the ladder's
    /// null leaf when the leaf was unoccupied.
    pub previous: O,
    /// Every changed `(heap index, value)` pair, leaf → root.
    pub changed: Vec<(u64, O)>,
    /// The new root (heap node 1).
    pub root: O,
}

/// The heap indexes a `set_leaf` must read: the leaf plus every sibling on
/// its path to the root. The custom-shell read list for a write — load
/// these, then plan through [`plan_set`].
#[must_use]
pub fn set_read_heaps(depth: u8, index: LeafIndex) -> Vec<u64> {
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
/// then commit [`SetPlan::changed`] as one atomic batch. The custom-shell
/// write planner: same gate, same atomic-batch contract as the built-in
/// shells.
///
/// # Errors
///
/// [`TreeError::UpdateMismatch`] when the gate rejects.
pub fn plan_set<S: Storage, H: crate::hashers::Hasher>(
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

/// The sibling heap indexes of a leaf's proof path, bottom-up. The
/// custom-shell read list for a single proof — load these, then materialize
/// through [`build_proof`].
#[must_use]
pub fn proof_read_heaps(depth: u8, index: LeafIndex) -> Vec<u64> {
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
/// the ladder. Pure — the custom-shell proof builder.
pub fn build_proof<O: HashValue>(
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
/// them. Pure; the shells load exactly these nodes. The custom-shell
/// multiproof planner: normalize, load, then materialize through
/// [`build_multiproof`].
///
/// # Errors
///
/// [`TreeError::EmptyProof`] for an empty index set,
/// [`TreeError::IndexOutOfRange`] for any index at or beyond `capacity`.
pub fn plan_multiproof<S: Storage>(
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
/// to check the proof's sibling budget (see
/// [`verify_multi_proof`](crate::merkle::verify_multi_proof), which
/// consumes exactly this plan).
///
/// `indexes` must be ascending and unique — the canonical
/// [`TreeMultiProof`] order ([`plan_multiproof`] normalizes before calling;
/// the verifier trusts [`TreeMultiProof::indexes`]' documented contract).
///
/// ```
/// # #[cfg(feature = "merkle_tree")]
/// # fn walk_plan() {
/// use accumulators::merkle::math::multiproof_walk;
/// use accumulators::primitives::LeafIndex;
///
/// // Leaves {0, 1} of a depth-3 tree merge into one subtree: only the
/// // siblings above it are needed, bottom-up (heap 5 at level 1, heap 3
/// // at level 2).
/// let plan = multiproof_walk(3, &[LeafIndex::new(0), LeafIndex::new(1)]);
/// assert_eq!(plan, vec![5, 3]);
/// # }
/// ```
#[must_use]
pub fn multiproof_walk(depth: u8, indexes: &[LeafIndex]) -> Vec<u64> {
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
/// `depth − ilog2(heap)` (the [`heap_level_and_index`] decode). Pure — the
/// custom-shell multiproof builder.
pub fn build_multiproof<O: HashValue>(
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
            // The ladder is indexed from the leaves: a node at heap index
            // `heap` sits `level` edges below the root and covers a subtree
            // of height `depth − level`, so its unoccupied hash is
            // `ladder[depth − level]`.
            let (level, _) = heap_level_and_index(heap);
            value.unwrap_or_else(|| ladder.at(depth - level))
        })
        .collect();

    TreeMultiProof {
        indexes,
        siblings,
        depth,
        root,
    }
}
