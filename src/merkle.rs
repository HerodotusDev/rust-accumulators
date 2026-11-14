//! Incremental Merkle tree redesign: sparse storage, zero-hash ladder, fixed
//! proofs.
//!
//! v0.5 defects this design fixes:
//! - **init was `O(size)`**: `initialize` materialized every leaf and every
//!   internal node into the store. Here only occupied leaves and their
//!   ancestors are stored — init writes a constant number of records and an
//!   empty tree stores nothing beyond metadata.
//! - **the non-power-of-2 proof bug**: null-padded parents were folded into
//!   parent hashes but never stored, so `get_inclusion_proof` hit missing
//!   keys with `NotFound` (~18% of leaves in a 10k tree). The zero-hash
//!   ladder makes virtual (unoccupied) siblings *computable*, not stored:
//!   proofs for any index within capacity always succeed.
//! - **metadata not persisted**: size/depth/null value lived only in the
//!   struct. Here depth, null leaf and hasher identity are persisted at
//!   creation and validated on re-open (same mechanism as the MMR).
//! - **mutating out-params** in `verify_multi_proof` (`&mut Vec<...>` × 3) —
//!   the redesign returns structured results.
//!
//! The tree is a *sparse* incremental tree of fixed capacity `2^depth`:
//! leaves are set in place (like the owner's usage in proving systems), the
//! root updates incrementally, and unoccupied leaves hash to the null leaf.
//!
//! Nodes live under the [`Table::TreeNode`](crate::store::keys::Table::TreeNode) table keyed by the **1-based
//! heap index** (root `1`, leaf `i` at `2^depth + i`); the root is heap node
//! `1`. Unoccupied nodes are never written — reads fall back to the
//! zero-hash ladder.
//!
//! Note (intentional asymmetry with the MMR): single-leaf `proof` returns the
//! bare sibling list — the tree has one fixed root and the caller already
//! holds it (see [`IncrementalMerkleTree::root`](crate::merkle::IncrementalMerkleTree::root)); the proof's commitment is
//! the root passed to [`IncrementalMerkleTree::verify`](crate::merkle::IncrementalMerkleTree::verify). The MMR's proofs are
//! self-contained because an MMR's root moves with every append.

use crate::hashers::HasherError;
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::{HashValue, LeafIndex};
use crate::store::{Storage, Store, keys, keys::Table, record};
use alloc::vec;
use alloc::vec::Vec;

/// An incremental Merkle tree of fixed capacity `2^depth`.
///
/// Generic over the id type like the MMR handle (`crate::mmr::Mmr`) — the
/// default [`AccumulatorId`] covers the common case.
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
/// This is what makes virtual siblings computable and fixes the
/// non-power-of-2 proof bug at its root.
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
    /// Previous hash at this leaf, if it was occupied.
    pub previous: Option<O>,
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

    /// Persisted metadata is missing or inconsistent.
    #[error("tree metadata is missing or inconsistent: {0}")]
    Corrupted(#[source] TreeCorrupted),
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
        /// Hasher passed to the constructor.
        supplied: &'static str,
    },
}

/// Heap index of leaf `i` in a tree of `depth` levels.
const fn leaf_heap(depth: u8, index: LeafIndex) -> u64 {
    (1_u64 << depth) + index.get()
}

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
        if depth == 0 || depth > 63 {
            return Err(TreeError::InvalidDepth { depth });
        }
        let ladder = ZeroLadder::new(&hasher, depth, null_leaf);

        let mut batch = crate::store::Batch::new();
        batch.put_owned(
            keys::encode(&id, Table::HasherInfo, 0),
            record::hasher_info(&hasher),
        );
        batch.put_owned(keys::encode(&id, Table::TreeMeta, 0), {
            let mut meta = Vec::with_capacity(1 + H::Output::LEN);
            meta.push(depth);
            meta.extend_from_slice(null_leaf.to_vec().as_slice());
            meta
        });
        // The empty root: heap node 1 = the top of the ladder.
        batch.put_owned(
            keys::encode(&id, Table::TreeNode, 1),
            record::hash_value(&ladder.at(depth)),
        );
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
        let metadata_keys: Vec<Vec<u8>> = vec![
            keys::encode(&id, Table::HasherInfo, 0),
            keys::encode(&id, Table::TreeMeta, 0),
            keys::encode(&id, Table::TreeNode, 1),
        ];
        let refs: Vec<&[u8]> = metadata_keys.iter().map(Vec::as_slice).collect();
        let values = store.read(&refs).map_err(TreeError::Store)?;

        let missing = || TreeError::Corrupted(TreeCorrupted::MissingMetadata);
        let malformed = || TreeError::Corrupted(TreeCorrupted::MalformedMetadata);
        let value = |index: usize| -> Result<&[u8], TreeError<S>> {
            values
                .get(index)
                .and_then(Option::as_deref)
                .ok_or_else(missing)
        };

        let (stored_id, stored_config) =
            record::parse_hasher_info(value(0)?).ok_or_else(malformed)?;
        if stored_id != hasher.id() || stored_config != hasher.config() {
            return Err(TreeError::Corrupted(TreeCorrupted::HasherMismatch {
                stored: alloc::format!("{stored_id} ({stored_config})"),
                supplied: "",
            }));
        }

        let meta = value(1)?;
        let depth = *meta.first().ok_or_else(malformed)?;
        if depth == 0 || depth > 63 {
            return Err(malformed());
        }
        let Some(null_bytes) = meta.get(1..) else {
            return Err(malformed());
        };
        let null_leaf = H::Output::from_bytes(null_bytes).ok_or_else(malformed)?;
        if null_bytes.len() != H::Output::LEN {
            return Err(malformed());
        }

        // The root is whatever the last write left; its shape is validated
        // by the HashValue parse.
        let root = H::Output::from_bytes(value(2)?).ok_or_else(malformed)?;

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

    /// Sets a leaf in place. Writing over an occupied leaf requires the
    /// current value — the update gate that v0.5's `update` provided via
    /// proof-verification, but without a store round trip to fetch the root.
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
        if index.get() >= self.capacity() {
            return Err(TreeError::IndexOutOfRange {
                index,
                capacity: self.capacity(),
            });
        }
        let new_hash = self.hasher.hash_leaf(element)?;

        // Current value at the leaf: store read, ladder for unoccupied.
        let leaf_heap_index = leaf_heap(self.depth, index);
        let mut loaded = self.load_nodes(&[leaf_heap_index])?;
        let previous = loaded.pop().flatten().or(Some(self.ladder.at(0)));
        if let Some(expected) = expected_current
            && previous != Some(expected)
        {
            return Err(TreeError::UpdateMismatch { index });
        }

        // Walk up: sibling from store or ladder; write every changed node.
        let mut hash = new_hash;
        let mut heap = leaf_heap_index;
        let mut changed = vec![(heap, hash)];
        for level in 0..self.depth {
            let sibling_heap = heap ^ 1;
            let mut sibling = self.load_nodes(&[sibling_heap])?;
            let sibling = sibling
                .pop()
                .flatten()
                .unwrap_or_else(|| self.ladder.at(level));
            hash = if heap & 1 == 1 {
                // Node is the right child: sibling sits on the left.
                self.hasher.hash_pair(sibling, hash)
            } else {
                self.hasher.hash_pair(hash, sibling)
            };
            heap >>= 1;
            changed.push((heap, hash));
        }

        let mut batch = crate::store::Batch::new();
        for (node, value) in &changed {
            batch.put_owned(
                keys::encode(&self.id, Table::TreeNode, *node),
                record::hash_value(value),
            );
        }
        self.store.write(batch).map_err(TreeError::Store)?;
        self.root = hash;

        Ok(SetOutcome {
            index,
            previous,
            root: hash,
        })
    }

    /// Inclusion proof for a leaf: sibling hashes leaf→root, virtual
    /// siblings materialized from the ladder. Always succeeds within
    /// capacity — the non-power-of-2 bug is structurally gone. The proof
    /// commits against [`Self::root`] (see the module note on why this is
    /// not self-contained like MMR proofs).
    ///
    /// # Errors
    ///
    /// [`TreeError::IndexOutOfRange`] or store failures.
    pub fn proof(&self, index: LeafIndex) -> Result<Vec<H::Output>, TreeError<S>> {
        if index.get() >= self.capacity() {
            return Err(TreeError::IndexOutOfRange {
                index,
                capacity: self.capacity(),
            });
        }

        let mut heap = leaf_heap(self.depth, index);
        let siblings: Vec<u64> = (0..self.depth)
            .map(|_| {
                let sibling = heap ^ 1;
                heap >>= 1;
                sibling
            })
            .collect();
        let loaded = self.load_nodes(&siblings)?;

        Ok(loaded
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
                value.unwrap_or_else(|| self.ladder.at(level))
            })
            .collect())
    }

    /// Verifies a leaf against an expected root. No store access.
    ///
    /// # Errors
    ///
    /// Hasher failures.
    pub fn verify(
        &self,
        index: LeafIndex,
        element: &[u8],
        proof: &[H::Output],
        root: H::Output,
    ) -> Result<bool, TreeError<S>> {
        if index.get() >= self.capacity() {
            return Err(TreeError::IndexOutOfRange {
                index,
                capacity: self.capacity(),
            });
        }
        if proof.len() != self.depth as usize {
            return Ok(false);
        }

        let mut hash = self.hasher.hash_leaf(element)?;
        let mut heap = leaf_heap(self.depth, index);
        for sibling in proof {
            hash = if heap & 1 == 1 {
                self.hasher.hash_pair(*sibling, hash)
            } else {
                self.hasher.hash_pair(hash, *sibling)
            };
            heap >>= 1;
        }
        Ok(hash == root)
    }

    /// Multi-leaf proof: minimal sibling set covering all requested leaves,
    /// returned as an explicit structure (not mutating out-params).
    ///
    /// # Errors
    ///
    /// [`TreeError::IndexOutOfRange`] or store failures.
    pub fn multiproof<I>(&self, indexes: I) -> Result<TreeMultiProof<H::Output>, TreeError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let mut indexes: Vec<LeafIndex> = indexes.into_iter().collect();
        indexes.sort_unstable();
        indexes.dedup();
        for &index in &indexes {
            if index.get() >= self.capacity() {
                return Err(TreeError::IndexOutOfRange {
                    index,
                    capacity: self.capacity(),
                });
            }
        }

        // Level walk: the set of needed nodes, bottom-up. Siblings already
        // in the set are merged, not proven.
        let mut current: Vec<u64> = indexes.iter().map(|i| leaf_heap(self.depth, *i)).collect();
        let mut needed: Vec<u64> = Vec::new();
        for _ in 0..self.depth {
            let mut next = Vec::with_capacity(current.len());
            let mut level_needed: Vec<u64> = Vec::new();
            for &node in &current {
                let sibling = node ^ 1;
                if current.binary_search(&sibling).is_err() {
                    level_needed.push(sibling);
                }
                let parent = node >> 1;
                if next.last() != Some(&parent) {
                    next.push(parent);
                }
            }
            needed.extend(level_needed);
            current = next;
        }

        let loaded = self.load_nodes(&needed)?;
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
                let level = self.depth - heap.ilog2() as u8;
                value.unwrap_or_else(|| self.ladder.at(level))
            })
            .collect();

        Ok(TreeMultiProof {
            indexes,
            siblings,
            depth: self.depth,
        })
    }

    /// Verifies a multi-leaf proof against the current root — consuming the
    /// proof's structural contract (see [`TreeMultiProof`]'s ordering
    /// documentation). No store access.
    ///
    /// `elements` must align positionally with the proof's indexes.
    ///
    /// # Errors
    ///
    /// Structural inconsistency, hasher failures, or an element count not
    /// matching the proof.
    pub fn verify_multi<I>(
        &self,
        proof: &TreeMultiProof<H::Output>,
        elements: I,
    ) -> Result<bool, TreeError<S>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let elements: Vec<H::Output> = elements
            .into_iter()
            .map(|element| self.hasher.hash_leaf(element.as_ref()))
            .collect::<Result<_, _>>()?;
        if elements.len() != proof.indexes.len() || proof.depth != self.depth {
            return Ok(false);
        }
        for &index in &proof.indexes {
            if index.get() >= self.capacity() {
                return Ok(false);
            }
        }
        for pair in proof.indexes.windows(2) {
            if pair[0] >= pair[1] {
                return Ok(false);
            }
        }

        // Replay the level walk: values per level for the needed nodes.
        let mut values: Vec<(u64, H::Output)> = proof
            .indexes
            .iter()
            .zip(elements)
            .map(|(index, hash)| (leaf_heap(self.depth, *index), hash))
            .collect();
        let mut siblings = proof.siblings.iter().copied();

        for _ in 0..self.depth {
            let mut next: Vec<(u64, H::Output)> = Vec::with_capacity(values.len());
            let mut index_into_values = 0;
            while index_into_values < values.len() {
                let (node, hash) = values[index_into_values];
                let sibling = node ^ 1;
                // The set is sorted; a merge partner sits next to it.
                if index_into_values + 1 < values.len()
                    && values[index_into_values + 1].0 == sibling
                {
                    let (sibling_node, sibling_hash) = values[index_into_values + 1];
                    let parent = node >> 1;
                    let parent_hash = if node & 1 == 1 {
                        self.hasher.hash_pair(sibling_hash, hash)
                    } else {
                        self.hasher.hash_pair(hash, sibling_hash)
                    };
                    next.push((parent, parent_hash));
                    index_into_values += 2;
                    let _ = sibling_node;
                    continue;
                }
                // Needs a proof sibling: they appear left-to-right within the
                // level, matching this walk's order.
                let Some(proof_sibling) = siblings.next() else {
                    return Ok(false);
                };
                let parent_hash = if node & 1 == 1 {
                    self.hasher.hash_pair(proof_sibling, hash)
                } else {
                    self.hasher.hash_pair(hash, proof_sibling)
                };
                next.push((node >> 1, parent_hash));
                index_into_values += 1;
            }
            values = next;
        }

        // Every proof sibling must be consumed, and the final single value
        // (heap node 1) is the root.
        if siblings.next().is_some() {
            return Ok(false);
        }
        Ok(values.len() == 1 && values[0].1 == self.root())
    }

    /// Batched heap-node read from the store.
    fn load_nodes(&self, heaps: &[u64]) -> Result<Vec<Option<H::Output>>, TreeError<S>> {
        let encoded: Vec<Vec<u8>> = heaps
            .iter()
            .map(|heap| keys::encode(&self.id, Table::TreeNode, *heap))
            .collect();
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        Ok(self
            .store
            .read(&refs)
            .map_err(TreeError::Store)?
            .into_iter()
            .map(|value| value.and_then(|bytes| H::Output::from_bytes(&bytes)))
            .collect())
    }
}

/// Multi-leaf proof with explicit structure (v0.5's `verify_multi_proof`
/// took three `&mut Vec` out-params; this returns data instead).
///
/// # Ordering (the v0.5 `IndexMap` contract, preserved by construction)
///
/// v0.5 used an `IndexMap` so the sibling list came out in bottom-up,
/// level-by-level discovery order — the order its verifier consumed via
/// `proof.remove(0)`. Here the same order is produced directly by the
/// level walk over structured (depth, index) keys — no ordered hash map
/// needed — and is part of this type's contract:
///
/// - `indexes` ascending, `values` (from the verified elements) positionally
///   paired with them,
/// - `siblings` emitted bottom-up, level by level, left to right within a
///   level; the verifier walks levels front-to-back, pairing each merge with
///   the next sibling it needs from the front of the list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeMultiProof<O: HashValue> {
    /// Proven leaf indexes, ascending.
    pub indexes: Vec<LeafIndex>,
    /// The minimal sibling hash set — bottom-up, level by level, left to
    /// right within a level (see the ordering contract above).
    pub siblings: Vec<O>,
    /// Tree depth the proof was built at.
    pub depth: u8,
}
