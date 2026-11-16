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
//! pure functions of the [`math`](crate::merkle::math) submodule;
//! [`AsyncIncrementalMerkleTree`](crate::merkle::AsyncIncrementalMerkleTree)
//! is the same tree over an [`AsyncStore`](crate::store::AsyncStore),
//! differing only in fetch/commit plumbing — one batched read and one
//! atomic batch write per operation, exactly like the sync shell.

mod async_tree;

pub use async_tree::AsyncIncrementalMerkleTree;

/// The pure math: heap-index algebra, metadata codecs, write/proof
/// planners. Canonical home of the tree's custom-shell seam; the toolbox
/// ([`crate::utils::merkle`]) re-exports it.
pub mod math;

use crate::hashers::HasherError;
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::{HashValue, LeafIndex};
use crate::store::{Batch, Storage, Store, keys, keys::Table, record};
use alloc::vec::Vec;

use math::{
    build_multiproof, build_proof, check_depth, check_index, create_batch, leaf_heap,
    metadata_keys, multiproof_walk, parse_node_value, plan_multiproof, plan_set, proof_read_heaps,
    set_read_heaps, validate_metadata,
};

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

    /// The tree's depth — the persisted shape parameter; capacity is
    /// `2^depth`.
    #[must_use]
    pub const fn depth(&self) -> u8 {
        self.depth
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
