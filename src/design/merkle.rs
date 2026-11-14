//! Incremental Merkle tree redesign: sparse storage, zero-hash ladder, fixed
//! proofs.
//!
//! v0.5 defects this design fixes:
//! - **init was `O(size)`**: `initialize` materialized every leaf and every
//!   internal node into the store. Here only occupied leaves and their
//!   ancestors are stored — init writes `O(depth)` nodes and an empty tree
//!   stores nothing.
//! - **the non-power-of-2 proof bug**: null-padded parents were folded into
//!   parent hashes but never stored, so `get_inclusion_proof` hit missing
//!   keys with `NotFound` (~18% of leaves in a 10k tree). The zero-hash
//!   ladder makes virtual (unoccupied) siblings *computable*, not stored:
//!   proofs for any index within capacity always succeed.
//! - **metadata not persisted**: size/depth/null value lived only in the
//!   struct. Here depth, null hash and hasher identity are persisted at
//!   creation and validated on re-open (same mechanism as the MMR).
//! - **mutating out-params** in `verify_multi_proof` (`&mut Vec<...>` × 3) —
//!   the redesign returns structured results.
//!
//! The tree is a *sparse* incremental tree of fixed capacity `2^depth`:
//! leaves are set in place (like the owner's usage in proving systems), the
//! root updates incrementally, and unoccupied leaves hash to the null leaf.
//!
//! Note (intentional asymmetry with the MMR): single-leaf `proof` returns the
//! bare sibling list — the tree has one fixed root and the caller already
//! holds it (see [`IncrementalMerkleTree::root`]); the proof's commitment is
//! the root passed to [`IncrementalMerkleTree::verify`]. The MMR's proofs are
//! self-contained because an MMR's root moves with every append.

use crate::design::hashers::{Hasher, HasherError};
use crate::design::ids::{MmrId, TreeId};
use crate::design::primitives::{HashValue, LeafIndex};
use crate::design::store::{Storage, Store};
use alloc::vec::Vec;

/// An incremental Merkle tree of fixed capacity `2^depth`.
///
/// Generic over the id type like [`Mmr`](crate::design::mmr::Mmr) — the
/// default [`MmrId`] covers the common case.
pub struct IncrementalMerkleTree<H: Hasher, S, Id = MmrId> {
    pub(crate) hasher: H,
    pub(crate) store: S,
    pub(crate) id: Id,
    pub(crate) depth: u8,
    pub(crate) null_leaf: H::Output,
    pub(crate) ladder: ZeroLadder<H::Output>,
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
    /// Infallible: the ladder folds [`Hasher::hash_pair`] calls, which are
    /// infallible by contract.
    #[must_use]
    pub fn new<H: Hasher<Output = O>>(hasher: &H, depth: u8, null_leaf: O) -> Self {
        let _ = (hasher, depth, null_leaf);
        todo!()
    }

    /// Hash of an unoccupied subtree at the given level.
    #[must_use]
    pub fn at(&self, level: u8) -> O {
        let _ = level;
        todo!()
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
/// error-unification model of [`MmrError`](crate::design::mmr::MmrError).
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

    /// Persisted metadata is missing or inconsistent.
    #[error("tree metadata is missing or inconsistent: {0}")]
    Corrupted(#[source] TreeCorrupted),
}

/// Specific corruption findings when re-opening a tree — the granular
/// counterpart of the MMR's [`Corrupted`](crate::design::mmr::Corrupted).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TreeCorrupted {
    /// Required metadata records are absent.
    #[error("metadata records missing")]
    MissingMetadata,
    /// Persisted hasher id/config differs from the hasher in use.
    #[error("hasher mismatch: store has {stored}, caller supplied {supplied}")]
    HasherMismatch {
        /// Hasher identity/config recorded at creation (read from the store).
        stored: alloc::string::String,
        /// Hasher passed to the constructor.
        supplied: &'static str,
    },
    /// Persisted depth differs from the caller's declared depth.
    #[error("depth mismatch: store has {stored}, caller declared {declared}")]
    DepthMismatch {
        /// Depth recorded at creation.
        stored: u8,
        /// Depth the caller declared.
        declared: u8,
    },
    /// Persisted null leaf differs from the one the hasher produces.
    #[error("null leaf mismatch: persisted null leaf differs from the hasher's")]
    NullMismatch,
}

impl<H: Hasher, S: Store, Id: TreeId> IncrementalMerkleTree<H, S, Id> {
    /// Creates a new tree and persists its metadata (`O(depth)` writes).
    ///
    /// # Errors
    ///
    /// Store failures or hasher failures.
    pub fn create(
        hasher: H,
        store: S,
        id: Id,
        depth: u8,
        null_leaf: H::Output,
    ) -> Result<Self, TreeError<S>> {
        let _ = (&hasher, &store, id, depth, null_leaf);
        todo!()
    }

    /// Re-opens an existing tree, validating persisted depth/null/hasher
    /// metadata against the supplied hasher.
    ///
    /// # Errors
    ///
    /// [`TreeError::Corrupted`] or store failures.
    pub fn open(hasher: H, store: S, id: Id) -> Result<Self, TreeError<S>> {
        let _ = (&hasher, &store, id);
        todo!()
    }

    /// Current root (incremental — recomputed on writes, read from cache).
    #[must_use]
    pub const fn root(&self) -> H::Output {
        todo!()
    }

    /// The tree's capacity: `2^depth`.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        todo!()
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
        let _ = (index, element, expected_current);
        todo!()
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
        let _ = index;
        todo!()
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
        let _ = (index, element, proof, root);
        todo!()
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
        let _ = indexes;
        todo!()
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
    pub fn verify_multiproof<I>(
        &self,
        proof: &TreeMultiProof<H::Output>,
        elements: I,
    ) -> Result<bool, TreeError<S>>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let _ = (proof, elements);
        todo!()
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
