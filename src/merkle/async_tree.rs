//! The async shell over the same pure core as
//! [`IncrementalMerkleTree`](super::IncrementalMerkleTree).
//!
//! Mirrors the sync tree method-for-method, generic over
//! [`AsyncStore`] instead of
//! [`Store`](crate::store::Store). All state math lives in the pure core in
//! [`super`](super) (metadata validation, the set/proof walks), so each
//! method is "fetch → pure transform → one atomic batch write"; the
//! residual duplication is the fetch/commit plumbing itself (the metadata
//! load/validate sequence), kept parallel to the sync loader because the
//! store contracts differ.
//!
//! Errors are unified with the sync shell: [`TreeError`] is generic over
//! [`Storage`](crate::store::Storage), which both
//! [`Store`](crate::store::Store) and [`AsyncStore`] require as a
//! supertrait. No wrapper types, no duplicated error enums, and a backend
//! implementing both contracts reports the same error type through either.
//!
//! Send-bounds: the shell's futures are `Send` when the type parameters and
//! their auto traits propagate into them. For the `&self` methods (proofs,
//! leaf reads) the future borrows `self`, which requires `S: Sync` and
//! `Id: Sync` on top of each parameter's `Send`; the `&mut self` methods
//! (`set_leaf`) additionally require the values they move — `H::Output` —
//! to be `Send`/`Sync` (the [`HashValue`](crate::primitives::HashValue)
//! trait carries no Send/Sync supertraits, so they must be required
//! explicitly). The full per-method set — `S: AsyncStore + Send + Sync +
//! 'static`, `H: Hasher + Send + Sync` with `H::Output: Send + Sync`,
//! `Id: TreeId + Send + Sync` — is asserted by a compile-time test
//! (`tests/async_merkle.rs`); construct the handle with those bounds to
//! spawn its methods on a multi-thread runtime.
//!
//! Note on runtimes: the trait uses native async-fn-in-trait; no
//! `async-trait` boxing anywhere. `no_std` targets use the sync
//! [`IncrementalMerkleTree`](super::IncrementalMerkleTree) with a sync store
//! instead.

use super::{
    SetOutcome, TreeCorrupted, TreeError, TreeMultiProof, TreeProof, ZeroLadder, build_multiproof,
    build_proof, check_depth, check_index, create_batch, leaf_heap, metadata_keys,
    parse_node_value, plan_multiproof, plan_set, proof_read_heaps, set_read_heaps,
    validate_metadata, verify_multi_proof, verify_proof,
};
use crate::hashers::Hasher;
use crate::ids::{AccumulatorId, TreeId};
use crate::primitives::LeafIndex;
use crate::store::{AsyncStore, Batch, keys, keys::Table, record};
use alloc::vec::Vec;

/// An async incremental Merkle tree of fixed capacity `2^depth`. Semantics
/// identical to [`IncrementalMerkleTree`](super::IncrementalMerkleTree) —
/// see that type for the full method contract, including the
/// `set_leaf` gate's single-writer assumption.
#[expect(
    missing_debug_implementations,
    reason = "generic over non-Debug store types"
)]
pub struct AsyncIncrementalMerkleTree<H: Hasher, S, Id = AccumulatorId> {
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

impl<H: Hasher, S: AsyncStore, Id: TreeId> AsyncIncrementalMerkleTree<H, S, Id> {
    /// Creates a new tree and persists its metadata (a constant number of
    /// writes; the empty tree stores nothing beyond the null root). See
    /// [`IncrementalMerkleTree::create`](super::IncrementalMerkleTree::create).
    ///
    /// # Errors
    ///
    /// As the sync [`create`](super::IncrementalMerkleTree::create).
    pub async fn create(
        hasher: H,
        store: S,
        id: Id,
        depth: u8,
        null_leaf: H::Output,
    ) -> Result<Self, TreeError<S>> {
        check_depth::<S>(depth)?;
        let (batch, ladder) = create_batch::<S, H, Id>(&hasher, &id, depth, null_leaf)?;
        store.write(batch).await.map_err(TreeError::Store)?;

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
    /// metadata against the supplied hasher. See
    /// [`IncrementalMerkleTree::open`](super::IncrementalMerkleTree::open).
    ///
    /// # Errors
    ///
    /// As the sync [`open`](super::IncrementalMerkleTree::open).
    pub async fn open(hasher: H, store: S, id: Id) -> Result<Self, TreeError<S>> {
        let encoded = metadata_keys(&id);
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        let values = store.read(&refs).await.map_err(TreeError::Store)?;

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

    /// The stored hash of a leaf, or `None` when the leaf is unoccupied. See
    /// [`IncrementalMerkleTree::leaf_hash`](super::IncrementalMerkleTree::leaf_hash).
    ///
    /// # Errors
    ///
    /// As the sync [`leaf_hash`](super::IncrementalMerkleTree::leaf_hash).
    pub async fn leaf_hash(&self, index: LeafIndex) -> Result<Option<H::Output>, TreeError<S>> {
        check_index::<S>(self.capacity(), index)?;
        let mut loaded = self.load_nodes(&[leaf_heap(self.depth, index)]).await?;
        Ok(loaded.pop().flatten())
    }

    /// Sets a leaf in place. Writing over an occupied leaf requires the
    /// current value. See
    /// [`IncrementalMerkleTree::set_leaf`](super::IncrementalMerkleTree::set_leaf)
    /// for the gate semantics.
    ///
    /// # Errors
    ///
    /// As the sync [`set_leaf`](super::IncrementalMerkleTree::set_leaf).
    pub async fn set_leaf(
        &mut self,
        index: LeafIndex,
        element: &[u8],
        expected_current: Option<H::Output>,
    ) -> Result<SetOutcome<H::Output>, TreeError<S>> {
        check_index::<S>(self.capacity(), index)?;
        let new_hash = self.hasher.hash_leaf(element)?;

        // One batched read for the leaf and all its siblings; unoccupied
        // nodes fall back to the zero ladder.
        let loaded = self.load_nodes(&set_read_heaps(self.depth, index)).await?;
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
        self.store.write(batch).await.map_err(TreeError::Store)?;
        self.root = plan.root;

        Ok(SetOutcome {
            index,
            previous: plan.previous,
            root: plan.root,
        })
    }

    /// Inclusion proof for a leaf; self-contained like the sync tree's — it
    /// carries the root it commits to (see [`TreeProof`]). See
    /// [`IncrementalMerkleTree::proof`](super::IncrementalMerkleTree::proof).
    ///
    /// # Errors
    ///
    /// As the sync [`proof`](super::IncrementalMerkleTree::proof).
    pub async fn proof(&self, index: LeafIndex) -> Result<TreeProof<H::Output>, TreeError<S>> {
        check_index::<S>(self.capacity(), index)?;
        let loaded = self
            .load_nodes(&proof_read_heaps(self.depth, index))
            .await?;
        Ok(build_proof(
            self.depth,
            index,
            loaded,
            &self.ladder,
            self.root,
        ))
    }

    /// Verifies a proof against this tree's *current* root. Synchronous:
    /// the check is pure over the proof — no store, no await. See
    /// [`IncrementalMerkleTree::verify`](super::IncrementalMerkleTree::verify).
    ///
    /// # Errors
    ///
    /// [`TreeError::Proof`] when the proof is structurally inconsistent;
    /// hasher failures.
    #[must_use = "a verification result is only meaningful when checked"]
    pub fn verify(
        &self,
        proof: &TreeProof<H::Output>,
        element: &[u8],
    ) -> Result<bool, TreeError<S>> {
        let valid = verify_proof(&self.hasher, proof, element)?;
        Ok(valid && proof.root == self.root)
    }

    /// Multi-leaf proof: minimal sibling set covering all requested leaves.
    /// See
    /// [`IncrementalMerkleTree::multiproof`](super::IncrementalMerkleTree::multiproof).
    ///
    /// # Errors
    ///
    /// As the sync
    /// [`multiproof`](super::IncrementalMerkleTree::multiproof).
    pub async fn multiproof<I>(&self, indexes: I) -> Result<TreeMultiProof<H::Output>, TreeError<S>>
    where
        I: IntoIterator<Item = LeafIndex>,
    {
        let (indexes, needed) = plan_multiproof::<S>(self.depth, self.capacity(), indexes)?;
        let loaded = self.load_nodes(&needed).await?;
        Ok(build_multiproof(
            self.depth,
            indexes,
            needed,
            loaded,
            &self.ladder,
            self.root,
        ))
    }

    /// Verifies a multi-leaf proof against this tree's *current* root.
    /// Synchronous; see
    /// [`IncrementalMerkleTree::verify_multi`](super::IncrementalMerkleTree::verify_multi).
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

    /// Batched heap-node read from the store. A present-but-unparsable
    /// value is [`TreeCorrupted::MalformedNode`] — it must never read as an
    /// unoccupied node (see the sync shell's loader).
    async fn load_nodes(&self, heaps: &[u64]) -> Result<Vec<Option<H::Output>>, TreeError<S>> {
        let encoded: Vec<Vec<u8>> = heaps
            .iter()
            .map(|heap| keys::encode(&self.id, Table::TreeNode, *heap))
            .collect();
        let refs: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
        self.store
            .read(&refs)
            .await
            .map_err(TreeError::Store)?
            .into_iter()
            .map(parse_node_value)
            .collect::<Result<_, _>>()
            .map_err(TreeError::Corrupted)
    }
}
