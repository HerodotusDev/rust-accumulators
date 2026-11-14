//! The pure, sync, `no_std` core of the MMR.
//!
//! [`MmrState`] is the complete logical state of an MMR: counts, cached peaks,
//! and provenance. All algorithms (append, proofs, bagging, root) are pure
//! functions over this state plus the hasher — no store access, no async.
//!
//! Both [`super::Mmr`] (sync) and [`super::AsyncMmr`] are thin shells: they
//! load [`MmrState`] from the store at open, apply the pure transforms here,
//! and commit the resulting deltas as a single batch write.

use crate::design::hashers::Hasher;
use crate::design::primitives::{LeafCount, LeafIndex, MmrSize, NodeIndex};
use alloc::vec::Vec;

/// Provenance of an MMR: full history, or created from peaks at a pinned size.
///
/// A peaks-only MMR has the same root as the full MMR it was seeded from, but
/// leaves below [`Provenance::first_provable_leaf`] have no sibling data and
/// cannot be proven.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Provenance {
    /// Every leaf since genesis is provable.
    Full,
    /// Created from peaks; only leaves from `first_provable_leaf` up are
    /// provable. Stores the node count at creation.
    FromPeaks {
        /// Node count at creation time.
        size_at_creation: MmrSize,
    },
}

impl Provenance {
    /// Lowest leaf index that can be proven, given this provenance.
    #[must_use]
    pub const fn first_provable_leaf(self) -> LeafIndex {
        match self {
            Self::Full => LeafIndex::FIRST,
            Self::FromPeaks {
                size_at_creation: _,
            } => todo!(),
        }
    }
}

/// The complete logical state of an MMR — the pure core both shells share.
///
/// Generic over the hasher so cached peaks use the hasher's own
/// [`Hasher::Output`] type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmrState<H: Hasher> {
    /// Number of appended elements.
    pub leaf_count: LeafCount,
    /// Total node count ("MMR size").
    pub node_count: MmrSize,
    /// Current peak hashes, left to right. Cache: appends and roots never
    /// round-trip the store for these.
    pub peaks: Vec<H::Output>,
    /// Whether history below the seed point is provable.
    pub provenance: Provenance,
}

impl<H: Hasher> MmrState<H> {
    /// State of an empty MMR with full history.
    #[must_use]
    pub fn empty() -> Self {
        todo!()
    }

    /// State of an MMR seeded from peaks (peaks-only provenance).
    #[must_use]
    pub fn from_peaks(size_at_creation: MmrSize, peaks: &[H::Output]) -> Self {
        let _ = (size_at_creation, peaks);
        todo!()
    }

    /// The cached root — re-derived from peaks, no store access.
    ///
    /// Infallible: bagging and root derivation fold [`Hasher::hash_pair`]
    /// calls, which are infallible by contract.
    #[must_use]
    pub fn root(&self, hasher: &H) -> H::Output {
        let _ = hasher;
        todo!()
    }

    /// Whether the given leaf is provable under this provenance.
    #[must_use]
    pub const fn is_provable(&self, leaf: LeafIndex) -> bool {
        let _ = leaf;
        todo!()
    }
}

/// Everything one append produces: the new state and the nodes to persist.
///
/// Shells translate `nodes` into batch puts — one store write per append,
/// independent of how many merges fire.
#[derive(Clone, Debug)]
pub struct AppendDelta<H: Hasher> {
    /// State after the append.
    pub state: MmrState<H>,
    /// New node hashes to persist, including the leaf itself.
    pub nodes: Vec<(NodeIndex, H::Output)>,
}

/// Computes the append of one element hash against a state.
///
/// Pure: takes the state, returns the next state plus the nodes to persist.
/// The element is *already* hashed (the shell calls [`Hasher::hash_leaf`],
/// the only fallible step). Merging itself is infallible — it folds
/// [`Hasher::hash_pair`] calls.
#[must_use]
pub fn apply_append<H: Hasher>(
    hasher: &H,
    state: &MmrState<H>,
    element_hash: H::Output,
) -> AppendDelta<H> {
    let _ = (hasher, state, element_hash);
    todo!()
}

/// Computes the appends of many element hashes in one pass.
///
/// The returned delta contains only the *final* nodes to persist —
/// intermediate states of earlier appends in the batch are folded through
/// memory, so a batch of N appends is exactly one store write.
#[must_use]
pub fn apply_append_batch<H: Hasher>(
    hasher: &H,
    state: &MmrState<H>,
    element_hashes: &[H::Output],
) -> AppendDelta<H> {
    let _ = (hasher, state, element_hashes);
    todo!()
}
