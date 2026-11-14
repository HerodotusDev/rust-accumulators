//! The pure, sync, `no_std` core of the MMR.
//!
//! [`MmrState`] is the complete logical state of an MMR: counts, cached peaks,
//! and provenance. All algorithms (append, proofs, bagging, root) are pure
//! functions over this state plus the hasher — no store access, no async.
//!
//! Both [`super::Mmr`] (sync) and [`super::AsyncMmr`] are thin shells: they
//! load [`MmrState`] from the store at open, apply the pure transforms here,
//! and commit the resulting deltas as a single batch write.

use super::layout::{LeafCount, MmrSize, NodeIndex, bag_peaks, merges_on_append, root_from};
use crate::hashers::Hasher;
use crate::primitives::LeafIndex;
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
    /// Lowest leaf index that can be proven, given this provenance: the first
    /// leaf appended *on top of* the seed peaks.
    #[must_use]
    pub const fn first_provable_leaf(self) -> LeafIndex {
        match self {
            Self::Full => LeafIndex::FIRST,
            Self::FromPeaks { size_at_creation } => match size_at_creation.leaf_count() {
                Some(count) => count.next_leaf(),
                None => LeafIndex::FIRST,
            },
        }
    }
}

/// The complete logical state of an MMR — the pure core both shells share.
///
/// Generic over the hasher so cached peaks use the hasher's own
/// [`Hasher::Output`] type. Fields are crate-private: the counts, peaks, and
/// provenance are invariants maintained by the shells, exposed for reading
/// through accessors — external code cannot forge a divergent state.
#[derive(Debug, PartialEq, Eq)]
pub struct MmrState<H: Hasher> {
    /// Number of appended elements.
    pub(crate) leaf_count: LeafCount,
    /// Total node count ("MMR size").
    pub(crate) node_count: MmrSize,
    /// Current peak hashes, left to right. Cache: appends and roots never
    /// round-trip the store for these.
    pub(crate) peaks: Vec<H::Output>,
    /// Whether history below the seed point is provable.
    pub(crate) provenance: Provenance,
}

impl<H: Hasher> Clone for MmrState<H> {
    fn clone(&self) -> Self {
        Self {
            leaf_count: self.leaf_count,
            node_count: self.node_count,
            // Hash outputs are `Copy` — no `H: Clone` needed.
            peaks: Vec::clone(&self.peaks),
            provenance: self.provenance,
        }
    }
}

impl<H: Hasher> MmrState<H> {
    /// State of an empty MMR with full history.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            leaf_count: LeafCount::ZERO,
            node_count: MmrSize::ZERO,
            peaks: Vec::new(),
            provenance: Provenance::Full,
        }
    }

    /// State of an MMR seeded from peaks (peaks-only provenance).
    ///
    /// The caller guarantees the peaks match `size_at_creation` — a valid MMR
    /// size and exactly [`LeafCount::get`]'s trailing `popcount(leaf_count)`
    /// peaks for it. The shells validate this before calling (rejecting with
    /// [`MmrError::InvalidPeaks`](super::MmrError::InvalidPeaks)); the debug
    /// assertion catches misuse in tests.
    #[must_use]
    pub fn from_peaks(size_at_creation: MmrSize, peaks: &[H::Output]) -> Self {
        debug_assert_eq!(
            peaks.len(),
            size_at_creation
                .leaf_count()
                .map_or(0, |c| c.get().count_ones() as usize),
            "peak count must match the leaf count's popcount"
        );
        Self {
            leaf_count: size_at_creation.leaf_count().unwrap_or(LeafCount::ZERO),
            node_count: size_at_creation,
            peaks: Vec::from(peaks),
            provenance: Provenance::FromPeaks { size_at_creation },
        }
    }

    /// The cached root — re-derived from peaks, no store access.
    ///
    /// Infallible: bagging and root derivation fold [`Hasher::hash_pair`]
    /// calls, which are infallible by contract.
    #[must_use]
    pub fn root(&self, hasher: &H) -> H::Output {
        root_from(hasher, bag_peaks(hasher, &self.peaks), self.node_count)
    }

    /// Whether the given leaf is provable under this provenance.
    #[must_use]
    pub const fn is_provable(&self, leaf: LeafIndex) -> bool {
        match self.provenance {
            Provenance::Full => true,
            Provenance::FromPeaks { size_at_creation } => match size_at_creation.leaf_count() {
                Some(count) => leaf.get() >= count.get(),
                None => true,
            },
        }
    }

    /// The number of appended elements.
    #[must_use]
    pub const fn leaf_count(&self) -> LeafCount {
        self.leaf_count
    }

    /// The total node count ("MMR size").
    #[must_use]
    pub const fn node_count(&self) -> MmrSize {
        self.node_count
    }

    /// The cached peak hashes, left to right.
    #[must_use]
    pub fn peaks(&self) -> &[H::Output] {
        &self.peaks
    }

    /// The provenance (full history vs peaks-seeded).
    #[must_use]
    pub const fn provenance(&self) -> Provenance {
        self.provenance
    }
}

/// Cross-checks persisted leaf/node counters.
///
/// Pure load-path validation shared by the sync shell, the async shell, and
/// the stacked opener: the node counter must be a well-formed MMR size, and
/// its implied leaf count must equal the stored leaf counter.
#[must_use]
pub(crate) fn checked_counters(leaf_count: u64, node_count: u64) -> CounterCheck {
    let Some(leaves) = MmrSize::new_unchecked(node_count).leaf_count() else {
        return CounterCheck::MalformedNodeCount;
    };
    if leaves.get() != leaf_count {
        return CounterCheck::Mismatch;
    }
    CounterCheck::Ok(leaves, MmrSize::new_unchecked(node_count))
}

/// Outcome of [`checked_counters`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CounterCheck {
    /// Consistent counters: the validated leaf and node counts.
    Ok(LeafCount, MmrSize),
    /// The node counter is not a well-formed MMR size.
    MalformedNodeCount,
    /// The node counter's implied leaf count differs from the leaf counter.
    Mismatch,
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
    apply_append_many(hasher, state, &[element_hash])
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
    apply_append_many(hasher, state, element_hashes)
}

/// The shared append engine: folds every element hash into the state and
/// collects the nodes written along the way.
fn apply_append_many<H: Hasher>(
    hasher: &H,
    state: &MmrState<H>,
    element_hashes: &[H::Output],
) -> AppendDelta<H> {
    let mut peaks = Vec::clone(&state.peaks);
    let mut leaves = state.leaf_count.get();
    let mut node_count = state.node_count.get();
    let mut nodes = Vec::new();

    for &element_hash in element_hashes {
        // The new leaf takes the node right after the current size.
        node_count += 1;
        let leaf_node = NodeIndex::try_new(node_count).expect("leaf node within u64");
        nodes.push((leaf_node, element_hash));
        peaks.push(element_hash);

        // Merge right-spine peaks: one merge per trailing one of the leaf
        // count *before* this append.
        let mut merges = merges_on_append(LeafCount::new(leaves));
        while merges > 0 {
            let right = peaks.pop().expect("merge consumes a peak");
            let left = peaks.pop().expect("merge consumes a peak");
            node_count += 1;
            let parent = NodeIndex::try_new(node_count).expect("parent node within u64");
            let parent_hash = hasher.hash_pair(left, right);
            nodes.push((parent, parent_hash));
            peaks.push(parent_hash);
            merges -= 1;
        }

        leaves += 1;
    }

    AppendDelta {
        state: MmrState {
            leaf_count: LeafCount::new(leaves),
            node_count: MmrSize::new_unchecked(node_count),
            peaks,
            provenance: state.provenance,
        },
        nodes,
    }
}
