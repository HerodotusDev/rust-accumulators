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
use crate::store::keys::Table;
use crate::store::record::{parse_counter, parse_hasher_info, parse_text};
use alloc::vec::Vec;

/// Provenance of an MMR: full history, or created from peaks at a pinned size.
///
/// A peaks-only MMR has the same root as the full MMR it was seeded from, but
/// leaves below [`Provenance::first_provable_leaf`] have no sibling data and
/// cannot be proven.
///
/// Persisted per accumulator in `keys::Table::Provenance` (see the
/// `store::keys` wire spec) and validated on open, so a re-opened peaks-only
/// MMR cannot silently degrade to full history and lose the seed floor.
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
    /// The peaks must match `size_at_creation` — a valid MMR size and exactly
    /// [`LeafCount::get`]'s trailing `popcount(leaf_count)` peaks for it.
    /// Handles validate this before calling (rejecting with
    /// [`MmrError::InvalidPeaks`](super::MmrError::InvalidPeaks)); the
    /// check is repeated here because the constructor is public and a
    /// divergent state would silently corrupt every downstream conclusion
    /// (roots, floors, provability).
    ///
    /// # Panics
    ///
    /// Panics when the peak count does not match `size_at_creation`'s
    /// implied peak count, or when `size_at_creation` is not a well-formed
    /// MMR size — a caller bug is a panic, not a silently wrong state.
    #[must_use]
    pub fn from_peaks(size_at_creation: MmrSize, peaks: &[H::Output]) -> Self {
        let leaf_count = size_at_creation.leaf_count().unwrap_or_else(|| {
            panic!("from_peaks: size {size_at_creation} is not a well-formed MMR size")
        });
        assert_eq!(
            peaks.len(),
            leaf_count.get().count_ones() as usize,
            "from_peaks: peak count must match the leaf count's popcount"
        );
        Self {
            leaf_count,
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
/// the stacked opener — and part of the custom-shell seam: any shell reading
/// the same persisted records runs them through this check. The node counter
/// must be a well-formed MMR size, and its implied leaf count must equal the
/// stored leaf counter.
#[must_use]
pub fn checked_counters(leaf_count: u64, node_count: u64) -> CounterCheck {
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
pub enum CounterCheck {
    /// Consistent counters: the validated leaf and node counts.
    Ok(LeafCount, MmrSize),
    /// The node counter is not a well-formed MMR size.
    MalformedNodeCount,
    /// The node counter's implied leaf count differs from the leaf counter.
    Mismatch,
}

/// Metadata validated by [`validate_metadata`]: the counters and the
/// persisted provenance. Part of the custom-shell seam — a shell opening an
/// MMR accumulator's records ends here, with the validated view.
#[derive(Debug, Clone, Copy)]
pub struct Metadata {
    /// Validated leaf count.
    pub leaf_count: LeafCount,
    /// Validated node count.
    pub node_count: MmrSize,
    /// Validated provenance (see the `store::keys` wire spec for the record
    /// format).
    pub provenance: Provenance,
}

/// The one shared load-path metadata validation (hasher, mode, counters,
/// provenance) used by every MMR shell — and available to custom shells over
/// the same records. The root check stays with the callers: it compares
/// against the recomputed root, whose peak loading differs per shell
/// (routed for stacks).
///
/// `values` holds the raw records in table order `HasherInfo, Mode,
/// LeafCount, NodeCount, Provenance` (the `store::keys::Table` tags) —
/// absence and malformed content are both [`Corrupted`](super::Corrupted)
/// findings, distinguished by table.
///
/// The record byte layouts are the persisted wire spec (see the
/// `store::keys` module docs); this function is their shared decoder and its
/// acceptance is byte-compatible with every shell.
///
/// # Errors
///
/// [`Corrupted`](super::Corrupted) findings distinguished by table: missing
/// or malformed records, hasher and mode mismatches, inconsistent counters,
/// an out-of-range seed.
pub fn validate_metadata<H: Hasher>(
    hasher: &H,
    values: [&[u8]; 5],
    declared_mode: &'static str,
) -> Result<Metadata, super::Corrupted> {
    use super::Corrupted;

    let malformed = |table| Corrupted::MalformedRecord { table };
    let [hasher_info, mode, leaf_bytes, node_bytes, provenance] = values;

    let (stored_id, stored_config) =
        parse_hasher_info(hasher_info).ok_or_else(|| malformed(Table::HasherInfo))?;
    if stored_id != hasher.id() || stored_config != hasher.config() {
        return Err(Corrupted::HasherMismatch {
            stored: alloc::format!("{stored_id} ({stored_config})"),
            supplied: alloc::format!("{} ({})", hasher.id(), hasher.config()),
        });
    }

    let stored_mode = parse_text(mode).ok_or_else(|| malformed(Table::Mode))?;
    if stored_mode != declared_mode {
        return Err(Corrupted::ModeMismatch {
            stored: stored_mode,
            declared: declared_mode,
        });
    }

    // Counters and their mutual consistency.
    let leaf_count = parse_counter(leaf_bytes).ok_or_else(|| malformed(Table::LeafCount))?;
    let node_count = parse_counter(node_bytes).ok_or_else(|| malformed(Table::NodeCount))?;
    let (leaf_count, node_count) = match checked_counters(leaf_count, node_count) {
        CounterCheck::Ok(leaves, nodes) => (leaves, nodes),
        CounterCheck::MalformedNodeCount => return Err(malformed(Table::NodeCount)),
        CounterCheck::Mismatch => {
            return Err(Corrupted::PeaksMismatch {
                expected: node_count.count_ones() as usize,
                found: leaf_count.count_ones() as usize,
            });
        }
    };

    // Provenance: a missing record on an accumulator that reports a nonzero
    // size cannot be assumed Full (peaks-only provenance would silently
    // degrade and the seed floor would be lost), so it is a
    // missing-record finding, fail-closed.
    let provenance = parse_provenance(provenance).ok_or_else(|| malformed(Table::Provenance))?;
    if let Provenance::FromPeaks { size_at_creation } = provenance {
        // The seed must be a well-formed MMR size that does not exceed the
        // persisted node count — otherwise the floor would sit beyond the
        // MMR's own history.
        let seed_leaf_count = size_at_creation
            .leaf_count()
            .ok_or_else(|| malformed(Table::Provenance))?;
        if size_at_creation > node_count || seed_leaf_count > leaf_count {
            return Err(malformed(Table::Provenance));
        }
    }

    Ok(Metadata {
        leaf_count,
        node_count,
        provenance,
    })
}

/// Encodes the `Provenance` record: `[kind: u8]` (`0` = full history, `1` =
/// peaks-only) and, for peaks-only, `[size_at_creation: u64 BE]`.
///
/// Persisted format: the byte layout is fixed by the `store::keys` wire
/// spec — a change would strand every persisted accumulator, so this
/// encoding is a compatibility commitment, not an implementation detail.
#[must_use]
pub fn encode_provenance(provenance: Provenance) -> Vec<u8> {
    match provenance {
        Provenance::Full => alloc::vec![0],
        Provenance::FromPeaks { size_at_creation } => {
            let mut out = alloc::vec![1];
            out.extend_from_slice(&size_at_creation.get().to_be_bytes());
            out
        }
    }
}

/// Decodes the `Provenance` record (see [`encode_provenance`] for the fixed
/// byte layout).
#[must_use]
pub fn parse_provenance(bytes: &[u8]) -> Option<Provenance> {
    match *bytes.first()? {
        0 => Some(Provenance::Full),
        1 => Some(Provenance::FromPeaks {
            size_at_creation: MmrSize::new_unchecked(parse_counter(bytes.get(1..)?)?),
        }),
        _ => None,
    }
}

/// Everything one append produces: the new state, the nodes to persist, and
/// the root after the append.
///
/// Shells translate `nodes` into batch puts — one store write per append,
/// independent of how many merges fire. The root is derived here (from the
/// delta's final cached peaks) so shells persist and report it without
/// re-bagging — one bagging per operation, not one per consumer.
#[derive(Clone, Debug)]
pub struct AppendDelta<H: Hasher> {
    /// State after the append.
    pub state: MmrState<H>,
    /// New node hashes to persist, including the leaf itself.
    pub nodes: Vec<(NodeIndex, H::Output)>,
    /// Root after the append: `state.root(hasher)`, computed once.
    pub root: H::Output,
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
///
/// Public for custom shells: this is the engine behind [`apply_append`] and
/// [`apply_append_batch`] — a shell committing straight to the store appends
/// through it. The element is *already* hashed; merging is infallible (it
/// folds [`Hasher::hash_pair`] calls).
///
/// # Panics
///
/// Panics only on u64 node-counter overflow — unreachable for any state
/// within the layout bound ([`MAX_LEAF_COUNT`](crate::primitives::MAX_LEAF_COUNT)).
#[must_use]
pub fn apply_append_many<H: Hasher>(
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
        #[expect(
            clippy::expect_used,
            reason = "node_count only grows by 1 per iteration, never past u64::MAX"
        )]
        let leaf_node = NodeIndex::try_new(node_count).expect("leaf node within u64");
        nodes.push((leaf_node, element_hash));
        peaks.push(element_hash);

        // Merge right-spine peaks: one merge per trailing one of the leaf
        // count *before* this append.
        let mut merges = merges_on_append(LeafCount::new(leaves));
        while merges > 0 {
            #[expect(
                clippy::expect_used,
                reason = "merges_on_append counts existing peaks; the pops cannot exhaust"
            )]
            let right = peaks.pop().expect("merge consumes a peak");
            #[expect(
                clippy::expect_used,
                reason = "merges_on_append counts existing peaks; the pops cannot exhaust"
            )]
            let left = peaks.pop().expect("merge consumes a peak");
            node_count += 1;
            #[expect(
                clippy::expect_used,
                reason = "node_count only grows by 1 per iteration, never past u64::MAX"
            )]
            let parent = NodeIndex::try_new(node_count).expect("parent node within u64");
            let parent_hash = hasher.hash_pair(left, right);
            nodes.push((parent, parent_hash));
            peaks.push(parent_hash);
            merges -= 1;
        }

        leaves += 1;
    }

    let state = MmrState {
        leaf_count: LeafCount::new(leaves),
        node_count: MmrSize::new_unchecked(node_count),
        peaks,
        provenance: state.provenance,
    };
    let root = state.root(hasher);
    AppendDelta { state, nodes, root }
}
