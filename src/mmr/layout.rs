//! Pure MMR layout math: the node-index vocabulary and the size/peak/path
//! computations every MMR shell shares.
//!
//! Everything here is `no_std`-safe: fixed-size values, no allocation except
//! where explicitly documented (`Vec` returns), and no store dependencies.
//!
//! # Layout model (test-pinned)
//!
//! The MMR's node space is 1-based; leaf `i` (0-based) lives at node
//! `2i + 1 − popcount(i)`. A node of height `h` spans `2^(h+1) − 1` nodes
//! ending at itself; its left child is `n − 2^h` and its right child is
//! `n − 1`. Peaks are the roots of the perfect mountains that tile the node
//! count; bagging folds them right-to-left with the leftmost peak outermost.
//!
//! The shared leaf-space bound ([`MAX_LEAF_COUNT`]) and the leaf index type
//! itself live in [`crate::primitives`]; the MMR-specific node mapping
//! ([`LeafIndex::node`]) lives here.

use crate::hashers::Hasher;
use crate::primitives::{HashValue, LeafIndex, MAX_LEAF_COUNT};
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU64;

/// Position of a node in the MMR's 1-based node space.
///
/// Deliberately a distinct type from [`LeafIndex`]: leaf and node spaces are
/// different vocabularies, and a distinct type turns mixing them up into a
/// compile error.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NodeIndex(NonZeroU64);

impl NodeIndex {
    /// Index of the first node.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Creates an index, or `None` for `0` (which is not a valid node).
    #[must_use]
    pub const fn try_new(index: u64) -> Option<Self> {
        match NonZeroU64::new(index) {
            Some(n) => Some(Self(n)),
            None => None,
        }
    }

    /// The raw 1-based index.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// Height of the node in the MMR (leaves are height 0).
    ///
    /// Derived from the node's position in the gap structure: a node of
    /// height `h ≥ 1` sits `h` nodes past the leaf node that closes the
    /// mountain before it, which pins `n + 1` to
    /// `q · 2^(h+1) − popcount(q−1)` for some `q ≥ 1`. The largest such `h`
    /// is the height; `h = 0` (leaves) has a solution for every `n`.
    #[must_use]
    pub const fn height(self) -> Height {
        let n = self.get();
        // The smallest perfect mountain that can contain `n` bounds the
        // search from above: 2^(h+1) ≤ n + 1 + 64. `n ≥ 1`, so the bound is
        // never 0 and `ilog2` cannot panic.
        let bound = n.saturating_add(64);
        let mut h = bound.ilog2().saturating_sub(1);
        while h >= 1 {
            if matches_height(n, h) {
                #[expect(
                    clippy::cast_possible_truncation,
                    reason = "h is at most ilog2(u64::MAX) = 63, so it fits in u8"
                )]
                return Height::new(h as u8);
            }
            h -= 1;
        }
        Height::LEAF
    }

    /// Index of the parent, or `None` on `u64` overflow (unreachable for
    /// well-formed MMRs).
    ///
    /// The side is decided by the node's position within its height level:
    /// odd positions are right children (`parent = n + 1`), even positions
    /// are left children (`parent = n + 2^(h+1)`).
    #[must_use]
    pub const fn parent(self) -> Option<Self> {
        let Some(leftmost) = self.leftmost_leaf() else {
            return None;
        };
        let h = self.height().get() as u32;
        let position = leftmost >> h;
        if position % 2 == 1 {
            match self.0.checked_add(1) {
                Some(p) => Some(Self(p)),
                None => None,
            }
        } else {
            match self.0.checked_add(1u64 << (h + 1)) {
                Some(p) => Some(Self(p)),
                None => None,
            }
        }
    }

    /// The left child — `n − 2^height` — or `None` for a leaf node. Children
    /// exist only below the leaf row: a leaf's children are phantom and no
    /// index names them. The downward inverse of [`Self::parent`]: for every
    /// internal node, `left_child().parent() == Some(self)`.
    #[must_use]
    pub const fn left_child(self) -> Option<Self> {
        let h = self.height().get() as u32;
        if h == 0 {
            return None;
        }
        match self.get().checked_sub(1_u64 << h) {
            Some(raw) => Self::try_new(raw),
            None => None,
        }
    }

    /// The right child — `n − 1` — or `None` for a leaf node (see
    /// [`Self::left_child`]). For every internal node,
    /// `right_child().parent() == Some(self)`.
    #[must_use]
    pub const fn right_child(self) -> Option<Self> {
        if self.height().get() == 0 {
            return None;
        }
        match self.get().checked_sub(1) {
            Some(raw) => Self::try_new(raw),
            None => None,
        }
    }

    /// The leaf this node wraps, if it is a leaf.
    ///
    /// A leaf node `n` satisfies `n − 1 = 2L − popcount(L)` — exactly the
    /// node count of an MMR with `L` leaves — so the leaf index falls out of
    /// the standard size-to-leaf walk.
    #[must_use]
    pub const fn as_leaf(self) -> Option<LeafIndex> {
        match leaf_count_of_size(self.get().saturating_sub(1)) {
            Some(count) => Some(count.next_leaf()),
            None => None,
        }
    }

    /// The leftmost leaf index covered by this node's subtree, or `None` on
    /// overflow. `n = node(L) + 2^(h+1) − 2` for the leftmost leaf `L`, and
    /// `node(L) − 1 = 2L − popcount(L)` is the node count of an `L`-leaf MMR,
    /// so `L = leaf_count_of_size(n + 1 − 2^(h+1))`.
    const fn leftmost_leaf(self) -> Option<u64> {
        let h = self.height().get() as u32;
        match self.get().checked_add(1) {
            Some(n1) => match n1.checked_sub(1u64 << (h + 1)) {
                Some(prefix) => match leaf_count_of_size(prefix) {
                    Some(count) => Some(count.get()),
                    None => None,
                },
                None => None,
            },
            None => None,
        }
    }
}

/// Whether node `n` has height `h`: exists `q ≥ 1` with
/// `n + 1 = q · 2^(h+1) − popcount(q−1)`.
const fn matches_height(n: u64, h: u32) -> bool {
    let shift = h + 1;
    if shift >= 64 {
        return false;
    }
    let base = 1u64 << shift;
    let target = n.wrapping_add(1);
    // q·base = target + padding with padding = popcount(q−1) ∈ [0, 64], so a
    // solution's q must satisfy q·base ∈ [target, target + 64] — i.e. q lies
    // in the window [target/base, (target + 64)/base]. Only that window is
    // searched.
    let lo = target / base;
    let hi = target.saturating_add(64) / base;
    let mut q = if lo == 0 { 1 } else { lo };
    while q <= hi {
        if let Some(product) = q.checked_mul(base) {
            let padding = if q == 0 {
                0
            } else {
                (q - 1).count_ones() as u64
            };
            if product == target.saturating_add(padding) {
                return true;
            }
        }
        q += 1;
    }
    false
}

/// Failed to build a [`NodeIndex`] from a raw `u64`: node indexes are
/// 1-based, so `0` names no node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NodeIndexZero;

impl fmt::Display for NodeIndexZero {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "node index 0 is invalid: node indexes are 1-based")
    }
}

impl core::error::Error for NodeIndexZero {}

impl TryFrom<u64> for NodeIndex {
    type Error = NodeIndexZero;

    fn try_from(index: u64) -> Result<Self, Self::Error> {
        Self::try_new(index).ok_or(NodeIndexZero)
    }
}

impl fmt::Display for NodeIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get())
    }
}

impl LeafIndex {
    /// The node index that holds this leaf's hash: `2i + 1 − popcount(i)`.
    ///
    /// Total for every constructible [`LeafIndex`]: [`LeafIndex::new`] rejects
    /// indices beyond [`MAX_LEAF_COUNT`], where the mapping would overflow.
    #[must_use]
    pub const fn node(self) -> NodeIndex {
        let i = self.get();
        let raw = (i << 1) + 1 - i.count_ones() as u64;
        match NonZeroU64::new(raw) {
            Some(node) => NodeIndex(node),
            // Unreachable: `i < MAX_LEAF_COUNT` keeps `raw` in `1..=u64::MAX`.
            None => NodeIndex::FIRST,
        }
    }
}

/// Number of leaves (appended elements) in an MMR.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct LeafCount(u64);

impl LeafCount {
    /// An empty MMR.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw count.
    #[must_use]
    pub const fn new(count: u64) -> Self {
        Self(count)
    }

    /// The raw count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The index one past the last leaf — the next append position.
    #[must_use]
    pub const fn next_leaf(self) -> LeafIndex {
        LeafIndex::new(self.0)
    }
}

impl TryFrom<u64> for LeafCount {
    type Error = crate::primitives::LeafSpaceOverflow;

    fn try_from(count: u64) -> Result<Self, Self::Error> {
        if count <= MAX_LEAF_COUNT {
            Ok(Self(count))
        } else {
            Err(crate::primitives::LeafSpaceOverflow(count))
        }
    }
}

impl From<LeafCount> for u64 {
    fn from(count: LeafCount) -> Self {
        count.0
    }
}

impl fmt::Display for LeafCount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Total number of nodes in the MMR (the "MMR size").
///
/// Not every value is a valid MMR size: valid sizes are those where the
/// leftover right spine is empty. Constructions from raw values go through
/// [`MmrSize::leaf_count`] which validates.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct MmrSize(u64);

impl MmrSize {
    /// Size of an empty MMR.
    pub const ZERO: Self = Self(0);

    /// Wraps a raw node count **without validation**. Prefer [`Self::try_new`].
    #[must_use]
    pub const fn new_unchecked(size: u64) -> Self {
        Self(size)
    }

    /// Wraps a raw node count, or `None` if it does not correspond to a
    /// well-formed MMR (see [`Self::leaf_count`]).
    #[must_use]
    pub const fn try_new(size: u64) -> Option<Self> {
        match leaf_count_of_size(size) {
            Some(_) => Some(Self(size)),
            None => None,
        }
    }

    /// The raw node count.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The number of leaves backing this MMR size, or `None` if the size does
    /// not correspond to a well-formed MMR.
    #[must_use]
    pub const fn leaf_count(self) -> Option<LeafCount> {
        leaf_count_of_size(self.0)
    }
}

/// Failed to build an [`MmrSize`] from a raw `u64`: the value does not
/// correspond to a well-formed MMR (its leftover right spine is non-empty).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InvalidMmrSize(
    /// The rejected raw value.
    pub u64,
);

impl fmt::Display for InvalidMmrSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} is not a valid MMR size: the leftover right spine is non-empty",
            self.0
        )
    }
}

impl core::error::Error for InvalidMmrSize {}

impl TryFrom<u64> for MmrSize {
    type Error = InvalidMmrSize;

    fn try_from(size: u64) -> Result<Self, Self::Error> {
        Self::try_new(size).ok_or(InvalidMmrSize(size))
    }
}

impl fmt::Display for MmrSize {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Height of a node: leaves are height 0, each merge adds one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Height(u8);

impl Height {
    /// Height of a leaf.
    pub const LEAF: Self = Self(0);

    /// Wraps a raw height.
    ///
    /// # Panics
    ///
    /// Panics when `height` exceeds 63 — beyond it the height could not
    /// belong to any node of a u64-sized MMR (the tallest peak of the
    /// largest representable mountain is 63).
    #[must_use]
    pub const fn new(height: u8) -> Self {
        assert!(height <= 63, "height beyond the layout range");
        Self(height)
    }

    /// The raw height.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Whether a sibling appears on the left or right of the node it pairs with.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Side {
    /// Sibling hash is hashed first (left operand).
    Left,
    /// Sibling hash is hashed second (right operand).
    Right,
}

/// One step of a proof path: the sibling node and which side it sits on.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct PathStep {
    /// The sibling node in the merge.
    pub sibling: NodeIndex,
    /// Which side the sibling occupies relative to the node being proven.
    pub side: Side,
}

/// Node indexes of the peaks of an MMR of the given size, left to right.
///
/// Empty for size `0` and for sizes that are not well-formed MMR sizes.
#[must_use]
pub fn peaks_of(size: MmrSize) -> Vec<NodeIndex> {
    peak_walk(size).map(|(peaks, _)| peaks).unwrap_or_default()
}

/// Heights of the peaks of an MMR of the given size, left to right.
///
/// Empty for size `0` and for sizes that are not well-formed MMR sizes.
#[must_use]
pub fn peak_heights(size: MmrSize) -> Vec<Height> {
    peak_walk(size)
        .map(|(_, heights)| heights)
        .unwrap_or_default()
}

/// Number of peaks of an MMR of the given size — the popcount of its leaf
/// count. Zero for the empty size and for sizes that are not well-formed
/// MMR sizes (matching [`peaks_of`], which returns no peaks for them).
///
/// ```
/// use accumulators::mmr::{LeafCount, MmrSize};
/// use accumulators::utils::mmr::{peak_count, size_of};
///
/// // Five leaves decompose into mountains 4 + 1 → two peaks.
/// assert_eq!(peak_count(size_of(LeafCount::new(5))), 2);
/// ```
#[must_use]
pub const fn peak_count(size: MmrSize) -> u32 {
    match size.leaf_count() {
        Some(count) => count.get().count_ones(),
        None => 0,
    }
}

/// Height of the largest mountain of an MMR of the given size — the first
/// peak's height, `floor(log2(leaf count))`. Zero when the size has no
/// peaks at all: the empty MMR and malformed sizes (matching
/// [`peak_heights`], which returns nothing for them).
///
/// ```
/// use accumulators::mmr::{LeafCount, MmrSize};
/// use accumulators::utils::mmr::{max_peak_height, size_of};
///
/// // Five leaves decompose into mountains 4 + 1 → the tallest is height 2.
/// let size = size_of(LeafCount::new(5));
/// assert_eq!(max_peak_height(size).get(), 2);
/// ```
#[must_use]
pub const fn max_peak_height(size: MmrSize) -> Height {
    match size.leaf_count() {
        Some(count) if count.get() > 0 =>
        {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "a leaf count is at most MAX_LEAF_COUNT < 2^63, so its log2 fits in u8"
            )]
            Height::new(count.get().ilog2() as u8)
        }
        _ => Height::LEAF,
    }
}

/// Shared peak walk: returns peak node indexes and their heights, or `None`
/// for a malformed size.
fn peak_walk(size: MmrSize) -> Option<(Vec<NodeIndex>, Vec<Height>)> {
    let size_add_one = size.get().checked_add(1)?;
    let mut remaining = size.get();
    let mut peaks = Vec::new();
    let mut heights = Vec::new();
    let mut offset = 0_u64;

    // Largest mountain that fits: leaves m = 2^k with 2m−1 ≤ remaining.
    let mut leaves = largest_mountain(size_add_one / 2);
    while leaves > 0 {
        let nodes = ((leaves - 1) << 1) + 1; // 2m − 1 without overflow
        if nodes <= remaining {
            let peak = NodeIndex::try_new(offset + nodes)?;
            offset += nodes;
            peaks.push(peak);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "leaves is a nonzero power of two ≤ 2^63, so its log2 fits in u8"
            )]
            heights.push(Height::new(leaves.ilog2() as u8));
            remaining -= nodes;
        }
        leaves >>= 1;
    }

    if remaining > 0 {
        return None;
    }
    Some((peaks, heights))
}

/// The highest power of two ≤ `bound` (0 for bound 0) — the size in leaves
/// of the largest perfect mountain that fits, and the first term of the
/// binary mountain decomposition behind the peak walk, [`path_length`], and
/// the size-to-leaf mapping.
///
/// ```
/// use accumulators::utils::mmr::largest_mountain;
///
/// assert_eq!(largest_mountain(5), 4);
/// assert_eq!(largest_mountain(8), 8);
/// assert_eq!(largest_mountain(0), 0);
/// assert_eq!(largest_mountain(u64::MAX), 1 << 63);
/// ```
#[must_use]
pub const fn largest_mountain(bound: u64) -> u64 {
    if bound == 0 { 0 } else { 1 << bound.ilog2() }
}

/// The full sibling path of a leaf, bottom-up, for an MMR of the given size.
///
/// The last path element is the sibling across the peak level; bagging is a
/// separate concern and is not part of the path. Empty when the size is not
/// well-formed or the leaf is at or beyond it.
#[must_use]
pub fn sibling_path(leaf: LeafIndex, size: MmrSize) -> Vec<PathStep> {
    if size.leaf_count().is_none() {
        return Vec::new();
    }
    let mut leaf_index = leaf.get();
    let mut node = leaf.node().get();
    let mut height = 0_u32;
    let mut steps = Vec::new();

    // Walk up while the node still exists in this MMR; the final iteration
    // crosses the peak level and is popped off (bagging is not part of the
    // path — see the module docs).
    while node <= size.get() {
        let offset = (1_u64 << (height + 1)) - 1;
        if leaf_index % 2 == 1 {
            steps.push(PathStep {
                sibling: match NodeIndex::try_new(node - offset) {
                    Some(sibling) => sibling,
                    None => return Vec::new(),
                },
                side: Side::Left,
            });
            node += 1;
        } else {
            steps.push(PathStep {
                sibling: match NodeIndex::try_new(node + offset) {
                    Some(sibling) => sibling,
                    None => return Vec::new(),
                },
                side: Side::Right,
            });
            node += offset + 1;
        }
        leaf_index /= 2;
        height += 1;
    }
    steps.pop();
    steps
}

/// Length of a leaf's sibling path — the number of steps from the leaf to
/// its own mountain's peak, which is the height of the mountain containing
/// it. Zero when the leaf has no path: at or beyond the size, or a size
/// that is not well-formed (matching [`sibling_path`], which returns an
/// empty path for those). Bagging the peak into the root is a separate
/// concern and adds no steps.
///
/// ```
/// use accumulators::mmr::{LeafCount, MmrSize};
/// use accumulators::utils::mmr::{path_length, sibling_path, size_of};
/// use accumulators::primitives::LeafIndex;
///
/// let size = size_of(LeafCount::new(5));
/// // Leaf 0 lives in the height-2 mountain covering leaves 0..4; leaf 4
/// // is its own height-0 mountain.
/// assert_eq!(path_length(LeafIndex::new(0), size), 2);
/// assert_eq!(path_length(LeafIndex::new(4), size), 0);
/// // Equals the built path's length, without building it.
/// assert_eq!(
///     path_length(LeafIndex::new(2), size),
///     sibling_path(LeafIndex::new(2), size).len() as u32,
/// );
/// ```
#[must_use]
pub const fn path_length(leaf: LeafIndex, size: MmrSize) -> u32 {
    let Some(count) = size.leaf_count() else {
        return 0;
    };
    // The mountains tile the leaf space tallest-first, one per set bit of
    // the leaf count; walk them until the one containing the leaf.
    let mut remaining = count.get();
    let mut offset = 0_u64;
    let mut mountain = largest_mountain(remaining);
    while mountain > 0 {
        if leaf.get() < offset + mountain {
            return mountain.ilog2();
        }
        offset += mountain;
        remaining -= mountain;
        mountain = largest_mountain(remaining);
    }
    0
}

/// Node count for an MMR holding `leaves` leaves: `2L − popcount(L)`.
///
/// Counts above [`MAX_LEAF_COUNT`] saturate to [`u64::MAX`] — see
/// the size-to-leaf walk below for the inverse.
#[must_use]
pub const fn size_of(leaves: LeafCount) -> MmrSize {
    let l = leaves.0;
    if l > MAX_LEAF_COUNT {
        return MmrSize(u64::MAX);
    }
    MmrSize((l << 1) - l.count_ones() as u64)
}

/// Number of merges an append triggers for an MMR with `leaves` leaves: the
/// trailing ones of the leaf count.
#[must_use]
pub const fn merges_on_append(leaves: LeafCount) -> u64 {
    let l = leaves.0;
    let mut count = 0;
    let mut value = l;
    while value != 0 && value & 1 == 1 {
        value >>= 1;
        count += 1;
    }
    count
}

/// Leaf count of a well-formed MMR of `size` nodes, or `None`.
///
/// Decomposes the size into perfect mountains `2^k − 1` nodes wide; any
/// leftover means the size is not a valid MMR size.
const fn leaf_count_of_size(size: u64) -> Option<LeafCount> {
    let Some(size_add_one) = size.checked_add(1) else {
        return None;
    };
    let mut remaining = size;
    let mut leaves = 0_u64;
    let mut mountain = largest_mountain(size_add_one / 2);

    while mountain > 0 {
        let nodes = ((mountain - 1) << 1) + 1;
        if nodes <= remaining {
            match leaves.checked_add(mountain) {
                Some(total) => leaves = total,
                None => return None,
            }
            remaining -= nodes;
        }
        mountain >>= 1;
    }

    if remaining > 0 {
        return None;
    }
    Some(LeafCount(leaves))
}

/// Folds a list of peak hashes into the single bagged peak, right to left with
/// the leftmost peak outermost. The fold order is pinned by golden tests —
/// it defines the root every verifier computes.
///
/// A single peak bags to itself; zero peaks bags to the hasher's genesis
/// value (see [`Hasher::genesis`]).
///
/// Infallible: bagging is a fold of [`Hasher::hash_pair`] calls.
#[must_use]
pub fn bag_peaks<H: Hasher>(hasher: &H, peaks: &[H::Output]) -> H::Output {
    match peaks.len() {
        0 => hasher.genesis(),
        1 => peaks[0],
        n => {
            let mut acc = hasher.hash_pair(peaks[n - 2], peaks[n - 1]);
            for peak in peaks[..n - 2].iter().rev() {
                acc = hasher.hash_pair(*peak, acc);
            }
            acc
        }
    }
}

/// Computes the MMR root from bagged peaks and the node count.
///
/// Binding: `root = H(node_count, bag)` — the node count enters as a
/// canonical big-endian `u64` integer
/// ([`crate::primitives::HashValue::from_u64`]). Pinned by golden tests.
#[must_use]
pub fn root_from<H: Hasher>(hasher: &H, bag: H::Output, size: MmrSize) -> H::Output {
    hasher.hash_pair(H::Output::from_u64(size.get()), bag)
}
