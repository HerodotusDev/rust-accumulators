//! Zero-cost primitive types and pure MMR layout math.
//!
//! Everything in this module is `no_std`-safe: fixed-size values, no
//! allocation except where explicitly documented (`Vec` returns in layout
//! math), and no store or hasher dependencies.

use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU64;

/// A 32-byte hash output.
///
/// All hashers in the crate produce 32-byte digests; storing them as bytes
/// instead of hex strings removes a parse/format per hash operation and makes
/// `Copy` semantics explicit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; 32]);

impl Hash {
    /// The all-zero hash.
    pub const ZERO: Self = Self([0; 32]);

    /// Wraps raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Converts into the raw bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Shortened form: hashes appear in proofs and logs in bulk, full width
        // is noise there. Use the `H` alternate form for the full hex.
        write!(f, "Hash(0x")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        write!(f, "…)")
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, _f: &mut fmt::Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl From<[u8; 32]> for Hash {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<Hash> for [u8; 32] {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// A hash output value — the node currency of every accumulator.
///
/// Built-in hashers produce [`Hash`](struct@crate::design::primitives::Hash) (32 bytes); implementing this trait for
/// any `Copy` type — 16-byte truncations, 64-byte digests, field-element
/// wrappers — makes them first-class with zero cost. Same flexibility model
/// as [`TreeId`](crate::design::ids::TreeId): a default for the common case,
/// anything allowed beyond it.
pub trait HashValue: Copy + Eq + Ord + core::hash::Hash + core::fmt::Debug {
    /// Fixed byte length of the canonical encoding.
    const LEN: usize;

    /// Borrows the canonical byte encoding (the store-value form).
    fn as_bytes(&self) -> &[u8];

    /// Rebuilds from a canonical encoding of exactly [`Self::LEN`] bytes, or
    /// `None` on a wrong length.
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

impl HashValue for Hash {
    const LEN: usize = 32;

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 32 {
            let mut out = [0; 32];
            out.copy_from_slice(bytes);
            Some(Self(out))
        } else {
            None
        }
    }
}

/// Position of a node in the MMR's 1-based node space.
///
/// Deliberately a distinct type from [`LeafIndex`]: the v0.5 API accepted bare
/// `usize` in both spaces and callers passed leaves where nodes were expected
/// (or vice versa) with no diagnostic.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct NodeIndex(NonZeroU64);

impl NodeIndex {
    /// Index of the first node.
    pub const FIRST: Self = Self(NonZeroU64::MIN);

    /// Creates an index, or `None` for `0` (which is not a valid node).
    ///
    /// Named `try_new` per Rust convention: fallible construction.
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
    #[must_use]
    pub const fn height(self) -> u8 {
        todo!()
    }

    /// Index of the parent, if the node is not a peak of its current tree.
    #[must_use]
    pub const fn parent(self) -> Option<Self> {
        todo!()
    }

    /// The leaf this node wraps, if it is a leaf.
    #[must_use]
    pub const fn as_leaf(self) -> Option<LeafIndex> {
        todo!()
    }
}

impl fmt::Display for NodeIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.get())
    }
}

/// Position of an appended element (leaf) in the MMR, 0-based.
///
/// This is the index space all *public* proof APIs speak. Conversions to
/// [`NodeIndex`] are explicit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LeafIndex(u64);

impl LeafIndex {
    /// Index of the first appended leaf.
    pub const FIRST: Self = Self(0);

    /// Creates a leaf index. Any `u64` is a valid leaf index value; whether a
    /// given MMR *contains* that leaf is checked at the point of use.
    #[must_use]
    pub const fn new(index: u64) -> Self {
        Self(index)
    }

    /// The raw 0-based index.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// The node index that holds this leaf's hash.
    #[must_use]
    pub const fn node(self) -> NodeIndex {
        todo!()
    }
}

impl fmt::Display for LeafIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
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
        LeafIndex(self.0)
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
        // Placeholder until the layout math lands; the real body validates
        // the same way `leaf_count` does.
        let _ = size;
        todo!()
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
        todo!()
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
    #[must_use]
    pub const fn new(height: u8) -> Self {
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
#[must_use]
pub fn peaks_of(_size: MmrSize) -> Vec<NodeIndex> {
    todo!()
}

/// Heights of the peaks of an MMR of the given size, left to right.
#[must_use]
pub fn peak_heights(_size: MmrSize) -> Vec<Height> {
    todo!()
}

/// The full sibling path of a leaf, bottom-up, for an MMR of the given size.
///
/// The last path element is the sibling across the peak level; bagging is a
/// separate concern and is not part of the path.
#[must_use]
pub fn sibling_path(_leaf: LeafIndex, _size: MmrSize) -> Vec<PathStep> {
    todo!()
}

/// Node count for an MMR holding `leaves` leaves.
#[must_use]
pub const fn size_of(_leaves: LeafCount) -> MmrSize {
    todo!()
}

/// Number of merges an append triggers for an MMR with `leaves` leaves.
#[must_use]
pub const fn merges_on_append(_leaves: LeafCount) -> u64 {
    todo!()
}

/// Folds a list of peak hashes into the single bagged peak, right to left with
/// the leftmost peak outermost, per the current (test-pinned) semantics.
///
/// A single peak bags to itself; zero peaks bags to the hasher's genesis
/// value (see [`crate::design::hashers::Hasher::genesis`]).
///
/// Infallible by construction: bagging is a fold of
/// [`Hasher::hash_pair`](crate::design::hashers::Hasher::hash_pair)
/// calls, and `hash_pair` is infallible — the v0.5 arity error class does not
/// exist here.
#[must_use]
pub fn bag_peaks<H: crate::design::hashers::Hasher>(
    _hasher: &H,
    _peaks: &[H::Output],
) -> H::Output {
    todo!()
}

/// Computes the MMR root from bagged peaks and the node count.
///
/// Preserves the existing binding `root = H(node_count_as_decimal, bag)` —
/// this is hash-format-sensitive and pinned by golden tests.
#[must_use]
pub fn root_from<H: crate::design::hashers::Hasher>(
    _hasher: &H,
    _bag: H::Output,
    _size: MmrSize,
) -> H::Output {
    todo!()
}
