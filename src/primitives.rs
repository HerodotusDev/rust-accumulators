//! Zero-cost primitive types shared by every accumulator family.
//!
//! Deliberately small: [`Hash`](crate::primitives::Hash), the
//! [`HashValue`](crate::primitives::HashValue) trait, the shared leaf
//! index ([`LeafIndex`](crate::primitives::LeafIndex)) and its space bound
//! ([`MAX_LEAF_COUNT`](crate::primitives::MAX_LEAF_COUNT)). Everything
//! MMR-specific — the node-index vocabulary and the layout math — lives in
//! `crate::mmr::layout`, so a build without the `mmr` feature does not
//! carry it. All types here are `no_std`-safe: fixed-size, no store or hasher
//! dependencies.

use alloc::vec::Vec;
use core::fmt;

/// Highest leaf count the layout math supports: above it, node counts no
/// longer fit `u64` arithmetic.
pub const MAX_LEAF_COUNT: u64 = (1 << 63) - 1;

/// A 32-byte hash output.
///
/// All byte-oriented hashers in the crate produce 32-byte digests; storing
/// them as bytes instead of hex strings removes a parse/format per hash
/// operation and makes `Copy` semantics explicit.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash([u8; 32]);

impl Hash {
    /// The all-zero hash — the null placeholder of the fixed-width encodings.
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

    /// The value as a 32-byte big-endian integer.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        let mut out = [0; 32];
        out[24..].copy_from_slice(&value.to_be_bytes());
        Self(out)
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
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
/// Byte-oriented hashers produce [`Hash`](struct@Hash) (32 bytes); the Starknet field
/// hashers produce `starknet_crypto::Felt`. Implementing this trait for any
/// `Copy` type — 16-byte truncations, 64-byte digests, field-element
/// wrappers — makes it first-class with zero cost. Same flexibility model as
/// [`TreeId`](crate::ids::TreeId): a default for the common case, anything
/// allowed beyond it.
pub trait HashValue: Copy + Eq + Ord + core::hash::Hash + core::fmt::Debug {
    /// Fixed byte length of the canonical encoding.
    const LEN: usize;

    /// The value as a canonical integer — how node counts enter hashing.
    fn from_u64(value: u64) -> Self;

    /// Writes the canonical byte encoding (the store-value form) into `out`.
    /// The caller provides exactly [`Self::LEN`] bytes.
    fn write_bytes(&self, out: &mut [u8]);

    /// The canonical byte encoding as an owned buffer.
    #[must_use]
    fn to_vec(&self) -> Vec<u8> {
        let mut out = alloc::vec![0; Self::LEN];
        self.write_bytes(&mut out);
        out
    }

    /// Rebuilds from a canonical encoding of exactly [`Self::LEN`] bytes, or
    /// `None` on a wrong length or out-of-range value.
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

impl HashValue for Hash {
    const LEN: usize = 32;

    fn from_u64(value: u64) -> Self {
        Self::from_u64(value)
    }

    fn write_bytes(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.0);
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

/// Position of an appended element (leaf) in a tree accumulator, 0-based.
///
/// In the MMR this is the index space all *public* proof APIs speak; the
/// mapping to the MMR's 1-based node space lives in `crate::mmr::layout`.
/// The Merkle tree uses the same 0-based leaf space.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LeafIndex(u64);

impl LeafIndex {
    /// Index of the first appended leaf.
    pub const FIRST: Self = Self(0);

    /// Creates a leaf index.
    ///
    /// Whether a given accumulator *contains* that leaf is checked at the
    /// point of use.
    ///
    /// # Panics
    ///
    /// Panics when `index` exceeds [`MAX_LEAF_COUNT`] — beyond it the MMR
    /// node mapping would overflow `u64`. Unreachable for real accumulators,
    /// which cannot grow that large.
    #[must_use]
    pub const fn new(index: u64) -> Self {
        assert!(
            index <= MAX_LEAF_COUNT,
            "leaf index beyond the layout range"
        );
        Self(index)
    }

    /// The raw 0-based index.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for LeafIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
