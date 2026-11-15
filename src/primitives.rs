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
        // is noise there. `#?` (the `H` alternate form) renders the full hex.
        if f.alternate() {
            fmt::LowerHex::fmt(self, f)
        } else {
            write!(f, "Hash(0x")?;
            for byte in &self.0[..4] {
                write!(f, "{byte:02x}")?;
            }
            write!(f, "…)")
        }
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

impl fmt::LowerHex for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for Hash {
    type Err = HashParseError;

    /// Parses the 64-character hex encoding (leading `0x` tolerated).
    ///
    /// ```
    /// use accumulators::primitives::Hash;
    ///
    /// let full = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    /// assert!(full.parse::<Hash>().is_ok());
    /// assert!(format!("0x{full}").parse::<Hash>().is_ok());
    /// assert!("zz".parse::<Hash>().is_err());
    /// assert!("aabb".parse::<Hash>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix("0x").unwrap_or(s);
        let mut out = [0; 32];
        hex::decode_into(hex, &mut out)?;
        Ok(Self(out))
    }
}

/// Failed to parse a [`Hash`](struct@Hash) from text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HashParseError {
    /// The text is not 64 characters (32 bytes hex-encoded), ignoring an
    /// optional `0x` prefix.
    WrongLength(usize),
    /// A character is not a lowercase or uppercase hex digit.
    BadHex,
}

impl fmt::Display for HashParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(f, "invalid hash: expected 64 hex characters, found {len}")
            }
            Self::BadHex => write!(f, "invalid hash: not a hex string"),
        }
    }
}

impl core::error::Error for HashParseError {}

impl From<hex::DecodeError> for HashParseError {
    fn from(error: hex::DecodeError) -> Self {
        match error {
            hex::DecodeError::WrongLength(len) => Self::WrongLength(len),
            hex::DecodeError::BadHex => Self::BadHex,
        }
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

    /// Creates a leaf index, or `None` beyond [`MAX_LEAF_COUNT`] — the
    /// fallible counterpart of [`Self::new`].
    #[must_use]
    pub const fn try_new(index: u64) -> Option<Self> {
        if index <= MAX_LEAF_COUNT {
            Some(Self(index))
        } else {
            None
        }
    }

    /// The raw 0-based index.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A raw value exceeded the leaf-space bound ([`MAX_LEAF_COUNT`]): the
/// MMR layout math cannot represent leaf indexes/counts above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct LeafSpaceOverflow(
    /// The rejected raw value.
    pub u64,
);

impl fmt::Display for LeafSpaceOverflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "value {} exceeds the leaf-space bound {MAX_LEAF_COUNT}",
            self.0
        )
    }
}

impl core::error::Error for LeafSpaceOverflow {}

impl TryFrom<u64> for LeafIndex {
    type Error = LeafSpaceOverflow;

    fn try_from(index: u64) -> Result<Self, Self::Error> {
        Self::try_new(index).ok_or(LeafSpaceOverflow(index))
    }
}

impl From<usize> for LeafIndex {
    /// # Panics
    ///
    /// Panics when the value exceeds [`MAX_LEAF_COUNT`] — impossible on
    /// 64-bit targets.
    fn from(index: usize) -> Self {
        Self::new(index as u64)
    }
}

impl From<LeafIndex> for u64 {
    fn from(leaf: LeafIndex) -> Self {
        leaf.0
    }
}

impl From<LeafIndex> for usize {
    /// # Panics
    ///
    /// Panics when the index exceeds `usize::MAX` — only possible on
    /// 32-bit targets (the leaf-space bound is close to `u64::MAX`).
    fn from(leaf: LeafIndex) -> Self {
        #[expect(
            clippy::expect_used,
            reason = "documented narrow-target conversion failure, not a crate invariant"
        )]
        Self::try_from(leaf.0).expect("leaf index exceeds usize::MAX")
    }
}

impl fmt::Display for LeafIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The shared lowercase-hex codec — one implementation for every consumer
/// (`FromStr`, the wire encodings, the `serde` impls).
pub(crate) mod hex {
    #[cfg(any(feature = "mmr", feature = "serde"))]
    use alloc::string::String;

    /// Lowercase hex encoding of `bytes`.
    #[cfg(any(feature = "mmr", feature = "serde"))]
    pub(crate) fn encode(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[usize::from(byte >> 4)] as char);
            out.push(HEX[usize::from(byte & 0x0f)] as char);
        }
        out
    }

    /// Hex decoding failure: wrong character count or a non-hex character.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum DecodeError {
        /// Not exactly `2 × out.len()` characters.
        WrongLength(usize),
        /// A character is not a hex digit.
        BadHex,
    }

    /// Decodes exactly `out.len()` bytes of hex (no `0x` prefix handling —
    /// callers own the prefix convention) into `out`.
    pub(crate) fn decode_into(s: &str, out: &mut [u8]) -> Result<(), DecodeError> {
        let bytes = s.as_bytes();
        if bytes.len() != out.len() * 2 {
            return Err(DecodeError::WrongLength(bytes.len()));
        }
        for (chunk, slot) in bytes.as_chunks::<2>().0.iter().zip(out) {
            let hi = (chunk[0] as char).to_digit(16).ok_or(DecodeError::BadHex)?;
            let lo = (chunk[1] as char).to_digit(16).ok_or(DecodeError::BadHex)?;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "each digit is 0..=15, so (hi << 4) | lo is at most 0xFF"
            )]
            let byte = ((hi << 4) | lo) as u8;
            *slot = byte;
        }
        Ok(())
    }
}
