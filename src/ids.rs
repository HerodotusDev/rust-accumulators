//! Accumulator identifiers: flexible, feature-extensible, collision-proof
//! in keys.
//!
//! The default id is [`AccumulatorId`](crate::ids::AccumulatorId) — 16 bytes, which uuid v4, uuid v7 and ulid
//! all serialize into with zero heap use. Accumulators are generic over
//! [`TreeId`](crate::ids::TreeId), so any `Copy` id type (32-byte digests, semantic composites
//! like `(chain_id, contract, slot)`, …) plugs in by implementing one
//! method; the common case just infers `AccumulatorId` everywhere.
//!
//! Store keys are length-prefixed binary (`[id_len][id bytes][table tag]
//! [index]`), so ids of any length and content are safe — no delimiter can
//! collide (fixing the v0.5 bug where an `mmr_id` containing `:` corrupted
//! key parsing).
//!
//! Feature flags:
//! - `uuid_v4` — `random_v4`,
//! - `uuid_v7` — `now_v7` (time-ordered, index-friendly; enables `uuid/v7`;
//!   the clock-based constructor additionally requires the `std` feature),
//! - `ulid` — `from_ulid` (const) / `generate_ulid` (requires `std`).

use alloc::vec::Vec;

/// An accumulator identifier usable in store keys.
///
/// Implement this for your own id type and pass it wherever an id is
/// required; [`AccumulatorId`] is the built-in default.
pub trait TreeId: Copy + Eq + Ord + core::hash::Hash + core::fmt::Debug {
    /// Appends the canonical byte encoding to `out` (the store-key form).
    /// Any length works — the key layout length-prefixes id bytes.
    fn encode_into(&self, out: &mut Vec<u8>);

    /// Rebuilds from the canonical byte encoding, or `None` on a wrong
    /// length. Required so persisted stack layers can be reconstructed.
    fn from_bytes(bytes: &[u8]) -> Option<Self>;
}

/// A 128-bit accumulator identifier — the default [`TreeId`], shared by the
/// MMR and the Merkle tree.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct AccumulatorId([u8; 16]);

impl AccumulatorId {
    /// The all-zero id. Valid for tests and ephemeral use; production code
    /// should prefer a generated id so distinct accumulators sharing a store
    /// cannot collide.
    pub const ZERO: Self = Self([0; 16]);

    /// Wraps arbitrary 16 bytes — the escape hatch for custom id schemes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw bytes (used for key encoding).
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl From<[u8; 16]> for AccumulatorId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl From<AccumulatorId> for [u8; 16] {
    fn from(id: AccumulatorId) -> Self {
        id.0
    }
}

impl AsRef<[u8]> for AccumulatorId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AccumulatorId {
    /// Random uuid v4. Requires the `uuid_v4` feature.
    #[cfg(feature = "uuid_v4")]
    #[must_use]
    pub fn random_v4() -> Self {
        Self(*uuid::Uuid::new_v4().as_bytes())
    }

    /// Time-ordered uuid v7 — ids sort by creation time, which keeps
    /// key-value stores' write amplification low. Requires the `uuid_v7`
    /// feature (enables `uuid/v7`) and the `std` feature (a wall clock).
    #[cfg(all(feature = "uuid_v7", feature = "std"))]
    #[must_use]
    pub fn now_v7() -> Self {
        Self(*uuid::Uuid::now_v7().as_bytes())
    }

    /// Wraps an existing ulid.
    #[cfg(feature = "ulid")]
    #[must_use]
    pub const fn from_ulid(ulid: ulid::Ulid) -> Self {
        Self(ulid.to_bytes())
    }

    /// Generates a new monotonic ulid. Requires the `ulid` and `std`
    /// features (a wall clock and the system RNG).
    #[cfg(all(feature = "ulid", feature = "std"))]
    #[must_use]
    pub fn generate_ulid() -> Self {
        Self(ulid::Ulid::generate().to_bytes())
    }
}

impl core::fmt::Debug for AccumulatorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "AccumulatorId({self})")
    }
}

impl core::fmt::Display for AccumulatorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in &self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl core::str::FromStr for AccumulatorId {
    type Err = AccumulatorIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.as_bytes();
        if bytes.len() != 32 {
            return Err(AccumulatorIdParseError::WrongLength(bytes.len()));
        }
        let mut out = [0; 16];
        for (i, chunk) in bytes.as_chunks::<2>().0.iter().enumerate() {
            let hi = (chunk[0] as char)
                .to_digit(16)
                .ok_or(AccumulatorIdParseError::BadHex)?;
            let lo = (chunk[1] as char)
                .to_digit(16)
                .ok_or(AccumulatorIdParseError::BadHex)?;
            #[expect(
                clippy::cast_possible_truncation,
                reason = "each digit is 0..=15, so (hi << 4) | lo is at most 0xFF"
            )]
            let byte = ((hi << 4) | lo) as u8;
            out[i] = byte;
        }
        Ok(Self(out))
    }
}

/// Failed to parse an [`AccumulatorId`] from text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AccumulatorIdParseError {
    /// The text is not 32 characters (16 bytes hex-encoded).
    WrongLength(usize),
    /// A character is not a lowercase or uppercase hex digit.
    BadHex,
}

impl core::fmt::Display for AccumulatorIdParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongLength(len) => {
                write!(
                    f,
                    "invalid accumulator id: expected 32 hex characters, found {len}"
                )
            }
            Self::BadHex => write!(f, "invalid accumulator id: not a hex string"),
        }
    }
}

impl core::error::Error for AccumulatorIdParseError {}

impl TreeId for AccumulatorId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let array: [u8; 16] = bytes.try_into().ok()?;
        Some(Self(array))
    }
}

/// Encodes any id into an owned buffer (the store-key form).
#[cfg(any(feature = "mmr", feature = "merkle_tree"))]
#[expect(dead_code, reason = "shared codec; used by stacked persistence paths")]
pub(crate) fn encoded_id<Id: TreeId>(id: &Id) -> Vec<u8> {
    let mut out = Vec::new();
    id.encode_into(&mut out);
    out
}
