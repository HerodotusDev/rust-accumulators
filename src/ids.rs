//! Accumulator identifiers: flexible, feature-extensible, collision-proof
//! in keys.
//!
//! The default id is [`AccumulatorId`](crate::ids::AccumulatorId) — 16 bytes, which uuid v4, uuid v7 and ulid
//! all serialize into with zero heap use. Accumulators are generic over
//! [`TreeId`](crate::ids::TreeId), so any `Copy` id type (32-byte digests, semantic composites
//! like `(chain_id, contract, slot)`, …) plugs in by implementing one
//! method; the common case infers `AccumulatorId` everywhere.
//!
//! Store keys are length-prefixed binary (`[id_len][id bytes][table tag]
//! [index]`), so no delimiter or id content can collide with the key
//! structure. The id length prefix is
//! one byte: ids must encode to **at most 255 bytes**
//! (`store::keys::encode` panics beyond that — silent truncation would
//! alias one accumulator's keyspace onto another's).
//!
//! Feature flags:
//! - `uuid_v4` — `random_v4`,
//! - `uuid_v7` — `now_v7` (time-ordered, index-friendly; enables `uuid/v7`;
//!   the clock-based constructor additionally requires the `std` feature),
//! - `ulid` — `from_ulid` (const) / `generate_ulid` (requires `std`).

use alloc::vec::Vec;

use crate::primitives::hex;

/// An accumulator identifier usable in store keys.
///
/// Implement this for your own id type and pass it wherever an id is
/// required; [`AccumulatorId`] is the built-in default.
///
/// # Key-encoding bound
///
/// The store-key layout length-prefixes the id encoding with a single
/// byte, so [`TreeId::encode_into`] must emit **at most 255 bytes**.
/// `store::keys::encode` asserts this bound (a longer id is a programming
/// error: it cannot be represented, and truncating it would collide
/// keyspaces across accumulators).
///
/// A composite id — any `Copy` type with a fixed-size canonical encoding
/// plugs in:
///
/// ```
/// use accumulators::ids::TreeId;
///
/// /// Names one accumulator slot: (chain, contract, slot).
/// #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
/// struct ChainSlot {
///     chain_id: u64,
///     contract: [u8; 20],
///     slot: u64,
/// }
///
/// impl TreeId for ChainSlot {
///     fn encode_into(&self, out: &mut Vec<u8>) {
///         out.extend_from_slice(&self.chain_id.to_be_bytes());
///         out.extend_from_slice(&self.contract);
///         out.extend_from_slice(&self.slot.to_be_bytes());
///     }
///
///     fn from_bytes(bytes: &[u8]) -> Option<Self> {
///         let (chain, rest) = bytes.split_first_chunk::<8>()?;
///         let (contract, rest) = rest.split_first_chunk::<20>()?;
///         let slot = rest.first_chunk::<8>()?;
///         Some(Self {
///             chain_id: u64::from_be_bytes(*chain),
///             contract: *contract,
///             slot: u64::from_be_bytes(*slot),
///         })
///     }
/// }
///
/// let id = ChainSlot { chain_id: 1, contract: [7; 20], slot: 42 };
/// let mut encoded = Vec::new();
/// id.encode_into(&mut encoded);
/// assert_eq!(ChainSlot::from_bytes(&encoded), Some(id));
/// ```
pub trait TreeId: Copy + Eq + Ord + core::hash::Hash + core::fmt::Debug {
    /// Appends the canonical byte encoding to `out` (the store-key form).
    /// Must produce at most 255 bytes — see the trait-level bound.
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
        let mut out = [0; 16];
        hex::decode_into(s, &mut out)?;
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

impl From<crate::primitives::hex::DecodeError> for AccumulatorIdParseError {
    fn from(error: crate::primitives::hex::DecodeError) -> Self {
        match error {
            crate::primitives::hex::DecodeError::WrongLength(len) => Self::WrongLength(len),
            crate::primitives::hex::DecodeError::BadHex => Self::BadHex,
        }
    }
}

impl TreeId for AccumulatorId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let array: [u8; 16] = bytes.try_into().ok()?;
        Some(Self(array))
    }
}
