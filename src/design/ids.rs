//! MMR identifiers: flexible, feature-extensible, collision-proof in keys.
//!
//! The default id is [`MmrId`] — 16 bytes, which uuid v4, uuid v7 and ulid
//! all serialize into with zero heap use. Accumulators are generic over
//! [`TreeId`], so any `Copy` id type (32-byte digests, semantic composites
//! like `(chain_id, contract, slot)`, …) plugs in by implementing one
//! method; the common case just infers `MmrId` everywhere.
//!
//! Store keys are length-prefixed binary (`[id_len][id bytes][table tag]
//! [index]`), so ids of any length and content are safe — no delimiter can
//! collide (fixing the v0.5 bug where an `mmr_id` containing `:` corrupted
//! key parsing).
//!
//! Feature flags:
//! - `uuid_v7` — `now_v7` (time-ordered, index-friendly; enables `uuid/v7`),
//! - `ulid` — `from_ulid` / `generate_ulid`.
//!
//! (`random_v4` is available whenever the `uuid` dependency is — currently
//! always; it becomes its own `uuid_v4` feature at the 1.0.0-rc.1 swap.)

use alloc::vec::Vec;

/// An accumulator identifier usable in store keys.
///
/// Implement this for your own id type and pass it wherever an id is
/// required; [`MmrId`] is the built-in default.
pub trait TreeId: Copy + Eq + Ord + core::hash::Hash + core::fmt::Debug {
    /// Appends the canonical byte encoding to `out` (the store-key form).
    /// Any length works — the key layout length-prefixes id bytes.
    fn encode_into(&self, out: &mut Vec<u8>);
}

/// A 128-bit accumulator identifier — the default [`TreeId`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MmrId([u8; 16]);

impl MmrId {
    /// The all-zero id. Valid for tests and ephemeral use; production code
    /// should prefer a generated id so distinct MMRs sharing a store cannot
    /// collide.
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

impl From<[u8; 16]> for MmrId {
    fn from(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }
}

impl From<MmrId> for [u8; 16] {
    fn from(id: MmrId) -> Self {
        id.0
    }
}

impl AsRef<[u8]> for MmrId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl MmrId {
    /// Random uuid v4 (gated on the `uuid` dependency being enabled —
    /// currently always present for the v0.5 modules).
    #[must_use]
    pub fn random_v4() -> Self {
        todo!()
    }

    /// Time-ordered uuid v7 — ids sort by creation time, which keeps
    /// key-value stores' write amplification low. Requires the `uuid_v7`
    /// feature (enables `uuid/v7`).
    #[cfg(feature = "uuid_v7")]
    #[must_use]
    pub fn now_v7() -> Self {
        todo!()
    }

    /// Wraps an existing ulid.
    #[cfg(feature = "ulid")]
    #[must_use]
    pub const fn from_ulid(ulid: ulid::Ulid) -> Self {
        let _ = ulid;
        todo!()
    }

    /// Generates a new monotonic ulid.
    #[cfg(feature = "ulid")]
    #[must_use]
    pub fn generate_ulid() -> Self {
        todo!()
    }
}

impl core::fmt::Debug for MmrId {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

impl core::fmt::Display for MmrId {
    fn fmt(&self, _f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        todo!()
    }
}

impl core::str::FromStr for MmrId {
    type Err = MmrIdParseError;

    fn from_str(_s: &str) -> Result<Self, Self::Err> {
        todo!()
    }
}

/// Failed to parse an [`MmrId`] from text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmrIdParseError;

impl core::fmt::Display for MmrIdParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "invalid mmr id")
    }
}

impl core::error::Error for MmrIdParseError {}

impl TreeId for MmrId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}
