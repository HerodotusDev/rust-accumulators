//! Hasher abstraction: infallible node hashing, fallible leaf ingestion,
//! flexible output size.
//!
//! The v0.5 `Hasher` trait takes `Vec<String>` of hex and returns hex. Every
//! call allocates, every element is re-validated, and malformed input is
//! silently hashed as zero (Poseidon `unwrap_or_default`). The redesigned
//! trait separates the two input classes:
//!
//! - **node hashes** — already-validated values by construction; `hash_pair`
//!   is infallible and allocation-free,
//! - **raw elements** — untrusted bytes from the user; `hash_leaf` is the
//!   single fallible entry point where parse/size validation happens.
//!
//! Arity is a solved problem: the MMR only ever combines **pairs** (merges
//! are pairs; peak bagging folds right-to-left as pairs), so the trait's
//! only combining method is [`Hasher::hash_pair`](crate::design::hashers::Hasher::hash_pair) — total for every built-in.
//! The whole v0.5 arity-error class (`InvalidArity`) is deleted instead of
//! documented. Keccak's flat-concatenation N-hashing remains reachable for
//! users who want it; nothing internal depends on it.
//!
//! Output size is flexible via [`Hasher::Output`](crate::design::hashers::Hasher): built-ins produce
//! [`Hash`](crate::design::primitives::Hash) (32 bytes), but any `Copy` type
//! implementing [`HashValue`](crate::design::primitives::HashValue) — 16-byte
//! truncations, 64-byte digests, field-element wrappers — is first-class,
//! inferred everywhere, and monomorphized away.

use crate::design::primitives::HashValue;
use alloc::borrow::Cow;

/// Identity of a hasher implementation, for metadata and debugging.
///
/// Built-ins are a closed set; user hashers carry their own name. This is
/// *not* used to reconstruct hasher state — configuration is serialized next
/// to it (see [`Hasher::config`]), fixing the bug where `should_pad` /
/// `truncate` flags were lost in metadata.
///
/// `#[non_exhaustive]`: users match on this for diagnostics; new built-ins
/// must not be a semver break.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum HasherId {
    /// Solidity-compatible Keccak-256.
    Keccak256,
    /// Starknet Poseidon.
    Poseidon,
    /// Starknet Pedersen.
    Pedersen,
    /// Cairo-flavored Blake2s.
    Blake2s,
    /// A user-provided hasher, identified by its declared name.
    Custom(&'static str),
}

/// A hash function usable by accumulators.
///
/// Implement this to plug in a custom hasher. Requirements on the output:
/// deterministic, [`HashValue`]-encodable, and `hash_pair` must be a proper
/// combining function (collision-resistant, order-sensitive).
pub trait Hasher {
    /// The hash value this hasher produces — any [`HashValue`] type.
    /// Inferred everywhere; the built-ins use
    /// [`Hash`](crate::design::primitives::Hash).
    type Output: HashValue;

    /// Identifier for metadata.
    fn id(&self) -> HasherId;

    /// Canonical serialization of any configuration that affects output
    /// bytes (e.g. Poseidon padding, Blake truncation). Persisted alongside
    /// MMR metadata so a reloaded MMR cannot silently use a mismatched hasher.
    ///
    /// `Cow` so built-ins return borrowed literals while custom hashers with
    /// runtime-computed configurations return owned strings.
    fn config(&self) -> Cow<'static, str>;

    /// Combines two node hashes. Infallible by contract: inputs are
    /// validated hashes. Order-sensitive: `hash_pair(a, b)` need not equal
    /// `hash_pair(b, a)`.
    fn hash_pair(&self, left: Self::Output, right: Self::Output) -> Self::Output;

    /// Hashes a raw leaf element. The single point where untrusted input is
    /// ingested, hence fallible.
    ///
    /// # Errors
    ///
    /// When the element is malformed for this hasher: wrong size, unparseable
    /// as a field element, non-multiple-of-4 bytes for Blake, etc. Never
    /// silently substitutes a default value.
    fn hash_leaf(&self, element: &[u8]) -> Result<Self::Output, HasherError>;

    /// The genesis hash — the value all counters/roots derive from in an
    /// empty accumulator.
    fn genesis(&self) -> Self::Output;
}

/// Errors from leaf ingestion and hasher configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HasherError {
    /// Element size does not fit the hasher's block/field constraints.
    ///
    /// Both units are carried and rendered — no mental conversion required.
    #[error(
        "element size {element_size} bytes exceeds the hasher limit \
         ({block_size_bytes} bytes / {block_size_bits} bits)"
    )]
    InvalidElementSize {
        /// Size of the rejected element in bytes.
        element_size: usize,
        /// The hasher's limit in bytes.
        block_size_bytes: usize,
        /// The hasher's limit in bits.
        block_size_bits: usize,
    },

    /// Element is not a valid field element for this hasher.
    #[error("element is not a valid field element")]
    InvalidFieldElement,

    /// A user hasher's own error, opaque to the crate.
    #[error(transparent)]
    Custom(#[from] alloc::boxed::Box<dyn core::error::Error + Send + Sync>),
}

/// Solidity-compatible Keccak-256 hasher.
///
/// `hash_pair`: keccak over the concatenation of the two 32-byte values (the
/// "solidity packing" convention, matching the v0.5 behavior and its golden
/// tests).
///
/// The type alias [`SolKeccak`] exists so call sites can spell the intent
/// explicitly.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keccak256Hasher;

/// Explicit alias — same hasher, named for the Solidity convention it models.
pub type SolKeccak = Keccak256Hasher;

/// Starknet Poseidon hasher.
///
/// `hash_pair` maps to `poseidon_hash`. The padding flag affects output
/// *formatting width* and must round-trip through [`Hasher::config`].
#[derive(Clone, Copy, Debug, Default)]
pub struct PoseidonHasher {
    /// Whether outputs are zero-padded to the full felt width.
    pub pad: bool,
}

/// Starknet Pedersen hasher.
///
/// `hash_pair` maps to the 2-input Pedersen permutation — its only arity, so
/// the v0.5 `hash_single` quirk (hashing `[data, ""]`, a digest no other
/// hasher agreed with) disappears: single-element hashing is
/// [`Hasher::hash_leaf`]'s job.
#[derive(Clone, Copy, Debug, Default)]
pub struct PedersenHasher;

/// Cairo-flavored Blake2s hasher (word-reversed, optional 252-bit truncation).
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake2sHasher {
    /// Whether to zero the top 4 bits for a 252-bit output.
    pub truncate: bool,
}
