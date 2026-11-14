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
//! only combining method is [`Hasher::hash_pair`](crate::hashers::Hasher::hash_pair) — total for every built-in.
//! The whole v0.5 arity-error class (`InvalidArity`) is deleted instead of
//! documented. Keccak's flat-concatenation N-hashing remains reachable for
//! users who want it; nothing internal depends on it.
//!
//! Output size is flexible via [`Hasher::Output`](crate::hashers::Hasher::Output): the byte hashers produce
//! [`Hash`](crate::primitives::Hash) (32 bytes) and the Starknet field hashers
//! produce [`Felt`](https://docs.rs/starknet-crypto/latest/starknet_crypto/struct.Felt.html) — any `Copy` type implementing
//! [`HashValue`](crate::primitives::HashValue) is first-class, inferred
//! everywhere, and monomorphized away.

use crate::primitives::HashValue;
use alloc::borrow::Cow;
#[cfg(any(feature = "mmr", feature = "merkle_tree"))]
use alloc::string::ToString;
use core::fmt;

#[cfg(feature = "blake")]
mod blake2s;
#[cfg(feature = "keccak")]
mod keccak;
#[cfg(any(feature = "pedersen", feature = "poseidon"))]
mod stark;
#[cfg(feature = "pedersen")]
mod stark_pedersen;
#[cfg(feature = "poseidon")]
mod stark_poseidon;

#[cfg(feature = "blake")]
pub use blake2s::Blake2sHasher;
#[cfg(feature = "keccak")]
pub use keccak::{Keccak256Hasher, SolKeccak};
#[cfg(feature = "pedersen")]
pub use stark_pedersen::PedersenHasher;
#[cfg(feature = "poseidon")]
pub use stark_poseidon::PoseidonHasher;

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

impl HasherId {
    /// Wire tag used in the persisted `HasherInfo` record.
    #[cfg(any(feature = "mmr", feature = "merkle_tree"))]
    pub(crate) const fn tag(&self) -> u8 {
        match self {
            Self::Keccak256 => 0,
            Self::Poseidon => 1,
            Self::Pedersen => 2,
            Self::Blake2s => 3,
            Self::Custom(_) => 4,
        }
    }

    /// Rebuilds from a wire tag and (for [`HasherId::Custom`]) the declared
    /// name. `None` for unknown tags.
    #[cfg(any(feature = "mmr", feature = "merkle_tree"))]
    pub(crate) fn from_tag(tag: u8, name: Option<&str>) -> Option<Self> {
        match (tag, name) {
            (0, _) => Some(Self::Keccak256),
            (1, _) => Some(Self::Poseidon),
            (2, _) => Some(Self::Pedersen),
            (3, _) => Some(Self::Blake2s),
            (4, Some(name)) => Some(Self::Custom(
                // The name was `&'static str` when persisted; leaking it back
                // is the price of a zero-alloc id. Custom hasher names are
                // static in practice (see [`Hasher::id`]).
                alloc::boxed::Box::leak(name.to_string().into_boxed_str()),
            )),
            _ => None,
        }
    }
}

impl fmt::Display for HasherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Keccak256 => f.write_str("keccak256"),
            Self::Poseidon => f.write_str("poseidon"),
            Self::Pedersen => f.write_str("pedersen"),
            Self::Blake2s => f.write_str("blake2s"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// A hash function usable by accumulators.
///
/// Implement this to plug in a custom hasher. Requirements on the output:
/// deterministic, [`HashValue`]-encodable, and `hash_pair` must be a proper
/// combining function (collision-resistant, order-sensitive).
pub trait Hasher {
    /// The hash value this hasher produces — any [`HashValue`] type.
    /// Inferred everywhere; the byte hashers use
    /// [`Hash`](crate::primitives::Hash), the Starknet field hashers use
    /// [`Felt`](https://docs.rs/starknet-crypto/latest/starknet_crypto/struct.Felt.html).
    type Output: HashValue;

    /// Identifier for metadata.
    fn id(&self) -> HasherId;

    /// Canonical serialization of any configuration that affects output
    /// bytes (e.g. Blake truncation). Persisted alongside
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
    /// When the element is malformed for this hasher: wrong size, not a
    /// valid field element, non-multiple-of-4 bytes for Blake, etc. Never
    /// silently substitutes a default value.
    fn hash_leaf(&self, element: &[u8]) -> Result<Self::Output, HasherError>;

    /// The genesis hash — the value an empty accumulator bags to, and the
    /// hash all counters/roots derive from in an empty accumulator.
    fn genesis(&self) -> Self::Output;
}

/// Errors from leaf ingestion and hasher configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HasherError {
    /// Element size does not fit the hasher's constraints.
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

    /// Element length is not a multiple of the hasher's word alignment
    /// (Blake2s hashes whole 4-byte words).
    #[error(
        "element size {element_size} bytes is not a multiple of the hasher's {alignment} byte word"
    )]
    InvalidElementAlignment {
        /// Size of the rejected element in bytes.
        element_size: usize,
        /// The hasher's word alignment in bytes.
        alignment: usize,
    },

    /// A user hasher's own error, opaque to the crate.
    #[error(transparent)]
    Custom(#[from] alloc::boxed::Box<dyn core::error::Error + Send + Sync>),
}
