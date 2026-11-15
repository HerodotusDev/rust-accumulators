//! Hasher abstraction: infallible node hashing, fallible leaf ingestion,
//! flexible output size.
//!
//! The [`Hasher`](crate::hashers::Hasher) trait separates two input classes:
//!
//! - **node hashes** — already-validated values by construction; [`Hasher::hash_pair`](crate::hashers::Hasher::hash_pair)
//!   is infallible and allocation-free,
//! - **raw elements** — untrusted bytes from the user; [`Hasher::hash_leaf`](crate::hashers::Hasher::hash_leaf) is the
//!   single fallible entry point where parse/size validation happens.
//!
//! The trait's only combining method is [`Hasher::hash_pair`](crate::hashers::Hasher::hash_pair): the MMR only
//! ever combines pairs (merges are pairs; peak bagging folds right-to-left
//! as pairs), so there is no N-input hashing method and no arity error to
//! handle.
//!
//! Output size is flexible via [`Hasher::Output`](crate::hashers::Hasher::Output): the byte hashers produce
//! [`Hash`](crate::primitives::Hash) (32 bytes) and the Starknet field hashers
//! produce [`Felt`](https://docs.rs/starknet-crypto/latest/starknet_crypto/struct.Felt.html) — any `Copy` type implementing
//! [`HashValue`](crate::primitives::HashValue) is first-class, inferred
//! everywhere, and monomorphized away.
//!
//! # Second-preimage posture
//!
//! Leaves and node pairs are two *structural* input classes, but the hashers
//! do not prefix inputs to distinguish them (no `0x00`-leaf / `0x01`-pair
//! domain separation). For a fixed-size byte hasher like Keccak-256, a
//! 64-byte leaf element is byte-identical to a node-pair input — so
//! `hash_leaf(x) = hash_pair(a, b)` is possible for a crafted element. This
//! is pinned, not accidental: output conventions are anchored by golden
//! tests and shared across every verifier of a deployed accumulator, and
//! adding domain separation would change every hash output — a breaking
//! change. The ambiguity is bounded in practice:
//!
//! - leaf bytes are **never stored** — the tree persists only
//!   `hash_leaf(element)` outputs, so raw leaf material never re-enters
//!   hashing as node data;
//! - elements enter hashing only through the fallible
//!   [`Hasher::hash_leaf`](crate::hashers::Hasher::hash_leaf) entry point,
//!   where per-hasher validation applies.
//!
//! Applications whose elements can be attacker-sized around the pair-input
//! shape (exactly 2·[`HashValue::LEN`](crate::primitives::HashValue::LEN)
//! bytes for fixed-size byte hashers) should pre-hash or length-prefix
//! elements at the application layer.

use crate::primitives::HashValue;
use alloc::borrow::Cow;
#[cfg(any(feature = "mmr", feature = "merkle_tree"))]
use alloc::string::ToString;
use core::fmt;

/// The shared genesis seed of the `keccak_sol`, `pedersen_stark`, and
/// `poseidon_stark` hashers.
/// Each hasher hashes it through its own leaf path, keeping the
/// `genesis == hash_leaf(seed)` invariant. The seed and the exact bytes
/// hashed are pinned: a deployed accumulator's empty root depends on them.
#[cfg(any(
    feature = "keccak_sol",
    feature = "pedersen_stark",
    feature = "poseidon_stark"
))]
pub(crate) const GENESIS_SEED: &[u8] = b"brave new world";

#[cfg(feature = "blake2s_stark")]
mod blake2s_stark;
#[cfg(feature = "keccak_sol")]
mod keccak_sol;
#[cfg(feature = "pedersen_stark")]
mod pedersen_stark;
#[cfg(feature = "poseidon_stark")]
mod poseidon_stark;
#[cfg(any(feature = "pedersen_stark", feature = "poseidon_stark"))]
mod stark;

#[cfg(feature = "blake2s_stark")]
pub use blake2s_stark::Blake2sStarkHasher;
#[cfg(feature = "keccak_sol")]
pub use keccak_sol::KeccakSolHasher;
#[cfg(feature = "pedersen_stark")]
pub use pedersen_stark::PedersenStarkHasher;
#[cfg(feature = "poseidon_stark")]
pub use poseidon_stark::PoseidonStarkHasher;

/// Identity of a hasher implementation, for metadata and debugging.
///
/// Built-ins are a closed set; user hashers carry their own name. This is
/// *not* used to reconstruct hasher state — the configuration is serialized
/// next to it (see [`Hasher::config`]), so a reloaded accumulator always
/// restores the exact output-affecting parameters.
///
/// `#[non_exhaustive]`: users match on this for diagnostics; new built-ins
/// must not be a semver break.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[non_exhaustive]
pub enum HasherId {
    /// Solidity-flavored Keccak-256 (`keccak_sol`).
    KeccakSol,
    /// Starknet-flavored Poseidon (`poseidon_stark`).
    PoseidonStark,
    /// Starknet-flavored Pedersen (`pedersen_stark`).
    PedersenStark,
    /// Cairo/Starknet-flavored Blake2s (`blake2s_stark`).
    Blake2sStark,
    /// A user-provided hasher, identified by its declared name.
    Custom(&'static str),
}

impl HasherId {
    /// Wire tag used in the persisted `HasherInfo` record.
    #[cfg(any(feature = "mmr", feature = "merkle_tree"))]
    pub(crate) const fn tag(&self) -> u8 {
        match self {
            Self::KeccakSol => 0,
            Self::PoseidonStark => 1,
            Self::PedersenStark => 2,
            Self::Blake2sStark => 3,
            Self::Custom(_) => 4,
        }
    }

    /// Rebuilds from a wire tag and (for [`HasherId::Custom`]) the declared
    /// name. `None` for unknown tags and for tag 4 without a name.
    ///
    /// Every caller maps a `None` here to a malformed-record error — an
    /// unknown tag can never read as a default hasher.
    #[cfg(any(feature = "mmr", feature = "merkle_tree"))]
    pub(crate) fn from_tag(tag: u8, name: Option<&str>) -> Option<Self> {
        match (tag, name) {
            (0, _) => Some(Self::KeccakSol),
            (1, _) => Some(Self::PoseidonStark),
            (2, _) => Some(Self::PedersenStark),
            (3, _) => Some(Self::Blake2sStark),
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
            Self::KeccakSol => f.write_str("keccak_sol"),
            Self::PoseidonStark => f.write_str("poseidon_stark"),
            Self::PedersenStark => f.write_str("pedersen_stark"),
            Self::Blake2sStark => f.write_str("blake2s_stark"),
            Self::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// A hash function usable by accumulators.
///
/// Implement this to plug in a custom hasher. Checklist for an
/// implementation:
///
/// - `Output`: deterministic and [`HashValue`]-encodable.
/// - `hash_pair`: a proper combining function — collision-resistant and
///   order-sensitive.
/// - `hash_leaf`: the single point where untrusted input is ingested;
///   validate there, never substitute a default on malformed input.
/// - `genesis`: the value an empty accumulator bags to. It is baked into
///   persisted roots, so it can never change after release.
/// - `id` / `config`: persisted next to the data; keep them stable, see the
///   method docs for the exact wire bounds.
///
/// A tiny custom hasher — 8-byte truncating digests, enough to drive a real
/// MMR (see the module-level second-preimage notes for why fixed-size byte
/// hashers carry a leaf/pair ambiguity; this toy hasher exists to show the
/// trait shape, not to be deployed):
///
/// ```
/// use accumulators::hashers::{Hasher, HasherError, HasherId};
/// use accumulators::primitives::HashValue;
/// use std::borrow::Cow;
///
/// /// Any `Copy` byte type works as an output — here, 8 bytes.
/// #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
/// struct TinyHash([u8; 8]);
///
/// impl HashValue for TinyHash {
///     const LEN: usize = 8;
///
///     fn from_u64(value: u64) -> Self {
///         Self(value.to_be_bytes())
///     }
///
///     fn write_bytes(&self, out: &mut [u8]) {
///         out.copy_from_slice(&self.0);
///     }
///
///     fn from_bytes(bytes: &[u8]) -> Option<Self> {
///         Some(Self(*bytes.first_chunk()?))
///     }
/// }
///
/// /// Bytewise XOR fold for pairs; keeps the first 8 leaf bytes as-is.
/// struct First8;
///
/// impl Hasher for First8 {
///     type Output = TinyHash;
///
///     fn id(&self) -> HasherId {
///         HasherId::Custom("first8")
///     }
///
///     fn config(&self) -> Cow<'static, str> {
///         Cow::Borrowed("")
///     }
///
///     fn hash_pair(&self, left: TinyHash, right: TinyHash) -> TinyHash {
///         let mut out = [0; 8];
///         for (o, (l, r)) in out.iter_mut().zip(left.0.iter().zip(&right.0)) {
///             *o = l ^ r;
///         }
///         TinyHash(out)
///     }
///
///     fn hash_leaf(&self, element: &[u8]) -> Result<TinyHash, HasherError> {
///         Ok(TinyHash(element.first_chunk::<8>().copied().unwrap_or([0; 8])))
///     }
///
///     fn genesis(&self) -> TinyHash {
///         TinyHash([0; 8])
///     }
/// }
///
/// let leaf = First8.hash_leaf(b"accumulator").unwrap();
/// assert_eq!(leaf.0, *b"accumula");
/// assert_eq!(First8.hash_pair(leaf, leaf).0, [0; 8]); // x ⊕ x = 0
/// assert_eq!(TinyHash::from_u64(1).0, 1_u64.to_be_bytes());
/// ```
///
/// The name passed to [`HasherId::Custom`] must be at most 255 bytes (it is
/// length-prefixed in the persisted metadata), and [`Hasher::config`] at
/// most 65535 — creation rejects longer values rather than truncating.
pub trait Hasher {
    /// The hash value this hasher produces — any [`HashValue`] type.
    /// Inferred everywhere; the byte hashers use
    /// [`Hash`](crate::primitives::Hash), the Starknet field hashers use
    /// [`Felt`](https://docs.rs/starknet-crypto/latest/starknet_crypto/struct.Felt.html).
    type Output: HashValue;

    /// Identifier for metadata.
    ///
    /// A [`HasherId::Custom`] name must be at most 255 bytes: it is
    /// length-prefixed with one byte in the persisted `HasherInfo` record,
    /// and creation rejects longer names rather than truncating them
    /// (truncation would brick every later open with a hasher mismatch).
    fn id(&self) -> HasherId;

    /// Canonical serialization of any configuration that affects output
    /// bytes (e.g. Blake truncation). Persisted alongside
    /// MMR metadata so a reloaded MMR cannot silently use a mismatched hasher.
    ///
    /// `Cow` so built-ins return borrowed literals while custom hashers with
    /// runtime-computed configurations return owned strings.
    ///
    /// The config text must be at most 65535 bytes: it is length-prefixed
    /// with two bytes in the persisted `HasherInfo` record, and creation
    /// rejects longer configs rather than truncating them (truncation would
    /// brick every later open with a hasher mismatch).
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
    ///
    /// Like every output convention, this is pinned once released: it is
    /// part of persisted roots, so changing it forks existing accumulators.
    fn genesis(&self) -> Self::Output;
}

/// Errors from leaf ingestion and hasher configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HasherError {
    /// Element size does not fit the hasher's constraints.
    ///
    /// The size is reported in both bytes and bits, so neither unit has to
    /// be derived.
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
