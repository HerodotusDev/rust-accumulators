//! Proof types: self-contained, standalone-verifiable, canonical multiproofs.
//!
//! v0.5 proofs carried peaks but `verify_proof` ignored them and re-read the
//! store — a proof only "verified" against whatever the verifier's store
//! happened to contain. Here a [`Proof`] is a complete commitment: element
//! hash, sibling path, peaks, root, and the node count it was created at.
//! [`verify_proof`] needs only the hasher — no store.
//!
//! [`MultiProof`] stores the sibling set **deduplicated** across the proven
//! leaves, with per-leaf reference lists into that set. For overlapping trees
//! (leaves sharing parents) this is strictly smaller than N separate proofs —
//! the v0.5 `get_proofs` returned `Vec<Proof>` with duplicated siblings.
//!
//! All types are generic over the hash output [`HashValue`], so proofs of any
//! hasher's output type are first-class.

use crate::design::hashers::Hasher;
use crate::design::hashers::HasherError;
use crate::design::primitives::{HashValue, LeafIndex, MmrSize};
use alloc::vec::Vec;

/// An inclusion proof for one leaf: a complete, standalone commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof<O: HashValue> {
    /// The proven leaf.
    pub leaf: LeafIndex,
    /// Hash of the leaf element (`hash_leaf(element)`), not the raw element.
    pub element_hash: O,
    /// Sibling hashes bottom-up, excluding the peak-level bagging sibling.
    pub siblings: Vec<O>,
    /// Peaks of the MMR at proof time (left to right) — the commitment the
    /// path terminates against.
    pub peaks: Vec<O>,
    /// The root at proof time: `root_from(bag(peaks), size)`.
    pub root: O,
    /// Node count at proof time. Root and peaks are only meaningful together
    /// with this.
    pub size: MmrSize,
}

/// A multi-leaf proof with a deduplicated sibling pool.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MultiProof<O: HashValue> {
    /// Proven leaves, ascending, same order as [`Self::element_hashes`].
    pub leaves: Vec<LeafIndex>,
    /// Leaf element hashes, aligned with [`Self::leaves`].
    pub element_hashes: Vec<O>,
    /// The deduplicated pool of all sibling hashes needed by every path.
    ///
    /// Ordering is canonical (discovery order during path construction) so
    /// proofs are byte-comparable.
    pub sibling_pool: Vec<O>,
    /// Per-leaf sibling references into [`Self::sibling_pool`], flattened
    /// bottom-up per leaf in [`Self::leaves`] order. Path length for leaf
    /// `i` is derivable from the leaf's peak height — no separate lengths
    /// field needed.
    pub sibling_refs: Vec<u32>,
    /// Peaks at proof time (see [`Proof::peaks`]).
    pub peaks: Vec<O>,
    /// Root at proof time (see [`Proof::root`]).
    pub root: O,
    /// Node count at proof time (see [`Proof::size`]).
    pub size: MmrSize,
}

/// Proof verification failures that are *not* structural mismatches.
///
/// A path that simply doesn't hash to the root is `Ok(false)` — a negative
/// result, not an error. Errors here mean "cannot attempt verification".
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// Proof was built for an MMR of a different shape than its own peaks.
    #[error("proof is internally inconsistent: {0}")]
    Inconsistent(#[source] ProofInconsistency),

    /// Hasher rejected an input while re-deriving hashes.
    #[error("hasher rejected proof data")]
    Hasher(#[from] HasherError),
}

/// Ways a proof can be structurally invalid before any hashing.
///
/// Exhaustive over the structural contract of [`Proof`] and [`MultiProof`]:
/// verification re-derives every conclusion and never trusts the proof's own
/// claims, so a fabricated proof can at worst produce `Ok(false)` — never a
/// panic and never a false `Ok(true)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ProofInconsistency {
    /// Sibling count does not match the path length implied by leaf + size.
    #[error("sibling count {siblings} does not match expected path length {expected}")]
    PathLengthMismatch {
        /// Actual sibling count.
        siblings: usize,
        /// Expected path length.
        expected: usize,
    },
    /// Peaks do not correspond to the recorded node count.
    #[error("peaks do not match node count {size}")]
    PeaksMismatch {
        /// Recorded node count.
        size: MmrSize,
    },
    /// Leaf index is not below the recorded leaf count implied by the size.
    #[error("leaf {leaf} is out of range for size {size}")]
    LeafOutOfRange {
        /// The out-of-range leaf.
        leaf: LeafIndex,
        /// Recorded node count.
        size: MmrSize,
    },
    /// A multiproof's per-leaf sibling reference points past the sibling
    /// pool (would otherwise be an unchecked slice — a panic class).
    #[error("sibling reference {index} is out of bounds for pool of {pool_len}")]
    RefOutOfBounds {
        /// The out-of-bounds reference.
        index: u32,
        /// The sibling pool length.
        pool_len: usize,
    },
    /// A multiproof lists the same leaf twice.
    #[error("leaf {leaf} appears more than once in the multiproof")]
    DuplicateLeaf {
        /// The duplicated leaf.
        leaf: LeafIndex,
    },
    /// A multiproof's leaves are not ascending (the canonical order
    /// [`MultiProof::leaves`] documents).
    #[error("multiproof leaves must be ascending: {first} then {second}")]
    UnsortedLeaves {
        /// The earlier, larger leaf.
        first: LeafIndex,
        /// The later, smaller leaf.
        second: LeafIndex,
    },
    /// The supplied element set does not align with the proof's leaves.
    #[error("{leaves} proven leaves but {elements} elements supplied")]
    ElementCountMismatch {
        /// Number of leaves in the proof.
        leaves: usize,
        /// Number of elements supplied for verification.
        elements: usize,
    },
}

/// Verifies a proof against its own commitment — no store involved.
///
/// Recomputes the leaf hash, walks the sibling path, bags the proof's peaks,
/// and compares to the proof's root. `Ok(false)` means the proof is validly
/// structured but does not commit to `element`.
///
/// # Errors
///
/// Structural inconsistency (see [`VerifyError`]) or hasher failure.
pub fn verify_proof<H: Hasher>(
    hasher: &H,
    proof: &Proof<H::Output>,
    element: &[u8],
) -> Result<bool, VerifyError> {
    let _ = (hasher, proof, element);
    todo!()
}

/// Verifies a multiproof against its own commitment.
///
/// `elements` must align positionally with the proof's leaves (checked
/// structurally — [`ProofInconsistency::ElementCountMismatch`]).
///
/// # Errors
///
/// Structural inconsistency or hasher failure (see [`verify_proof`]).
pub fn verify_multi_proof<I, H>(
    hasher: &H,
    proof: &MultiProof<H::Output>,
    elements: I,
) -> Result<bool, VerifyError>
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
    H: Hasher,
{
    let _ = (hasher, proof, elements);
    todo!()
}

/// Wire encodings for foreign verifiers (Solidity, cairo, …) — and the
/// extension point for user-defined ones.
///
/// The core proof is binary; encoding is an explicit, separate step,
/// replacing the v0.5 `FormattingOptions` that was woven through every proof
/// call. The built-in [`FixedWidth`](encoding::FixedWidth) implements v0.5's extracted semantics —
/// pad-to-fixed-length lists with a null placeholder, per-list output sizes,
/// error when a list exceeds its output size (`FormattingError` became
/// [`EncodingError::ListTooLong`](encoding::EncodingError::ListTooLong)) — and its presets capture what v0.5's
/// options were preparing for: Solidity fixed-size word arrays and cairo
/// felt widths. Anything else (ABI structs, calldata, JSON, felt252 arrays)
/// is one user [`ProofEncoding`](encoding::ProofEncoding) implementation away — the trait is the
/// extension point, the presets are just its first implementor.
pub mod encoding {
    use crate::design::primitives::HashValue;
    use alloc::{string::String, vec::Vec};

    /// The extension point: turn a proof into any wire format.
    ///
    /// Implement this for your own encoder — on-chain calldata, a JSON
    /// payload, a felt252 array, whatever the verifier consumes. Fallible
    /// because fixed-size targets can reject overlong input (v0.5 behavior,
    /// preserved in [`EncodingError`]).
    pub trait ProofEncoding {
        /// Wire representation of a single-leaf proof.
        type EncodedProof;
        /// Wire representation of a multi-leaf proof.
        type EncodedMultiProof;
        /// Encoding failures.
        type Error: core::error::Error + Send + Sync + 'static;

        /// Encodes a single-leaf proof.
        ///
        /// # Errors
        ///
        /// Per [`Self::Error`] — e.g. a list longer than a fixed output
        /// size.
        fn encode<O: HashValue>(
            &self,
            proof: &super::Proof<O>,
        ) -> Result<Self::EncodedProof, Self::Error>;

        /// Encodes a multi-leaf proof.
        ///
        /// # Errors
        ///
        /// Per [`Self::Error`].
        fn encode_multi<O: HashValue>(
            &self,
            proof: &super::MultiProof<O>,
        ) -> Result<Self::EncodedMultiProof, Self::Error>;
    }

    /// The built-in fixed-width encoding — v0.5's `FormattingOptions`
    /// semantics, extracted and made explicit.
    ///
    /// Hashes render as lowercase hex of the canonical [`HashValue`] bytes,
    /// zero-padded to [`Self::hash_width`] (minimal width when `None`). The
    /// node count renders zero-padded to [`Self::size_width`]. When a list
    /// output size is set, the list is null-padded — with the **zero hash**
    /// (all-zero canonical bytes: `bytes32(0)`, felt `0`), replacing v0.5's
    /// arbitrary `null_value` string — or errors when longer, exactly like
    /// v0.5's `format_peaks` / `format_proof`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct FixedWidth {
        /// Zero-pad hash strings to this width (`None` = minimal hex).
        pub hash_width: Option<usize>,
        /// Zero-pad the node-count / index strings to this width (`None` =
        /// minimal decimal).
        pub size_width: Option<usize>,
        /// Null-pad the peaks list to this length (`None` = as-is).
        pub peaks_size: Option<usize>,
        /// Null-pad the sibling list to this length (`None` = as-is).
        pub siblings_size: Option<usize>,
    }

    impl FixedWidth {
        /// Solidity-verifier preset: fixed-width 32-byte words, peaks and
        /// siblings null-padded to the verifier's expected array sizes.
        #[must_use]
        pub const fn solidity() -> Self {
            todo!()
        }

        /// Cairo-verifier preset: felt-compatible widths matching the v0.5
        /// stark-hasher output formatting.
        #[must_use]
        pub const fn cairo() -> Self {
            todo!()
        }
    }

    /// Fixed-width encoding failures — v0.5's `FormattingError`, made
    /// informative.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
    #[non_exhaustive]
    pub enum EncodingError {
        /// A list is longer than the requested fixed output size.
        #[error("list has {len} entries, exceeding the fixed output size {output_size}")]
        ListTooLong {
            /// Actual list length.
            len: usize,
            /// The requested fixed output size.
            output_size: usize,
        },
    }

    /// The [`FixedWidth`] wire representation of a [`Proof`](super::Proof).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EncodedProof {
        /// Sibling hashes, bottom-up, null-padded per `siblings_size`.
        pub siblings: Vec<String>,
        /// Peak hashes, left to right, null-padded per `peaks_size`.
        pub peaks: Vec<String>,
        /// The node count at proof time, rendered per `size_width`.
        pub size: String,
        /// The proven leaf index, rendered per `size_width`.
        pub leaf: String,
        /// The leaf element hash.
        pub element_hash: String,
        /// The root the proof commits to.
        pub root: String,
    }

    /// The [`FixedWidth`] wire representation of a
    /// [`MultiProof`](super::MultiProof).
    ///
    /// Structural integers (sibling references) stay numeric — they are
    /// indexes into `sibling_pool`, not hash data; consumers render them in
    /// their target's native integer form.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct EncodedMultiProof {
        /// Deduplicated sibling pool, canonical order, per `hash_width`.
        pub sibling_pool: Vec<String>,
        /// Per-leaf references into `sibling_pool`, flattened, per-leaf
        /// bottom-up in `leaves` order (the [`super::MultiProof`] contract).
        pub sibling_refs: Vec<u32>,
        /// Peak hashes, left to right, per `hash_width`.
        pub peaks: Vec<String>,
        /// The node count at proof time, rendered per `size_width`.
        pub size: String,
        /// Proven leaf indexes, ascending, rendered per `size_width`.
        pub leaves: Vec<String>,
        /// Leaf element hashes, aligned with `leaves`.
        pub element_hashes: Vec<String>,
        /// The root the proof commits to.
        pub root: String,
    }
}
