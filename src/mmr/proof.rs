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

use super::layout::{
    LeafCount, MmrSize, NodeIndex, PathStep, Side, bag_peaks, peaks_of, root_from, sibling_path,
};
use crate::hashers::{Hasher, HasherError};
use crate::primitives::{HashValue, LeafIndex};
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

/// Builds the deduplicated sibling pool for `paths` and the flattened
/// per-leaf reference list into it, in first-discovery order (so proofs are
/// byte-comparable). Returns `(pool_indexes, pool_refs)`.
#[expect(
    clippy::cast_possible_truncation,
    reason = "sibling pool indexes are bounded by u32 in the wire contract; a pool beyond it could not be addressed by any proof"
)]
pub(crate) fn build_sibling_pool(paths: &[Vec<PathStep>]) -> (Vec<NodeIndex>, Vec<u32>) {
    let mut pool_indexes: Vec<NodeIndex> = Vec::new();
    let mut pool_refs: Vec<u32> = Vec::new();
    for path in paths {
        for step in path {
            if let Some(position) = pool_indexes.iter().position(|n| *n == step.sibling) {
                pool_refs.push(position as u32);
            } else {
                pool_refs.push(pool_indexes.len() as u32);
                pool_indexes.push(step.sibling);
            }
        }
    }
    (pool_indexes, pool_refs)
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

/// Validates the shared structural contract of a self-contained commitment:
/// well-formed size, leaf in range, peaks matching the size. Returns the
/// leaf count of the recorded size.
fn check_commitment<O: HashValue>(
    leaf: LeafIndex,
    size: MmrSize,
    peaks: &[O],
) -> Result<LeafCount, ProofInconsistency> {
    let Some(leaf_count) = size.leaf_count() else {
        return Err(ProofInconsistency::PeaksMismatch { size });
    };
    if leaf.get() >= leaf_count.get() {
        return Err(ProofInconsistency::LeafOutOfRange { leaf, size });
    }
    // Peak count of a well-formed MMR is popcount(leaf count).
    if peaks.len() != leaf_count.get().count_ones() as usize {
        return Err(ProofInconsistency::PeaksMismatch { size });
    }
    Ok(leaf_count)
}

/// Validates a multiproof's structural contract: well-formed size, peaks
/// matching it, leaves ascending, unique, and in range.
fn check_multi_shape<O: HashValue>(proof: &MultiProof<O>) -> Result<(), VerifyError> {
    let Some(leaf_count) = proof.size.leaf_count() else {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::PeaksMismatch { size: proof.size },
        ));
    };
    if proof.peaks.len() != leaf_count.get().count_ones() as usize {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::PeaksMismatch { size: proof.size },
        ));
    }
    for pair in proof.leaves.windows(2) {
        if pair[0] == pair[1] {
            return Err(VerifyError::Inconsistent(
                ProofInconsistency::DuplicateLeaf { leaf: pair[0] },
            ));
        }
        if pair[0] > pair[1] {
            return Err(VerifyError::Inconsistent(
                ProofInconsistency::UnsortedLeaves {
                    first: pair[0],
                    second: pair[1],
                },
            ));
        }
    }
    for &leaf in &proof.leaves {
        if leaf.get() >= leaf_count.get() {
            return Err(VerifyError::Inconsistent(
                ProofInconsistency::LeafOutOfRange {
                    leaf,
                    size: proof.size,
                },
            ));
        }
    }
    Ok(())
}

/// Locates the index of the peak that contains `leaf`'s subtree, plus that
/// peak's height. Walks up beside the path until the node lands on a peak.
fn peak_position(leaf: LeafIndex, size: MmrSize) -> Option<(usize, u8)> {
    let peaks = peaks_of(size);
    let mut leaf_index = leaf.get();
    let mut node = leaf.node().get();
    let mut height = 0_u32;

    loop {
        if let Some((index, _)) = peaks
            .iter()
            .enumerate()
            .find(|(_, peak)| peak.get() == node)
        {
            // Heights are bounded by the MMR's node width (<= 63 levels for
            // u64 node indexes), far below `u8::MAX`.
            return Some((index, u8::try_from(height).ok()?));
        }
        if node > size.get() {
            return None;
        }
        let offset = (1_u64 << (height + 1)) - 1;
        if leaf_index % 2 == 1 {
            node += 1;
        } else {
            node += offset + 1;
        }
        leaf_index /= 2;
        height += 1;
    }
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
    check_commitment(proof.leaf, proof.size, &proof.peaks).map_err(VerifyError::Inconsistent)?;

    let path = sibling_path(proof.leaf, proof.size);
    if path.len() != proof.siblings.len() {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::PathLengthMismatch {
                siblings: proof.siblings.len(),
                expected: path.len(),
            },
        ));
    }

    let leaf_hash = hasher.hash_leaf(element)?;
    if leaf_hash != proof.element_hash {
        return Ok(false);
    }

    // Fold the path; each step's side is re-derived from the layout, never
    // trusted from the proof.
    let mut hash = leaf_hash;
    for (step, sibling) in path.iter().zip(&proof.siblings) {
        hash = match step.side {
            Side::Left => hasher.hash_pair(*sibling, hash),
            Side::Right => hasher.hash_pair(hash, *sibling),
        };
    }

    // The path must terminate exactly at the leaf's peak...
    let Some((peak_index, _)) = peak_position(proof.leaf, proof.size) else {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::PeaksMismatch { size: proof.size },
        ));
    };
    if hash != proof.peaks[peak_index] {
        return Ok(false);
    }

    // ...and the peaks must bag to the committed root.
    let recomputed = root_from(hasher, bag_peaks(hasher, &proof.peaks), proof.size);
    Ok(recomputed == proof.root)
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
    let element_hashes: Vec<H::Output> = elements
        .into_iter()
        .map(|e| hasher.hash_leaf(e.as_ref()))
        .collect::<Result<_, _>>()?;

    if element_hashes.len() != proof.leaves.len() {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::ElementCountMismatch {
                leaves: proof.leaves.len(),
                elements: element_hashes.len(),
            },
        ));
    }

    // Structural contract: well-formed size, peaks matching it, leaves
    // ascending, unique, and in range.
    check_multi_shape(proof)?;

    // Replay every path from the pool via the flattened refs.
    let mut refs = proof.sibling_refs.iter().copied();
    let mut refs_consumed = 0_usize;
    for (leaf, (element_hash, claimed_hash)) in proof
        .leaves
        .iter()
        .zip(element_hashes.iter().zip(&proof.element_hashes))
    {
        // The commitment must name the element being verified.
        if element_hash != claimed_hash {
            return Ok(false);
        }

        let path = sibling_path(*leaf, proof.size);
        let mut hash = *element_hash;
        for step in &path {
            let Some(sibling_ref) = refs.next() else {
                return Err(VerifyError::Inconsistent(
                    ProofInconsistency::RefOutOfBounds {
                        index: 0,
                        pool_len: proof.sibling_pool.len(),
                    },
                ));
            };
            refs_consumed += 1;
            let Some(sibling) = proof.sibling_pool.get(sibling_ref as usize) else {
                return Err(VerifyError::Inconsistent(
                    ProofInconsistency::RefOutOfBounds {
                        index: sibling_ref,
                        pool_len: proof.sibling_pool.len(),
                    },
                ));
            };
            hash = match step.side {
                Side::Left => hasher.hash_pair(*sibling, hash),
                Side::Right => hasher.hash_pair(hash, *sibling),
            };
        }
        let Some((peak_index, _)) = peak_position(*leaf, proof.size) else {
            return Err(VerifyError::Inconsistent(
                ProofInconsistency::PeaksMismatch { size: proof.size },
            ));
        };
        if hash != proof.peaks[peak_index] {
            return Ok(false);
        }
    }

    // Every ref must be consumed: a longer ref list than the paths need is
    // malformed.
    if refs_consumed != proof.sibling_refs.len() {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::PathLengthMismatch {
                siblings: proof.sibling_refs.len(),
                expected: refs_consumed,
            },
        ));
    }

    let recomputed = root_from(hasher, bag_peaks(hasher, &proof.peaks), proof.size);
    Ok(recomputed == proof.root)
}

/// Wire encodings for foreign verifiers (Solidity, cairo, …) — and the
/// extension point for user-defined ones.
///
/// The core proof is binary; encoding is an explicit, separate step,
/// replacing the v0.5 `FormattingOptions` that was woven through every proof
/// call. The built-in [`FixedWidth`](encoding::FixedWidth) implements v0.5's extracted semantics —
/// pad-to-length lists with a null placeholder, per-list output sizes,
/// error when a list exceeds its output size (`FormattingError` became
/// [`EncodingError::ListTooLong`](encoding::EncodingError::ListTooLong)) — and its presets capture what v0.5's
/// options were preparing for: Solidity fixed-size word arrays and cairo
/// felt widths. Anything else (ABI structs, calldata, JSON, felt252 arrays)
/// is one user [`ProofEncoding`](encoding::ProofEncoding) implementation away — the trait is the
/// extension point, the presets are just its first implementor.
pub mod encoding {
    use crate::primitives::{Hash, HashValue};
    use alloc::string::String;
    use alloc::vec::Vec;

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

    /// Renders the canonical bytes of a hash value as lowercase hex.
    fn hex_of<O: HashValue>(value: &O) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let bytes = value.to_vec();
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    /// Pads a hash string with leading zeros to `width` (minimal when
    /// `width` is smaller than the string).
    fn pad_hash(value: &str, width: Option<usize>) -> String {
        match width {
            Some(w) if w > value.len() => {
                let mut out = String::with_capacity(w);
                out.extend(core::iter::repeat_n('0', w - value.len()));
                out.push_str(value);
                out
            }
            _ => String::from(value),
        }
    }

    /// Pads a numeric string with leading zeros to `width`.
    fn pad_size(value: u64, width: Option<usize>) -> String {
        let text = alloc::format!("{value}");
        match width {
            Some(w) if w > text.len() => {
                let mut out = String::with_capacity(w);
                out.extend(core::iter::repeat_n('0', w - text.len()));
                out.push_str(&text);
                out
            }
            _ => text,
        }
    }

    /// Resizes a list to `size` entries with the `null` placeholder, or
    /// errors when the list is longer.
    fn pad_list<O: HashValue>(
        list: &[O],
        size: Option<usize>,
        render: impl Fn(&O) -> String,
        null: String,
    ) -> Result<Vec<String>, EncodingError> {
        match size {
            Some(size) if list.len() > size => Err(EncodingError::ListTooLong {
                len: list.len(),
                output_size: size,
            }),
            Some(size) => {
                let mut out: Vec<String> = list.iter().map(render).collect();
                out.resize(size, null);
                Ok(out)
            }
            None => Ok(list.iter().map(render).collect()),
        }
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
            Self {
                hash_width: Some(64),
                size_width: None,
                peaks_size: None,
                siblings_size: None,
            }
        }

        /// Cairo-verifier preset: felt-compatible widths matching the v0.5
        /// stark-hasher output formatting.
        #[must_use]
        pub const fn cairo() -> Self {
            Self {
                hash_width: Some(64),
                size_width: None,
                peaks_size: None,
                siblings_size: None,
            }
        }

        /// Renders one hash per the configured widths.
        fn render<O: HashValue>(&self, value: &O) -> String {
            pad_hash(&hex_of(value), self.hash_width)
        }

        /// The zero-hash placeholder at the configured width.
        fn null(&self) -> String {
            pad_hash(&hex_of(&Hash::ZERO), self.hash_width)
        }
    }

    impl ProofEncoding for FixedWidth {
        type EncodedProof = EncodedProof;
        type EncodedMultiProof = EncodedMultiProof;
        type Error = EncodingError;

        fn encode<O: HashValue>(
            &self,
            proof: &super::Proof<O>,
        ) -> Result<Self::EncodedProof, Self::Error> {
            let siblings = pad_list(
                &proof.siblings,
                self.siblings_size,
                |v| self.render(v),
                self.null(),
            )?;
            let peaks = pad_list(
                &proof.peaks,
                self.peaks_size,
                |v| self.render(v),
                self.null(),
            )?;

            Ok(EncodedProof {
                siblings,
                peaks,
                size: pad_size(proof.size.get(), self.size_width),
                leaf: pad_size(proof.leaf.get(), self.size_width),
                element_hash: pad_hash(&hex_of(&proof.element_hash), self.hash_width),
                root: pad_hash(&hex_of(&proof.root), self.hash_width),
            })
        }

        fn encode_multi<O: HashValue>(
            &self,
            proof: &super::MultiProof<O>,
        ) -> Result<Self::EncodedMultiProof, Self::Error> {
            let sibling_pool =
                pad_list(&proof.sibling_pool, None, |v| self.render(v), self.null())?;
            let peaks = pad_list(
                &proof.peaks,
                self.peaks_size,
                |v| self.render(v),
                self.null(),
            )?;

            Ok(EncodedMultiProof {
                sibling_pool,
                sibling_refs: proof.sibling_refs.clone(),
                peaks,
                size: pad_size(proof.size.get(), self.size_width),
                leaves: proof
                    .leaves
                    .iter()
                    .map(|l| pad_size(l.get(), self.size_width))
                    .collect(),
                element_hashes: proof
                    .element_hashes
                    .iter()
                    .map(|v| pad_hash(&hex_of(v), self.hash_width))
                    .collect(),
                root: pad_hash(&hex_of(&proof.root), self.hash_width),
            })
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
