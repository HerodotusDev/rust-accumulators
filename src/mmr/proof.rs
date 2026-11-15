//! Proof types: self-contained, standalone-verifiable, canonical multiproofs.
//!
//! A [`Proof`] is a complete commitment: element hash, sibling path, peaks,
//! root, and the node count it was created at. [`verify_proof`] needs only
//! the hasher — no store.
//!
//! [`MultiProof`] stores the sibling set **deduplicated** across the proven
//! leaves, with per-leaf reference lists into that set. For overlapping trees
//! (leaves sharing parents) this is strictly smaller than one proof per leaf.
//!
//! All types are generic over the hash output [`HashValue`], so proofs of any
//! hasher's output type are first-class.

use super::layout::{
    LeafCount, MmrSize, NodeIndex, PathStep, Side, bag_peaks, peak_heights, peaks_of, root_from,
    sibling_path,
};
use crate::hashers::{Hasher, HasherError};
use crate::primitives::{HashValue, LeafIndex};
use alloc::collections::BTreeMap;
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

impl<O: HashValue> Proof<O> {
    /// The sibling hashes, bottom-up (the path segment of the proof).
    ///
    /// Convenience accessor for inspecting or serializing the path without
    /// consuming the proof.
    #[must_use]
    pub fn siblings(&self) -> &[O] {
        &self.siblings
    }
}

impl<O: HashValue> IntoIterator for Proof<O> {
    type Item = O;
    type IntoIter = alloc::vec::IntoIter<O>;

    /// Iterates over the sibling hashes, bottom-up — the path a custom
    /// verifier would replay.
    ///
    /// **Everything else is discarded**: the leaf index, element hash, peaks,
    /// root, and size are dropped with the proof — the iterator cannot
    /// reconstruct them. Use [`Self::siblings`] to borrow the path without
    /// losing the commitment fields.
    fn into_iter(self) -> Self::IntoIter {
        self.siblings.into_iter()
    }
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
    // First-discovery position per sibling — a BTreeMap keeps the no_std
    // profile while making dedup O(n log n) instead of a linear scan per
    // step.
    let mut position_of: BTreeMap<NodeIndex, u32> = BTreeMap::new();
    for path in paths {
        for step in path {
            if let Some(&position) = position_of.get(&step.sibling) {
                pool_refs.push(position);
            } else {
                let position = pool_indexes.len() as u32;
                position_of.insert(step.sibling, position);
                pool_refs.push(position);
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
/// Exhaustive over the structural contract of [`Proof`], [`MultiProof`],
/// and [`ConsistencyProof`]. A standalone `Ok(true)` means the proof is
/// *self-consistent* — its path commits to the element and its peaks bag to
/// its own root; it authenticates nothing by itself. Authentication is the
/// root comparison: the handle-level
/// `verify`/`verify_multi` compare against the accumulator's current root,
/// and standalone users compare against a root they trust from elsewhere.
/// Verification re-derives every conclusion and never trusts the proof's own
/// claims, so a fabricated proof can at worst produce `Ok(false)` — never a
/// panic and never a false `Ok(true)` *relative to the compared roots*.
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
    /// A consistency proof's previous size exceeds its target size.
    #[error("consistency prev size {prev} exceeds the target size {size}")]
    SizesMismatch {
        /// The claimed earlier size.
        prev: MmrSize,
        /// The claimed later size.
        size: MmrSize,
    },
    /// A consistency proof's frontier reconstruction needs a node the proof
    /// does not carry. Unreachable for a well-formed proof (generation emits
    /// every needed node); guards the no-panic contract on fabricated input.
    #[error("consistency proof is missing the value of node {node}")]
    MissingPathNode {
        /// The node whose value could not be resolved.
        node: NodeIndex,
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
    // The element-hash commitments must align with the leaves exactly: a
    // shorter list would let a truncated proof "verify" against fewer
    // commitments than it claims leaves (zip-truncation false-Ok).
    if proof.element_hashes.len() != proof.leaves.len() {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::ElementCountMismatch {
                leaves: proof.leaves.len(),
                elements: proof.element_hashes.len(),
            },
        ));
    }
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
/// Trust model: `Ok(true)` certifies the proof is **self-consistent**
/// — internally coherent, but authentic only relative to a root the verifier
/// trusts (the handle-level `verify` compares against the accumulator's
/// current root; standalone users must compare `proof.root` against a root
/// obtained from a source they trust). A fabricated self-consistent proof is
/// not detected by this function alone.
///
/// # Errors
///
/// Structural inconsistency (see [`VerifyError`]) or hasher failure.
pub fn verify_proof<H: Hasher>(
    hasher: &H,
    proof: &Proof<H::Output>,
    element: &[u8],
) -> Result<bool, VerifyError> {
    let leaf_hash = hasher.hash_leaf(element)?;
    verify_proof_hashed(hasher, proof, leaf_hash)
}

/// The element-already-hashed variant of [`verify_proof`]: verifies a proof
/// against `element_hash` instead of raw element bytes.
///
/// Callers that already hold `hash_leaf(element)` (e.g. re-verifying a
/// captured proof against stored leaf commitments) skip the re-hash; the
/// fold never re-hashes the element — everything below the leaf is derived
/// from this value alone.
///
/// ```
/// use accumulators::hashers::{Hasher, KeccakSolHasher};
/// use accumulators::ids::AccumulatorId;
/// use accumulators::mmr::{Mmr, verify_proof_hashed};
/// use accumulators::primitives::LeafIndex;
/// use accumulators::store::memory::InMemoryStore;
///
/// let mut mmr: Mmr<KeccakSolHasher, _> =
///     Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO).unwrap();
/// mmr.append(b"element").unwrap();
/// let proof = mmr.proof(LeafIndex::FIRST).unwrap();
///
/// let element_hash = KeccakSolHasher.hash_leaf(b"element").unwrap();
/// assert!(verify_proof_hashed(&KeccakSolHasher, &proof, element_hash).unwrap());
/// ```
///
/// # Errors
///
/// Structural inconsistency (see [`VerifyError`]) or hasher failure.
pub fn verify_proof_hashed<H: Hasher>(
    hasher: &H,
    proof: &Proof<H::Output>,
    element_hash: H::Output,
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

    if element_hash != proof.element_hash {
        return Ok(false);
    }

    // Fold the path; each step's side is re-derived from the layout, never
    // trusted from the proof.
    let mut hash = element_hash;
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
    // Order: element-count alignment first (before hashing — wasted work on
    // a misaligned call), then the structural contract, the reference
    // budget, and only then the hashed replay.
    let elements: Vec<I::Item> = elements.into_iter().collect();
    if elements.len() != proof.leaves.len() {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::ElementCountMismatch {
                leaves: proof.leaves.len(),
                elements: elements.len(),
            },
        ));
    }

    // Shape is checked before hashing so a structurally invalid proof never
    // pays for element hashing; the hashed variant re-validates cheaply (a
    // structural walk, no hashing) to stay self-contained.
    check_multi_shape(proof)?;

    let element_hashes: Vec<H::Output> = elements
        .iter()
        .map(|e| hasher.hash_leaf(e.as_ref()))
        .collect::<Result<_, _>>()?;

    verify_multi_proof_hashed(hasher, proof, element_hashes)
}

/// The element-hashes-already-known variant of [`verify_multi_proof`]:
/// verifies against per-leaf element hashes instead of raw element bytes.
///
/// `element_hashes` must align positionally with the proof's leaves (checked
/// structurally — [`ProofInconsistency::ElementCountMismatch`]); each is
/// compared against the proof's own commitment, and the paths are replayed
/// from these values without re-hashing.
///
/// ```
/// use accumulators::hashers::{Hasher, KeccakSolHasher};
/// use accumulators::ids::AccumulatorId;
/// use accumulators::mmr::{Mmr, verify_multi_proof_hashed};
/// use accumulators::primitives::LeafIndex;
/// use accumulators::store::memory::InMemoryStore;
///
/// let mut mmr: Mmr<KeccakSolHasher, _> =
///     Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO).unwrap();
/// for element in ["a", "b", "c"] {
///     mmr.append(element.as_bytes()).unwrap();
/// }
/// let multiproof = mmr.multiproof([LeafIndex::new(0), LeafIndex::new(2)]).unwrap();
///
/// let hashes: Vec<_> = ["a", "c"]
///     .iter()
///     .map(|e| KeccakSolHasher.hash_leaf(e.as_bytes()).unwrap())
///     .collect();
/// assert!(verify_multi_proof_hashed(&KeccakSolHasher, &multiproof, hashes).unwrap());
/// ```
///
/// # Errors
///
/// Structural inconsistency or hasher failure (see [`verify_proof`]).
pub fn verify_multi_proof_hashed<I, H>(
    hasher: &H,
    proof: &MultiProof<H::Output>,
    element_hashes: I,
) -> Result<bool, VerifyError>
where
    I: IntoIterator<Item = H::Output>,
    H: Hasher,
{
    let element_hashes: Vec<H::Output> = element_hashes.into_iter().collect();
    if element_hashes.len() != proof.leaves.len() {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::ElementCountMismatch {
                leaves: proof.leaves.len(),
                elements: element_hashes.len(),
            },
        ));
    }

    check_multi_shape(proof)?;

    // The reference budget is validated before the replay: exactly one ref
    // per path step across all leaves. An early `Ok(false)` below can
    // therefore never mask an over-long (or under-long) ref list — a
    // malformed ref count is an `Err` even when the replayed prefix already
    // failed to commit.
    let expected_refs: usize = proof
        .leaves
        .iter()
        .map(|leaf| sibling_path(*leaf, proof.size).len())
        .sum();
    if proof.sibling_refs.len() != expected_refs {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::PathLengthMismatch {
                siblings: proof.sibling_refs.len(),
                expected: expected_refs,
            },
        ));
    }

    let mut refs = proof.sibling_refs.iter().copied();
    for (leaf, (element_hash, claimed_hash)) in proof
        .leaves
        .iter()
        .zip(element_hashes.iter().zip(&proof.element_hashes))
    {
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

    // The ref budget was validated structurally above, so the replay always
    // consumes exactly `sibling_refs.len()` refs — no trailing check needed.

    let recomputed = root_from(hasher, bag_peaks(hasher, &proof.peaks), proof.size);
    Ok(recomputed == proof.root)
}

/// A consistency proof: the MMR at [`Self::prev_size`] is a prefix of the
/// MMR at [`Self::size`].
///
/// The construction is the Reyzin–Yakoubov accumulator-consistency shape,
/// flattened to what the crate's proofs carry: the earlier
/// MMR's peaks (to recompute the earlier root) plus one deduplicated,
/// canonical `path` of the frontier nodes the earlier peaks merge with on
/// the way to the later peaks. Shared siblings appear once; the later
/// peaks themselves are recomputed, not carried.
///
/// Verification ([`verify_consistency_proof`]) needs only the hasher and
/// the two roots — no store, no elements. Every node position is re-derived
/// from the layout, never trusted from the proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyProof<O: HashValue> {
    /// Node count of the earlier MMR.
    pub prev_size: MmrSize,
    /// Node count of the later MMR.
    pub size: MmrSize,
    /// Peaks of the earlier MMR (left to right) — re-bagged (with
    /// `prev_size`) to recompute the earlier root.
    pub prev_peaks: Vec<O>,
    /// Bridge hashes: the frontier nodes the earlier peaks merge with,
    /// in canonical walk order. For an empty earlier MMR there is nothing
    /// to walk from — this carries the later MMR's peaks directly.
    pub path: Vec<O>,
}

/// Verifies a consistency proof: that an MMR of `proof.prev_size` nodes
/// with root `prev_root` is a prefix of an MMR of `proof.size` nodes with
/// root `root`.
///
/// Both roots are the verifier's trusted anchors — obtained from whichever
/// source the two accumulator states were authenticated by — exactly like
/// the root a standalone [`verify_proof`] caller compares against. The
/// verifier re-derives everything else: it re-bags the earlier peaks into
/// `prev_root`, replays the canonical merge walk to bind every path entry
/// to its node, rebuilds the later frontier from the earlier peaks and the
/// path, and re-bags it into `root`. A fabricated proof can at worst yield
/// `Ok(false)` — never a panic and never a false `Ok(true)` relative to
/// the compared roots.
///
/// Under collision resistance, `Ok(true)` means the leaf hashes committed
/// by `prev_root` are a prefix of those committed by `root` — the MMR
/// counterpart of a log's append-only guarantee (Reyzin–Yakoubov).
///
/// ```
/// use accumulators::hashers::{Hasher, KeccakSolHasher};
/// use accumulators::ids::AccumulatorId;
/// use accumulators::mmr::{LeafCount, Mmr, size_of, verify_consistency_proof};
/// use accumulators::store::memory::InMemoryStore;
///
/// let mut mmr: Mmr<KeccakSolHasher, _> =
///     Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO).unwrap();
/// for element in ["a", "b", "c", "d", "e"] {
///     mmr.append(element.as_bytes()).unwrap();
/// }
/// let prev_size = size_of(LeafCount::new(3));
/// let proof = mmr.consistency_proof(prev_size).unwrap();
///
/// // The verifier holds only the two roots, the proof, and the hasher.
/// let mut seed: Mmr<KeccakSolHasher, InMemoryStore> =
///     Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::from_bytes([9; 16]))
///         .unwrap();
/// for element in ["a", "b", "c"] {
///     seed.append(element.as_bytes()).unwrap();
/// }
/// assert!(verify_consistency_proof(&KeccakSolHasher, &proof, seed.root(), mmr.root()).unwrap());
/// ```
///
/// # Errors
///
/// Structural inconsistency (see [`VerifyError`]) — a malformed size, a
/// size order violation, a peak-count mismatch, or a path length that does
/// not match the canonical walk for the two sizes.
pub fn verify_consistency_proof<H: Hasher>(
    hasher: &H,
    proof: &ConsistencyProof<H::Output>,
    prev_root: H::Output,
    root: H::Output,
) -> Result<bool, VerifyError> {
    // Structural contract first: well-formed sizes, in order, with the
    // earlier peak count matching the earlier size. A structurally invalid
    // proof never reaches the hashing below.
    let inconsistent = |error| VerifyError::Inconsistent(error);
    let Some(prev_leaves) = proof.prev_size.leaf_count() else {
        return Err(inconsistent(ProofInconsistency::PeaksMismatch {
            size: proof.prev_size,
        }));
    };
    if proof.size.leaf_count().is_none() {
        return Err(inconsistent(ProofInconsistency::PeaksMismatch {
            size: proof.size,
        }));
    }
    if proof.prev_size > proof.size {
        return Err(inconsistent(ProofInconsistency::SizesMismatch {
            prev: proof.prev_size,
            size: proof.size,
        }));
    }
    if proof.prev_peaks.len() != prev_leaves.get().count_ones() as usize {
        return Err(inconsistent(ProofInconsistency::PeaksMismatch {
            size: proof.prev_size,
        }));
    }

    // The canonical walk binds every path entry to its node position — a
    // fabricated path cannot choose which nodes it names, only supply
    // values for the positions the layout dictates.
    let bridge_nodes = consistency_bridge_nodes(proof.prev_size, proof.size);
    if proof.path.len() != bridge_nodes.len() {
        return Err(inconsistent(ProofInconsistency::PathLengthMismatch {
            siblings: proof.path.len(),
            expected: bridge_nodes.len(),
        }));
    }

    // The earlier frontier must bag to the earlier root.
    let recomputed_prev = root_from(
        hasher,
        bag_peaks(hasher, &proof.prev_peaks),
        proof.prev_size,
    );
    if recomputed_prev != prev_root {
        return Ok(false);
    }

    // Known values, bound to their canonical node positions: the earlier
    // peaks, then the path entries.
    let mut known: BTreeMap<NodeIndex, H::Output> = BTreeMap::new();
    for (node, value) in peaks_of(proof.prev_size).into_iter().zip(&proof.prev_peaks) {
        known.insert(node, *value);
    }
    for (node, value) in bridge_nodes.into_iter().zip(&proof.path) {
        known.insert(node, *value);
    }

    // Rebuild the later frontier from the earlier peaks and the path.
    let mut frontier = Vec::with_capacity(peaks_of(proof.size).len());
    for peak in peaks_of(proof.size) {
        frontier.push(resolve_frontier_node(hasher, peak, &known)?);
    }

    // The rebuilt frontier must bag to the later root.
    let recomputed = root_from(hasher, bag_peaks(hasher, &frontier), proof.size);
    Ok(recomputed == root)
}

/// The canonical bridge walk: the node indexes whose values a consistency
/// proof from `prev_size` to `size` must carry, in generation order.
///
/// Two node families, in order:
///
/// 1. For each earlier peak that is no longer a peak of the later MMR, walk
///    up to its later peak; at each step the sibling is either another
///    earlier peak (already known to the verifier) or a bridge node the
///    proof must carry.
/// 2. The later MMR's "right peaks" — peaks whose leaf range starts at or
///    after the prefix boundary. They contain no earlier leaves, so no walk
///    reaches them; they are the IETF COSE MMR profile's `right-peaks`,
///    carried whole. (A chain sibling is never a later peak — its parent
///    exists — so the two families are disjoint.)
///
/// For an empty earlier MMR the first family is empty and the second is
/// the later MMR's entire peak list.
///
/// Both sizes must be well-formed MMR sizes (validated by every caller);
/// the walk is then pure layout and terminates — each step moves to the
/// parent, and every non-peak node of a well-formed MMR has its containing
/// peak as an ancestor.
pub(crate) fn consistency_bridge_nodes(prev_size: MmrSize, size: MmrSize) -> Vec<NodeIndex> {
    #[expect(
        clippy::expect_used,
        reason = "every caller validates well-formed MMR sizes before walking"
    )]
    let prev_leaves = prev_size
        .leaf_count()
        .expect("validated by every caller: a well-formed MMR size");
    let mut path = Vec::new();
    let new_peaks = peaks_of(size);
    let prev_peaks = peaks_of(prev_size);
    for peak in &prev_peaks {
        if new_peaks.contains(peak) {
            continue; // Survived: still a peak of the later MMR.
        }
        let mut node = *peak;
        while !new_peaks.contains(&node) {
            #[expect(
                clippy::expect_used,
                reason = "a non-peak node of a well-formed MMR has its parent within it; the walk is pure layout over validated sizes"
            )]
            let parent = node
                .parent()
                .expect("a non-peak node of a well-formed MMR has a parent within it");
            let sibling = merge_sibling(node, parent);
            if !prev_peaks.contains(&sibling) {
                path.push(sibling);
            }
            node = parent;
        }
    }
    // The right peaks: later peaks entirely past the prefix boundary.
    let mut covered = 0_u64;
    for (peak, height) in new_peaks.into_iter().zip(peak_heights(size)) {
        if covered >= prev_leaves.get() {
            path.push(peak);
        }
        covered += 1_u64 << u32::from(height.get());
    }
    path
}

/// The sibling of `node` under `parent`: the parent's other child. Children
/// of `parent` are `parent − 2^height(parent)` (left) and `parent − 1`
/// (right).
fn merge_sibling(node: NodeIndex, parent: NodeIndex) -> NodeIndex {
    if parent.get() == node.get() + 1 {
        // `node` is the right child; the sibling is the left one.
        #[expect(
            clippy::expect_used,
            reason = "the left child of a real MMR parent is a positive node index"
        )]
        NodeIndex::try_new(parent.get() - (1_u64 << u32::from(parent.height().get())))
            .expect("the left child of a real MMR parent is a valid node")
    } else {
        // `node` is the left child; the sibling is the right one.
        #[expect(
            clippy::expect_used,
            reason = "parent − 1 is a positive node index: the parent is a real merge node"
        )]
        NodeIndex::try_new(parent.get() - 1).expect("parent − 1 is a valid node")
    }
}

/// Resolves a later-frontier node's hash from the proof's known values,
/// expanding internal nodes recursively. Every expanded node is a node of
/// the later MMR (children of MMR nodes are MMR nodes), so expansion
/// terminates at the leaves; a leaf absent from `known` means the proof is
/// missing a node — unreachable for a well-formed proof (generation emits
/// every needed node), but never a panic on fabricated input.
fn resolve_frontier_node<H: Hasher>(
    hasher: &H,
    node: NodeIndex,
    known: &BTreeMap<NodeIndex, H::Output>,
) -> Result<H::Output, VerifyError> {
    if let Some(value) = known.get(&node) {
        return Ok(*value);
    }
    let height = u32::from(node.height().get());
    if height == 0 {
        return Err(VerifyError::Inconsistent(
            ProofInconsistency::MissingPathNode { node },
        ));
    }
    #[expect(
        clippy::expect_used,
        reason = "the left child of a real MMR node is a positive node index"
    )]
    let left = NodeIndex::try_new(node.get() - (1_u64 << height))
        .expect("the left child of a real MMR node is a valid node");
    #[expect(
        clippy::expect_used,
        reason = "node − 1 is a positive node index: internal nodes are ≥ 3"
    )]
    let right = NodeIndex::try_new(node.get() - 1).expect("node − 1 is a valid node");
    let left_hash = resolve_frontier_node(hasher, left, known)?;
    let right_hash = resolve_frontier_node(hasher, right, known)?;
    Ok(hasher.hash_pair(left_hash, right_hash))
}

/// Wire encodings for foreign verifiers (Solidity, cairo, …) — and the
/// extension point for user-defined ones.
///
/// The core proof is binary; encoding is an explicit, separate step. The
/// built-in [`FixedWidth`](encoding::FixedWidth) renders pad-to-length
/// lists with a null
/// placeholder, per-list output sizes, an error when a list exceeds its
/// output size ([`EncodingError::ListTooLong`](encoding::EncodingError::ListTooLong)) — with presets for
/// Solidity fixed-size word arrays and cairo felt widths. Anything else
/// (ABI structs, calldata, JSON, felt252 arrays) is one user
/// [`ProofEncoding`](encoding::ProofEncoding) implementation away.
pub mod encoding {
    use crate::primitives::HashValue;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// The extension point: turn a proof into any wire format.
    ///
    /// Implement this for your own encoder — on-chain calldata, a JSON
    /// payload, a felt252 array, whatever the verifier consumes. Fallible
    /// because fixed-size targets can reject overlong input
    /// ([`EncodingError`]).
    ///
    /// ```
    /// use accumulators::mmr::{MultiProof, Proof, ProofEncoding};
    /// use accumulators::primitives::HashValue;
    ///
    /// /// One-line-per-proof text rendering — a log format, not a wire
    /// /// format, but the trait contract is the same.
    /// struct TextEncoding;
    ///
    /// impl ProofEncoding for TextEncoding {
    ///     type EncodedProof = String;
    ///     type EncodedMultiProof = String;
    ///     type Error = core::convert::Infallible;
    ///
    ///     fn encode<O: HashValue>(&self, proof: &Proof<O>) -> Result<String, Self::Error> {
    ///         Ok(format!(
    ///             "leaf {} of {} nodes, {} siblings, root {}",
    ///             proof.leaf,
    ///             proof.size,
    ///             proof.siblings().len(),
    ///             proof.root.to_vec().iter().map(|b| format!("{b:02x}")).collect::<String>(),
    ///         ))
    ///     }
    ///
    ///     fn encode_multi<O: HashValue>(
    ///         &self,
    ///         proof: &MultiProof<O>,
    ///     ) -> Result<String, Self::Error> {
    ///         Ok(format!("{} leaves, {} pooled siblings", proof.leaves.len(), proof.sibling_pool.len()))
    ///     }
    /// }
    /// ```
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
        crate::primitives::hex::encode(&value.to_vec())
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

    /// How hash values render on the wire.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub enum HexStyle {
        /// `0x`-prefixed, full-width canonical hex — the Solidity `bytes32`
        /// convention.
        #[default]
        Word,
        /// Bare (unprefixed) minimal hex with leading zeros stripped — the
        /// cairo felt convention (a zero value renders as `"0"`).
        Felt,
    }

    /// The built-in fixed-width encoding.
    ///
    /// Hashes render per [`Self::style`] (word: `0x`-prefixed full canonical
    /// hex, zero-padded to [`Self::hash_width`] when set; felt: bare minimal
    /// hex, zero-padded to [`Self::hash_width`] when set). The node count
    /// renders zero-padded to [`Self::size_width`]. When a list output size
    /// is set, the list is null-padded — the **zero hash** rendered through
    /// the same style (`bytes32(0x000…0)` / felt `0`) — or errors when
    /// longer. The placeholder's width always tracks the hasher output's own
    /// [`HashValue::LEN`], never a hardcoded 32.
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct FixedWidth {
        /// Zero-pad hash strings to this width (`None` = the style's natural
        /// width: full canonical hex for [`HexStyle::Word`], minimal for
        /// [`HexStyle::Felt`]).
        pub hash_width: Option<usize>,
        /// Zero-pad the node-count / index strings to this width (`None` =
        /// minimal decimal).
        pub size_width: Option<usize>,
        /// Null-pad the peaks list to this length (`None` = as-is).
        pub peaks_size: Option<usize>,
        /// Null-pad the sibling list to this length (`None` = as-is).
        pub siblings_size: Option<usize>,
        /// How hash values render (prefix + zero handling).
        pub style: HexStyle,
    }

    impl FixedWidth {
        /// Solidity-verifier preset: `0x`-prefixed, zero-padded 64-hex
        /// `bytes32` words. Per-list output sizes are
        /// deliberately unset — the preset cannot know the verifier's
        /// expected array sizes; set [`Self::peaks_size`] /
        /// [`Self::siblings_size`] for the concrete verifier contract.
        #[must_use]
        pub const fn solidity() -> Self {
            Self {
                hash_width: Some(64),
                size_width: None,
                peaks_size: None,
                siblings_size: None,
                style: HexStyle::Word,
            }
        }

        /// Cairo-verifier preset: bare (unprefixed) minimal felt hex, the
        /// starknet felt rendering. Per-list output sizes are deliberately
        /// unset — the preset cannot know the verifier's expected array
        /// sizes; set [`Self::peaks_size`] / [`Self::siblings_size`] for the
        /// concrete verifier contract.
        #[must_use]
        pub const fn cairo() -> Self {
            Self {
                hash_width: None,
                size_width: None,
                peaks_size: None,
                siblings_size: None,
                style: HexStyle::Felt,
            }
        }

        /// Renders one hash per the configured style and widths.
        fn render<O: HashValue>(&self, value: &O) -> String {
            let hex = hex_of(value);
            match self.style {
                HexStyle::Word => {
                    let mut out = String::with_capacity(2 + hex.len());
                    out.push_str("0x");
                    out.push_str(&pad_hash(&hex, self.hash_width));
                    out
                }
                HexStyle::Felt => {
                    let stripped = hex.trim_start_matches('0');
                    let felt = if stripped.is_empty() { "0" } else { stripped };
                    pad_hash(felt, self.hash_width)
                }
            }
        }

        /// The zero-hash placeholder at the value type's own width, rendered
        /// through the configured style (`O::LEN`-aware, not hardcoded 32).
        fn null<O: HashValue>(&self) -> String {
            match self.style {
                HexStyle::Word => {
                    let zeros = "0".repeat(2 * O::LEN);
                    alloc::format!("0x{}", pad_hash(&zeros, self.hash_width))
                }
                HexStyle::Felt => pad_hash("0", self.hash_width),
            }
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
                self.null::<O>(),
            )?;
            let peaks = pad_list(
                &proof.peaks,
                self.peaks_size,
                |v| self.render(v),
                self.null::<O>(),
            )?;

            Ok(EncodedProof {
                siblings,
                peaks,
                size: pad_size(proof.size.get(), self.size_width),
                leaf: pad_size(proof.leaf.get(), self.size_width),
                element_hash: self.render(&proof.element_hash),
                root: self.render(&proof.root),
            })
        }

        fn encode_multi<O: HashValue>(
            &self,
            proof: &super::MultiProof<O>,
        ) -> Result<Self::EncodedMultiProof, Self::Error> {
            let sibling_pool = pad_list(
                &proof.sibling_pool,
                None,
                |v| self.render(v),
                self.null::<O>(),
            )?;
            let peaks = pad_list(
                &proof.peaks,
                self.peaks_size,
                |v| self.render(v),
                self.null::<O>(),
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
                    .map(|v| self.render(v))
                    .collect(),
                root: self.render(&proof.root),
            })
        }
    }

    /// Fixed-width encoding failures.
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
