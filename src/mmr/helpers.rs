use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::str::FromStr;
use thiserror::Error;

use super::MMRError;
use super::formatting::{PeaksFormattingOptions, ProofFormattingOptions};

/// An inclusion proof for a single element in an MMR.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Proof {
    /// The index of the proven element.
    /// For example: 1
    pub element_index: usize,

    /// The hash of the element - the hash that is stored in the database.
    /// For example: `0x1234567890abcdef`
    pub element_hash: String,

    /// The proof of the element's inclusion, aka the siblings hashes.
    /// For example: `0x1234567890abcdef`, `0x1234567890abcdef`
    pub siblings_hashes: Vec<String>,

    /// The hashes of the peaks of the tree.
    /// For example: `0x1234567890abcdef`, `0x1234567890abcdef`
    pub peaks_hashes: Vec<String>,

    /// The size of the tree, aka the position, aka the number of all elements in the tree.
    /// For example: 1
    pub elements_count: usize,
}

/// Options controlling proof generation.
#[derive(Clone, Default)]
pub struct ProofOptions {
    /// The element count to generate the proof against; defaults to the MMR's
    /// current element count when `None`.
    pub elements_count: Option<usize>,
    /// Formatting options applied to the proof's sibling and peak hashes.
    pub formatting_opts: Option<FormattingOptionsBundle>,
}

/// Options controlling peak retrieval.
pub struct PeaksOptions {
    /// The element count to compute the peaks for; defaults to the MMR's
    /// current element count when `None`.
    pub elements_count: Option<usize>,
    /// Formatting options applied to the peak hashes.
    pub formatting_opts: Option<PeaksFormattingOptions>,
}

/// A bundle of the formatting options applied to proofs and peaks.
#[derive(Clone)]
pub struct FormattingOptionsBundle {
    /// Formatting options applied to proofs.
    pub proof: ProofFormattingOptions,
    /// Formatting options applied to peaks.
    pub peaks: PeaksFormattingOptions,
}

/// Tree metadata keys error
#[derive(Debug, Error)]
pub enum TreeMetadataKeysError {
    /// The provided text is not a known tree metadata key.
    #[error("Invalid tree metadata key")]
    InvalidKey,
}

/// The metadata keys under which an MMR persists its state in the store.
#[derive(Debug, Clone, Copy)]
pub enum TreeMetadataKeys {
    /// The key under which the MMR's leaf count is stored.
    LeafCount,
    /// The key under which the MMR's element count is stored.
    ElementCount,
    /// The key under which the MMR's root hash is stored.
    RootHash,
    /// The key prefix under which the MMR's element hashes are stored.
    Hashes,
}

impl FromStr for TreeMetadataKeys {
    fn from_str(text: &str) -> Result<Self, TreeMetadataKeysError> {
        match text {
            "leaf_count" => Ok(TreeMetadataKeys::LeafCount),
            "elements_count" => Ok(TreeMetadataKeys::ElementCount),
            "root_hash" => Ok(TreeMetadataKeys::RootHash),
            "hashes" => Ok(TreeMetadataKeys::Hashes),
            _ => Err(TreeMetadataKeysError::InvalidKey),
        }
    }

    type Err = TreeMetadataKeysError;
}

impl Display for TreeMetadataKeys {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TreeMetadataKeys::LeafCount => write!(f, "leaf_count"),
            TreeMetadataKeys::ElementCount => write!(f, "elements_count"),
            TreeMetadataKeys::RootHash => write!(f, "root_hash"),
            TreeMetadataKeys::Hashes => write!(f, "hashes"),
        }
    }
}

/// The result of appending an element to an MMR.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AppendResult {
    /// The number of leaves in the MMR after the append.
    pub leaves_count: usize,
    /// The total number of nodes in the MMR after the append.
    pub elements_count: usize,
    /// The index of the appended element.
    pub element_index: usize,
    /// The MMR's root hash after the append.
    pub root_hash: String,
}

/// Returns the node indices of the peaks of an MMR with the given element count.
///
/// Returns an empty vector if the element count is not a valid MMR size.
#[must_use]
pub fn find_peaks(mut elements_count: usize) -> Vec<usize> {
    let mut mountain_elements_count = (1 << bit_length(elements_count)) - 1;
    let mut mountain_index_shift = 0;
    let mut peaks: Vec<usize> = Vec::new();

    while mountain_elements_count > 0 {
        if mountain_elements_count <= elements_count {
            mountain_index_shift += mountain_elements_count;
            peaks.push(mountain_index_shift);
            elements_count -= mountain_elements_count;
        }
        mountain_elements_count >>= 1;
    }

    if elements_count > 0 {
        return Vec::new();
    }

    peaks
}

pub(crate) fn count_ones(mut value: usize) -> usize {
    let mut ones_count = 0;
    while value > 0 {
        value &= value - 1;
        ones_count += 1;
    }
    ones_count
}

/// Maps a leaf's index (0-based) to its node index in the MMR.
#[must_use]
pub fn map_leaf_index_to_element_index(leaf_index: usize) -> usize {
    2 * leaf_index + 1 - count_ones(leaf_index)
}

/// Returns the number of peaks in an MMR with the given leaf count.
#[must_use]
pub fn leaf_count_to_peaks_count(leaf_count: usize) -> usize {
    count_ones(leaf_count)
}

/// Returns the total number of nodes in an MMR with the given leaf count.
#[must_use]
pub fn leaf_count_to_mmr_size(leaf_count: usize) -> usize {
    2 * leaf_count - leaf_count_to_peaks_count(leaf_count)
}

/// Returns the number of peak merges caused by appending a leaf to an MMR with
/// the given leaf count.
#[must_use]
pub fn leaf_count_to_append_no_merges(leaf_count: usize) -> usize {
    count_trailing_ones(leaf_count)
}

fn count_trailing_ones(mut num: usize) -> usize {
    let mut count = 0;
    while num != 0 && num & 1 == 1 {
        num >>= 1;
        count += 1;
    }
    count
}

/// Returns the node indices of the siblings along the path from the element at
/// `element_index` up to its peak, excluding the peak level itself.
///
/// # Errors
///
/// Returns `MMRError::InvalidElementIndex` if `element_index` is zero.
pub fn find_siblings(element_index: usize, elements_count: usize) -> Result<Vec<usize>, MMRError> {
    let mut leaf_index = element_index_to_leaf_index(element_index)?;
    let mut height = 0;
    let mut siblings = Vec::new();
    let mut current_element_index = element_index;

    while current_element_index <= elements_count {
        let siblings_offset = (2 << height) - 1;
        if leaf_index % 2 == 1 {
            // right child
            siblings.push(current_element_index - siblings_offset);
            current_element_index += 1;
        } else {
            // left child
            siblings.push(current_element_index + siblings_offset);
            current_element_index += siblings_offset + 1;
        }
        leaf_index /= 2;
        height += 1;
    }

    siblings.pop();
    Ok(siblings)
}

/// Maps an element's node index to its leaf index (0-based).
///
/// # Errors
///
/// Returns `MMRError::InvalidElementIndex` if the element index is zero.
pub fn element_index_to_leaf_index(element_index: usize) -> Result<usize, MMRError> {
    if element_index == 0 {
        return Err(MMRError::InvalidElementIndex);
    }
    elements_count_to_leaf_count(element_index - 1)
}

/// Returns the number of leaves in an MMR of the given size.
///
/// # Errors
///
/// Returns `MMRError::InvalidElementCount` if the element count is not a valid
/// MMR size.
pub fn elements_count_to_leaf_count(elements_count: usize) -> Result<usize, MMRError> {
    let mut leaf_count = 0;
    let mut mountain_leaf_count = 1 << bit_length(elements_count);
    let mut current_elements_count = elements_count;

    while mountain_leaf_count > 0 {
        let mountain_elements_count = 2 * mountain_leaf_count - 1;
        if mountain_elements_count <= current_elements_count {
            leaf_count += mountain_leaf_count;
            current_elements_count -= mountain_elements_count;
        }
        mountain_leaf_count >>= 1;
    }

    if current_elements_count > 0 {
        Err(MMRError::InvalidElementCount)
    } else {
        Ok(leaf_count)
    }
}

fn bit_length(num: usize) -> usize {
    (std::mem::size_of::<usize>() * 8) - num.leading_zeros() as usize
}

/// Removes duplicate elements from the vector. The order of the returned
/// elements is unspecified.
#[must_use]
pub fn array_deduplicate<T: Eq + Hash>(array: Vec<T>) -> Vec<T> {
    let set: HashSet<_> = array.into_iter().collect();
    set.into_iter().collect::<Vec<T>>()
}

/// Returns the index and height of the peak that the element at `element_index`
/// belongs to, for an MMR of the given size.
#[must_use]
pub fn get_peak_info(mut elements_count: usize, mut element_index: usize) -> (usize, usize) {
    let mut mountain_height = bit_length(elements_count);
    let mut mountain_elements_count = (1 << mountain_height) - 1;
    let mut mountain_index = 0;

    loop {
        if mountain_elements_count <= elements_count {
            if element_index <= mountain_elements_count {
                return (mountain_index, mountain_height - 1);
            }
            elements_count -= mountain_elements_count;
            element_index -= mountain_elements_count;
            mountain_index += 1;
        }
        mountain_elements_count >>= 1;
        mountain_height -= 1;
    }
}

/// Returns the number of leaves in an MMR of the given total size.
#[must_use]
pub fn mmr_size_to_leaf_count(mmr_size: usize) -> usize {
    let mut remaining_size = mmr_size;
    let bits = bit_length(remaining_size + 1);
    let mut mountain_tips = 1 << (bits - 1); // Using bitwise shift to calculate 2^(bits-1)
    let mut leaf_count = 0;

    while mountain_tips != 0 {
        let mountain_size = 2 * mountain_tips - 1;
        if mountain_size <= remaining_size {
            remaining_size -= mountain_size;
            leaf_count += mountain_tips;
        }
        mountain_tips >>= 1; // Using bitwise shift for division by 2
    }

    leaf_count
}
