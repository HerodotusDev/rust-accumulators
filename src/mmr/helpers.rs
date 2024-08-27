use std::collections::HashSet;
use std::fmt::{Display, Formatter};
use std::hash::Hash;
use std::str::FromStr;
use thiserror::Error;

use super::formatting::{PeaksFormattingOptions, ProofFormattingOptions};
use super::MMRError;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Proof {
    /// The index of the proven element.
    /// For example: 1
    pub element_index: usize,

    /// The hash of the element - the hash that is stored in the database.
    /// For example: "0x1234567890abcdef"
    pub element_hash: String,

    /// The proof of the element's inclusion, aka the siblings hashes.
    /// For example: ["0x1234567890abcdef", "0x1234567890abcdef"]
    pub siblings_hashes: Vec<String>,

    /// The hashes of the peaks of the tree.
    /// For example: ["0x1234567890abcdef", "0x1234567890abcdef"]
    pub peaks_hashes: Vec<String>,

    /// The size of the tree, aka the position, aka the number of all elements in the tree.
    /// For example: 1
    pub elements_count: usize,
}

#[derive(Clone, Default)]
pub struct ProofOptions {
    pub elements_count: Option<usize>,
    pub formatting_opts: Option<FormattingOptionsBundle>,
}

pub struct PeaksOptions {
    pub elements_count: Option<usize>,
    pub formatting_opts: Option<PeaksFormattingOptions>,
}

#[derive(Clone)]
pub struct FormattingOptionsBundle {
    pub proof: ProofFormattingOptions,
    pub peaks: PeaksFormattingOptions,
}

/// Tree metadata keys error
#[derive(Debug, Error)]
pub enum TreeMetadataKeysError {
    #[error("Invalid tree metadata key")]
    InvalidKey,
}

#[derive(Debug)]
pub enum TreeMetadataKeys {
    LeafCount,
    ElementCount,
    RootHash,
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

/// Append Result
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AppendResult {
    pub leaves_count: usize,
    pub elements_count: usize,
    /// The index of the appended element.
    pub element_index: usize,
    pub root_hash: String,
}

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

pub fn map_leaf_index_to_element_index(leaf_index: usize) -> usize {
    2 * leaf_index + 1 - count_ones(leaf_index)
}

pub fn leaf_count_to_peaks_count(leaf_count: usize) -> u32 {
    count_ones(leaf_count) as u32
}

pub fn leaf_count_to_mmr_size(leaf_count: usize) -> usize {
    2 * leaf_count - leaf_count_to_peaks_count(leaf_count) as usize
}

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

pub fn element_index_to_leaf_index(element_index: usize) -> Result<usize, MMRError> {
    if element_index == 0 {
        return Err(MMRError::InvalidElementIndex);
    }
    elements_count_to_leaf_count(element_index - 1)
}

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

pub fn array_deduplicate<T: Eq + Hash>(array: Vec<T>) -> Vec<T> {
    let set: HashSet<_> = array.into_iter().collect();
    set.into_iter().collect::<Vec<T>>()
}

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
