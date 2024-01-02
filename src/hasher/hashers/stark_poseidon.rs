use crate::hasher::{byte_size, HasherError, HashingFunction};

use super::super::Hasher;
use starknet::core::types::FieldElement;
use starknet_crypto::{poseidon_hash, poseidon_hash_many, poseidon_hash_single};

/// Hasher for Stark Poseidon
#[derive(Debug, Clone)]
pub struct StarkPoseidonHasher {
    /// The block size in bits for Stark Poseidon is 252
    block_size_bits: usize,
    /// Boolean flag to indicate whether to pad the hash with zeros
    should_pad: bool,
}

impl Hasher for StarkPoseidonHasher {
    fn get_name(&self) -> HashingFunction {
        HashingFunction::Poseidon
    }

    /// Hashes a data which is a vector of strings
    ///
    /// NOTE: data should be more than 1 element
    fn hash(&self, data: Vec<String>) -> Result<String, HasherError> {
        for element in &data {
            if !self.is_element_size_valid(element) {
                return Err(HasherError::InvalidElementSize {
                    element: element.to_string(),
                    block_size_bits: self.block_size_bits,
                });
            }
        }

        let field_elements: Vec<FieldElement> =
            data.iter().map(|e| e.parse().unwrap_or_default()).collect();

        let hash_core = match field_elements.len() {
            0 => return Err(HasherError::InvalidElementsLength),
            1 => poseidon_hash_single(field_elements[0]),
            2 => poseidon_hash(field_elements[0], field_elements[1]),
            _ => poseidon_hash_many(&field_elements),
        };

        let mut hash = format!("{:x}", hash_core);
        if self.should_pad {
            hash = format!("{:0>63}", hash);
        }
        let hash = format!("0x{}", hash);
        Ok(hash)
    }

    fn is_element_size_valid(&self, element: &str) -> bool {
        byte_size(element) <= self.block_size_bits
    }

    fn hash_single(&self, data: &str) -> Result<String, HasherError> {
        self.hash(vec![data.to_string()])
    }

    fn get_genesis(&self) -> Result<String, HasherError> {
        let genesis_str = "brave new world";
        let hex_str = format!("0x{}", hex::encode(genesis_str));
        self.hash_single(&hex_str)
    }

    fn get_block_size_bits(&self) -> usize {
        self.block_size_bits
    }
}

impl StarkPoseidonHasher {
    pub fn new(should_pad: Option<bool>) -> Self {
        Self {
            block_size_bits: 252,
            should_pad: should_pad.unwrap_or(false),
        }
    }
}

impl Default for StarkPoseidonHasher {
    fn default() -> Self {
        Self::new(None)
    }
}
