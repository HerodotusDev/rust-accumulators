use crate::hasher::{byte_size, HasherError, HashingFunction};
use sha3::{Digest, Keccak256};

use super::super::Hasher;

/// Hasher for Keccak256
#[derive(Debug, Clone)]
pub struct KeccakHasher {
    /// The block size in bits for Keccak256 is 256
    block_size_bits: usize,
}

impl Hasher for KeccakHasher {
    fn get_name(&self) -> HashingFunction {
        HashingFunction::Keccak256
    }

    /// Hashes a data which is a vector of strings (all elements must be hex encoded)
    ///
    /// NOTE: data have no limit in length of elements
    fn hash(&self, data: Vec<String>) -> Result<String, HasherError> {
        let mut keccak = Keccak256::default();

        //? We deliberately don't validate the size of the elements here, because we want to allow hashing of the RLP encoded block to get a block hash

        if data.is_empty() {
            keccak.update([]);
        } else if data.len() == 1 {
            let no_prefix = data[0].strip_prefix("0x").unwrap_or(&data[0]);
            keccak.update(hex::decode(no_prefix)?);
        } else {
            let mut result: Vec<u8> = Vec::new();

            for e in data.iter() {
                let no_prefix = e.strip_prefix("0x").unwrap_or(e);
                result.extend(hex::decode(no_prefix)?)
            }

            keccak.update(&result);
        }

        let res = keccak.finalize();
        Ok(format!("0x{:0>64}", hex::encode(res)))
    }

    fn is_element_size_valid(&self, element: &str) -> Result<bool, HasherError> {
        let size = byte_size(element);
        if size <= self.block_size_bits {
            Ok(true)
        } else {
            Err(HasherError::InvalidElementSize {
                element_size: size,
                block_size_bits: self.block_size_bits,
            })
        }
    }

    /// Hashes a single data which is a string (must be hex encoded)
    fn hash_single(&self, data: &str) -> Result<String, HasherError> {
        self.hash(vec![data.to_string()])
    }

    fn get_genesis(&self) -> Result<String, HasherError> {
        let genesis_str = "brave new world";
        let hex = hex::encode(genesis_str);

        self.hash_single(&hex)
    }

    fn get_block_size_bits(&self) -> usize {
        self.block_size_bits
    }
}

impl KeccakHasher {
    pub fn new() -> Self {
        Self {
            block_size_bits: 256,
        }
    }
}

impl Default for KeccakHasher {
    fn default() -> Self {
        Self::new()
    }
}
