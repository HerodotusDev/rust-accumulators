use std::str::FromStr;

use crate::hasher::{byte_size, HasherError, HashingFunction};
use num_bigint::BigInt;
use num_traits::Num as _;
use tiny_keccak::{Hasher as KeccakHasherTrait, Keccak};

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

    /// Hashes a data which is a vector of strings
    /// Be aware of depends on either data is hexadecimal or decimal, format differently
    /// example:
    /// hexadecimal: vec!["0x1", "0x2", "0x3", "0xa"]
    /// decimal: vec!["1", "2", "3", "10"]
    /// NOTE: data have no limit in length of elements
    fn hash(&self, data: Vec<String>) -> Result<String, HasherError> {
        let mut output = [0u8; 32];
        let mut keccak = Keccak::v256();

        //? We deliberately don't validate the size of the elements here, because we want to allow hashing of the RLP encoded block to get a block hash
        if data.is_empty() {
            keccak.update(&[]);
        } else if data.len() == 1 {
            let no_prefix = data[0].strip_prefix("0x").unwrap_or(&data[0]);
            keccak.update(&hex::decode(no_prefix)?);
        } else {
            let mut result: Vec<u8> = Vec::new();

            for e in data.iter() {
                let bigint = if e.starts_with("0x") || e.starts_with("0X") {
                    // Parse hexadecimal
                    BigInt::from_str_radix(&e[2..], 16).unwrap()
                } else {
                    // Parse decimal
                    BigInt::from_str(e).unwrap()
                };

                let hex = format!("{:0>64}", bigint.to_str_radix(16));
                let bytes = hex::decode(hex).unwrap();
                result.extend(bytes);
            }

            keccak.update(&result);
        }

        keccak.finalize(&mut output);
        Ok(format!("0x{:0>64}", hex::encode(output)))
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
        let hex = format!("0x{}", hex::encode(genesis_str));

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
