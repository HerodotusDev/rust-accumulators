use anyhow::Result;
use sha3::{Digest, Keccak256};

use crate::hasher::HashingFunction;

use super::super::Hasher;

#[derive(Debug)]
pub struct KeccakHasher {
    block_size_bits: usize,
}

impl Hasher for KeccakHasher {
    fn get_name(&self) -> HashingFunction {
        HashingFunction::Keccak256
    }

    fn hash(&self, data: Vec<String>) -> Result<String> {
        let mut keccak = Keccak256::new();

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

    fn is_element_size_valid(&self, element: &str) -> bool {
        byte_size(element) <= self.block_size_bits
    }

    fn hash_single(&self, data: &str) -> Result<String> {
        self.hash(vec![data.to_string()])
    }

    fn get_genesis(&self) -> Result<String> {
        let genesis_str = "brave new world";
        let hex = hex::encode(genesis_str);

        self.hash_single(&hex)
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

fn byte_size(hex: &str) -> usize {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);

    hex.len() / 2
}
