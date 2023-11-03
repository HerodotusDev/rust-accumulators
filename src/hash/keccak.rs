use anyhow::Result;
use num_bigint::BigInt;
use num_traits::{identities::Zero, Num};
use sha3::{Digest, Keccak256};

use super::IHasher;

pub struct KeccakHasher {
    block_size_bits: usize,
}

impl IHasher for KeccakHasher {
    fn hash(&self, data: Vec<String>) -> Result<String> {
        let mut keccak = Keccak256::new();

        if data.is_empty() {
            keccak.update([]);
        } else if data.len() == 1 {
            keccak.update(data[0].as_bytes());
        } else {
            let mut result: Vec<u8> = Vec::new();

            for e in data.iter() {
                let no_prefix = e.strip_prefix("0x").unwrap_or(e);

                let n = BigInt::from_str_radix(no_prefix, 16).unwrap_or(BigInt::zero());
                let hex = format!("{:0>64x}", n);

                for byte_pair in hex.as_str().as_bytes().chunks(2) {
                    let byte_str = std::str::from_utf8(byte_pair).unwrap();
                    let byte = u8::from_str_radix(byte_str, 16).unwrap();
                    result.push(byte);
                }
            }
            keccak.update(&result);
        }

        let res = keccak.finalize();
        Ok(format!("0x{}", hex::encode(res)))
    }

    fn is_element_size_valid(&self, element: &str) -> bool {
        byte_size(element) <= self.block_size_bits
    }

    fn hash_single(&self, data: &str) -> String {
        self.hash(vec![data.to_string()]).unwrap()
    }

    fn get_genesis(&self) -> String {
        let genesis_str = "brave new world";
        self.hash_single(genesis_str)
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
