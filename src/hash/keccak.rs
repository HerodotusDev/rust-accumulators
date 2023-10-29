use anyhow::Result;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;

use super::{IHasher, DEFAULT_BLOCK_SIZE_BITS};

pub struct KeccakHasher {
    options: HashMap<String, usize>,
}

impl IHasher for KeccakHasher {
    fn hash(&self, data: Vec<String>) -> Result<String> {
        if data.is_empty() {
            return Ok(hex::encode(Keccak256::digest(&[])));
        }
        if data.len() == 1 {
            return Ok(hex::encode(Keccak256::digest(data[0].as_bytes())));
        }

        let bytes: Vec<u8> = data
            .into_iter()
            .flat_map(|e| hex::decode(e).expect("Decoding failed"))
            .collect();

        Ok(hex::encode(Keccak256::digest(&bytes)))
    }

    fn is_element_size_valid(&self, element: &str) -> bool {
        element.len() * 8 <= *self.options.get("blockSizeBits").unwrap()
    }

    fn hash_single(&self, data: &str) -> String {
        self.hash(vec![data.to_string()]).unwrap()
    }

    fn get_genesis(&self) -> String {
        let genesis_str = "brave new world";
        let hex_string = hex::encode(genesis_str);
        self.hash_single(&hex_string)
    }
}

impl KeccakHasher {
    pub fn new() -> Self {
        let mut options = HashMap::new();
        options.insert("blockSizeBits".to_string(), DEFAULT_BLOCK_SIZE_BITS);
        KeccakHasher { options }
    }
}
