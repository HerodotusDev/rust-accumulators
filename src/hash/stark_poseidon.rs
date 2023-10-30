use super::IHasher;
use anyhow::{anyhow, Result};
use starknet::core::types::FieldElement;
use starknet_crypto::{poseidon_hash, poseidon_hash_many, poseidon_hash_single};

#[derive(Debug, Clone)]
pub struct StarkPoseidonHasher {
    block_size_bits: usize,
    should_pad: bool,
}

impl IHasher for StarkPoseidonHasher {
    fn hash(&self, data: Vec<String>) -> Result<String> {
        let size_error_index = data.iter().position(|e| !self.is_element_size_valid(&e));

        if let Some(index) = size_error_index {
            return Err(anyhow!(
                "Stark Poseidon Hasher only accepts elements of size {} bits. Got {}",
                self.block_size_bits,
                data[index].len() * 8
            ));
        }

        let field_elements: Vec<FieldElement> =
            data.iter().map(|e| e.parse().unwrap_or_default()).collect();
        let hash_core: FieldElement;

        match field_elements.len() {
            0 => {
                return Err(anyhow!(
                    "Stark Poseidon Hasher only accepts arrays of size 1 or greater".to_string()
                ))
            }
            1 => hash_core = poseidon_hash_single(field_elements[0].clone().into()),
            2 => {
                hash_core = poseidon_hash(
                    field_elements[0].clone().into(),
                    field_elements[1].clone().into(),
                )
            }
            _ => {
                hash_core = poseidon_hash_many(&field_elements);
            }
        }

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

    fn hash_single(&self, data: &str) -> String {
        self.hash(vec![data.to_string()]).unwrap()
    }

    fn get_genesis(&self) -> String {
        let genesis_str = "brave new world";
        let hex: String = genesis_str
            .as_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect();
        let hex_with_prefix = format!("0x{}", hex);
        self.hash_single(&hex_with_prefix)
    }
}

impl StarkPoseidonHasher {
    pub fn new(should_pad: Option<bool>) -> Self {
        StarkPoseidonHasher {
            block_size_bits: 252,
            should_pad: should_pad.unwrap_or(false),
        }
    }
}

fn byte_size(hex: &str) -> usize {
    let hex = if hex.starts_with("0x") {
        &hex[2..]
    } else {
        hex
    };

    hex.len() / 2
}
