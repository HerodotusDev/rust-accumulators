use anyhow::Result;
use std::collections::HashMap;

use primitive_types::U256;
use starknet::core::{crypto::pedersen_hash, types::FieldElement};

use crate::hasher::HashingFunction;

use super::super::Hasher;

#[derive(Debug, Clone)]
pub struct StarkPedersenHasher {
    options: HashMap<String, usize>,
}

impl Hasher for StarkPedersenHasher {
    fn get_name(&self) -> HashingFunction {
        HashingFunction::Pedersen
    }

    fn hash(&self, data: Vec<String>) -> Result<String> {
        if data.len() != 2 {
            panic!("Stark Pedersen Hasher only accepts two elements");
        }
        for element in &data {
            if !self.is_element_size_valid(element) {
                panic!("{}", format!("Element {} is not of valid size", element));
            }
        }

        let clean_data: Vec<String> = data
            .iter()
            .map(|s| {
                if let Some(stripped) = s.strip_prefix("0x") {
                    U256::from_str_radix(stripped, 16).unwrap().to_string()
                } else {
                    U256::from_str_radix(s, 16).unwrap().to_string()
                }
            })
            .collect();

        let result = pedersen_hash(
            &FieldElement::from_dec_str(&clean_data[0]).unwrap_or_default(),
            &FieldElement::from_dec_str(&clean_data[1]).unwrap_or_default(),
        )
        .to_string();

        let computed_result = U256::from_dec_str(result.trim()).expect("Failed to convert to U256");
        let padded_hex_str = format!("0x{:064x}", computed_result);

        Ok(padded_hex_str)
    }

    fn is_element_size_valid(&self, element: &str) -> bool {
        byte_size(element) <= *self.options.get("blockSizeBits").unwrap()
    }

    fn hash_single(&self, data: &str) -> Result<String> {
        self.hash(vec![data.to_string(), "".to_string()])
    }

    fn get_genesis(&self) -> Result<String> {
        let genesis_str = "brave new world";
        self.hash_single(genesis_str)
    }
}

impl StarkPedersenHasher {
    pub fn new() -> Self {
        let mut options = HashMap::new();
        options.insert("blockSizeBits".to_string(), 252);
        StarkPedersenHasher { options }
    }
}

impl Default for StarkPedersenHasher {
    fn default() -> Self {
        Self::new()
    }
}

fn byte_size(hex: &str) -> usize {
    let hex = if let Some(stripped) = hex.strip_prefix("0x") {
        stripped
    } else {
        hex
    };

    hex.len() / 2
}
