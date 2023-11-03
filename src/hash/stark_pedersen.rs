use anyhow::Result;
use std::collections::HashMap;

use primitive_types::U256;
use starknet::core::{crypto::pedersen_hash, types::FieldElement};

use super::IHasher;

#[derive(Debug, Clone)]
pub struct StarkPedersenHasher {
    options: HashMap<String, usize>,
}

impl IHasher for StarkPedersenHasher {
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
                if s.starts_with("0x") {
                    U256::from_str_radix(&s[2..], 16).unwrap().to_string()
                } else {
                    s.clone()
                }
            })
            .collect();

        let result = pedersen_hash(
            &FieldElement::from_dec_str(&clean_data[0]).unwrap_or_default(),
            &FieldElement::from_dec_str(&clean_data[1]).unwrap_or_default(),
        )
        .to_string();

        let computed_result =
            U256::from_dec_str(&result.trim()).expect("Failed to convert to U256");
        let hex_str = format!("{:064x}", computed_result);
        let padded_hex_str = format!("0x{}", hex_str);

        Ok(padded_hex_str)
    }

    fn is_element_size_valid(&self, element: &str) -> bool {
        byte_size(element) <= *self.options.get("blockSizeBits").unwrap()
    }

    fn hash_single(&self, data: &str) -> String {
        self.hash(vec![data.to_string(), "".to_string()]).unwrap()
    }

    fn get_genesis(&self) -> String {
        let genesis_str = "brave new world";
        self.hash_single(&genesis_str)
    }
}

impl StarkPedersenHasher {
    pub fn new() -> Self {
        let mut options = HashMap::new();
        options.insert("blockSizeBits".to_string(), 252);
        StarkPedersenHasher { options }
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
