use primitive_types::U256;
use starknet::core::{crypto::pedersen_hash, types::FieldElement};

use crate::hasher::{byte_size, HasherError, HashingFunction};

use super::super::Hasher;

/// Hasher for Stark Pedersen
#[derive(Debug, Clone)]
pub struct StarkPedersenHasher {
    /// The block size in bits for Stark Pedersen is 252
    block_size_bits: usize,
}

impl Hasher for StarkPedersenHasher {
    fn get_name(&self) -> HashingFunction {
        HashingFunction::Pedersen
    }

    /// Hashes a data which is a vector of strings
    ///
    /// NOTE: data should be of size 2
    fn hash(&self, data: Vec<String>) -> Result<String, HasherError> {
        if data.len() != 2 {
            return Err(HasherError::InvalidElementsLength);
        }

        for element in &data {
            self.is_element_size_valid(element)?;
        }

        let mut clean_data = Vec::with_capacity(data.len());
        for s in data.iter() {
            let number_str = if let Some(stripped) = s.strip_prefix("0x") {
                U256::from_str_radix(stripped, 16)
            } else {
                U256::from_str_radix(s, 16)
            };

            match number_str {
                Ok(number) => clean_data.push(number.to_string()),
                Err(_) => return Err(HasherError::U256ConversionError),
            }
        }

        let result = pedersen_hash(
            &FieldElement::from_dec_str(&clean_data[0]).unwrap_or_default(),
            &FieldElement::from_dec_str(&clean_data[1]).unwrap_or_default(),
        )
        .to_string();

        let computed_result =
            U256::from_dec_str(result.trim()).map_err(|_| HasherError::U256ConversionError)?;
        let padded_hex_str = format!("0x{:064x}", computed_result);

        Ok(padded_hex_str)
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

    fn hash_single(&self, data: &str) -> Result<String, HasherError> {
        self.hash(vec![data.to_string(), "".to_string()])
    }

    fn get_genesis(&self) -> Result<String, HasherError> {
        let genesis_str = "brave new world";
        self.hash_single(genesis_str)
    }

    fn get_block_size_bits(&self) -> usize {
        self.block_size_bits
    }
}

impl StarkPedersenHasher {
    pub fn new() -> Self {
        Self {
            block_size_bits: 252,
        }
    }
}

impl Default for StarkPedersenHasher {
    fn default() -> Self {
        Self::new()
    }
}
