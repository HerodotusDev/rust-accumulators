use starknet::core::crypto::pedersen_hash;
use starknet_crypto::Felt;

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

    fn hash(&self, data: Vec<String>) -> Result<String, HasherError> {
        if data.len() < 2 {
            return Err(HasherError::InvalidElementsLength);
        }

        let mut elements = data.into_iter();
        let mut hash = elements.next().unwrap();
        for element in elements {
            hash = self.internal_hash(vec![hash, element])?;
        }

        Ok(hash)
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
    /// Hashes a data which is a vector of hex strings
    ///
    /// NOTE: data should be of size 2
    fn internal_hash(&self, data: Vec<String>) -> Result<String, HasherError> {
        if data.len() != 2 {
            return Err(HasherError::InvalidElementsLength);
        }

        for element in &data {
            self.is_element_size_valid(element)?;
        }

        let result =
            pedersen_hash(&Felt::from_hex(&data[0])?, &Felt::from_hex(&data[1])?).to_bytes_be();

        let padded_hex_str = format!("0x{:0>64}", hex::encode(result));
        Ok(padded_hex_str)
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stark_pedersen_hasher_cairo_playground_reference_1() {
        let hasher = StarkPedersenHasher::new();
        let data = vec![
            // 314
            "0x13a".to_string(),
            // 159
            "0x9f".to_string(),
        ];
        let hash = hasher.hash(data).unwrap();
        assert_eq!(
            hash,
            // 307958720726328212653290369969069617958360335228383070119367204176047090109
            "0x00ae4c67cf8deb4f68f6bad0ce61be81097cf082b4bfa83c637af99a978fa9bd",
            "Hashes do not match"
        );
    }

    #[test]
    fn test_stark_pedersen_hasher_cairo_playground_reference_2() {
        let hasher = StarkPedersenHasher::new();
        let data = vec![
            // 314
            "0x13a".to_string(),
            // 159
            "0x9f".to_string(),
            // 265
            "0x109".to_string(),
            // 358
            "0x166".to_string(),
        ];
        let hash = hasher.hash(data).unwrap();
        assert_eq!(
            hash,
            // 1828757374677754028678056220799392919487521050857166686061558043629802016816
            "0x040b0a3d05cf798d507d2b4b2725bb28b00d16c0ceefa2222aa04cc88518d030",
            "Hashes do not match"
        );
    }
}
