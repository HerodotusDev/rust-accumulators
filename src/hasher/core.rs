use std::{fmt::Debug, str::FromStr};
use strum_macros::EnumIter;
use thiserror::Error;

/// Hasher error
#[derive(Error, Debug)]
pub enum HasherError {
    #[error("Invalid hashing function")]
    InvalidHashingFunction,
    #[error("Element {} is size {} bits. It is not of valid size {} bits", .element, .element.len() * 8, .block_size_bits)]
    InvalidElementSize {
        element: String,
        block_size_bits: usize,
    },
    #[error("Invalid elements length for hashing function")]
    InvalidElementsLength,
    #[error("Fail to convert to U256")]
    U256ConversionError,
}

/// A trait for hash functions
pub trait Hasher: Send + Sync + Debug {
    /// Hashes a data which is a vector of strings
    fn hash(&self, data: Vec<String>) -> Result<String, HasherError>;

    /// Checks if the element size is valid, i.e. if it is less than the block size
    fn is_element_size_valid(&self, element: &str) -> bool;

    /// Hashes a single element
    fn hash_single(&self, data: &str) -> Result<String, HasherError>;

    /// Returns the genesis hash
    fn get_genesis(&self) -> Result<String, HasherError>;

    /// Returns the name of the [`HashingFunction`]
    fn get_name(&self) -> HashingFunction;

    /// Returns the block size in bits
    fn get_block_size_bits(&self) -> usize;
}

/// Hashing functions types supported by the hasher
#[derive(EnumIter, Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashingFunction {
    Keccak256,
    Poseidon,
    Pedersen,
}

impl FromStr for HashingFunction {
    type Err = HasherError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "keccak" => Ok(HashingFunction::Keccak256),
            "poseidon" => Ok(HashingFunction::Poseidon),
            "pedersen" => Ok(HashingFunction::Pedersen),
            _ => Err(HasherError::InvalidHashingFunction),
        }
    }
}

impl ToString for HashingFunction {
    fn to_string(&self) -> String {
        match self {
            HashingFunction::Keccak256 => "keccak".to_string(),
            HashingFunction::Poseidon => "poseidon".to_string(),
            HashingFunction::Pedersen => "pedersen".to_string(),
        }
    }
}

/// Returns the byte size of a hex string
pub fn byte_size(hex: &str) -> usize {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex.len() / 2
}
