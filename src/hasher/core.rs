use anyhow::Result;
use std::{fmt::Debug, str::FromStr};
use strum_macros::EnumIter;

// Default Hasher Options
pub const DEFAULT_BLOCK_SIZE_BITS: usize = 256;

pub trait Hasher: Send + Sync + Debug {
    fn hash(&self, data: Vec<String>) -> Result<String>;
    fn is_element_size_valid(&self, element: &str) -> bool;
    fn hash_single(&self, data: &str) -> Result<String>;
    fn get_genesis(&self) -> Result<String>;
    fn get_name(&self) -> HashingFunction;
}

#[derive(EnumIter, Debug, PartialEq, Eq, Clone, Copy)]
pub enum HashingFunction {
    Keccak256,
    Poseidon,
    Pedersen,
}

impl FromStr for HashingFunction {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "keccak" => Ok(HashingFunction::Keccak256),
            "poseidon" => Ok(HashingFunction::Poseidon),
            "pedersen" => Ok(HashingFunction::Pedersen),
            _ => Err(anyhow::anyhow!("invalid hashing function")),
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
