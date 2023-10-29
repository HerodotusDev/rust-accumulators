mod keccak;
pub mod stark_pedersen;
pub mod stark_poseidon;
// Default Hasher Options
pub const DEFAULT_BLOCK_SIZE_BITS: usize = 256;

use anyhow::Result;

pub trait IHasher {
    fn hash(&self, data: Vec<String>) -> Result<String>;
    fn is_element_size_valid(&self, element: &str) -> bool;
    fn hash_single(&self, data: &str) -> String;
    fn get_genesis(&self) -> String;
}
