mod hashers;

#[cfg(feature = "keccak")]
pub use self::hashers::keccak;
#[cfg(feature = "pedersen")]
pub use self::hashers::stark_pedersen;
#[cfg(feature = "poseidon")]
pub use self::hashers::stark_poseidon;

use anyhow::Result;

// Default Hasher Options
pub const DEFAULT_BLOCK_SIZE_BITS: usize = 256;

pub trait Hasher {
    fn hash(&self, data: Vec<String>) -> Result<String>;
    fn is_element_size_valid(&self, element: &str) -> bool;
    fn hash_single(&self, data: &str) -> String;
    fn get_genesis(&self) -> String;
}
