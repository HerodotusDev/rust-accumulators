use starknet_types_core::felt::FromStrError;
use std::{
    fmt::{self, Debug},
    str::FromStr,
};
use thiserror::Error;

/// Errors returned by [`Hasher`] implementations.
#[derive(Error, Debug)]
pub enum HasherError {
    /// The given name does not match any supported [`HashingFunction`].
    #[error("Invalid hashing function")]
    InvalidHashingFunction,
    /// An element is too large for the block size of the hashing function.
    #[error(
        "Element size {element_size} is too big for hashing function with block size {block_size_bits}"
    )]
    InvalidElementSize {
        /// Size of the element in bytes.
        element_size: usize,
        /// Block size of the hashing function in bits.
        block_size_bits: usize,
    },
    /// The number of elements is not valid for the requested hash.
    #[error("Invalid elements length for hashing function")]
    InvalidElementsLength,
    /// A hex-encoded element could not be decoded.
    #[error("Fail to decode hex")]
    HexDecodeError(#[from] hex::FromHexError),
    /// A string could not be parsed as a big integer.
    #[error("Fail to parse bigint: {0}")]
    BigintParseError(#[from] num_bigint::ParseBigIntError),
    /// A string could not be converted to a field element (`Felt`).
    #[error("Fail to convert to felt")]
    FeltConversionError(#[from] FromStrError),
}

/// A trait for hash functions
pub trait Hasher: Send + Sync + Debug {
    /// Hashes a list of elements.
    ///
    /// Elements are hex-encoded (with or without a `0x` prefix) or decimal
    /// strings, depending on the implementation.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError`] if the elements cannot be parsed or do not
    /// satisfy the size and length requirements of the hasher.
    fn hash(&self, data: Vec<String>) -> Result<String, HasherError>;

    /// Checks whether the element size is valid, i.e. whether it fits in the
    /// block size of the hasher.
    ///
    /// An element that is too large is reported as an error rather than
    /// `Ok(false)`.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError::InvalidElementSize`] if the element exceeds the
    /// block size.
    fn is_element_size_valid(&self, element: &str) -> Result<bool, HasherError>;

    /// Hashes a single element.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError`] if the element cannot be parsed or hashed.
    fn hash_single(&self, data: &str) -> Result<String, HasherError>;

    /// Returns the genesis hash, computed by hashing a fixed seed string.
    ///
    /// # Errors
    ///
    /// Returns [`HasherError`] if hashing the seed fails.
    fn get_genesis(&self) -> Result<String, HasherError>;

    /// Returns the name of the [`HashingFunction`]
    fn get_name(&self) -> HashingFunction;

    /// Returns the block size in bits
    fn get_block_size_bits(&self) -> usize;
}

/// Hashing functions supported by the hashers
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum HashingFunction {
    /// Keccak256.
    Keccak256,
    /// Starknet Poseidon.
    Poseidon,
    /// Starknet Pedersen.
    Pedersen,
    /// Cairo variant of Blake2s.
    Blake,
}

impl FromStr for HashingFunction {
    type Err = HasherError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "keccak" => Ok(HashingFunction::Keccak256),
            "poseidon" => Ok(HashingFunction::Poseidon),
            "pedersen" => Ok(HashingFunction::Pedersen),
            "blake" => Ok(HashingFunction::Blake),
            _ => Err(HasherError::InvalidHashingFunction),
        }
    }
}

impl fmt::Display for HashingFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashingFunction::Keccak256 => write!(f, "keccak"),
            HashingFunction::Poseidon => write!(f, "poseidon"),
            HashingFunction::Pedersen => write!(f, "pedersen"),
            HashingFunction::Blake => write!(f, "blake"),
        }
    }
}

/// Returns the byte size of a hex string
#[must_use]
pub fn byte_size(hex: &str) -> usize {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    hex.len() / 2
}
