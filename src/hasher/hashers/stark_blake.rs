use std::str::FromStr;

use blake2::{Blake2s256, Digest};
use num_bigint::BigInt;

use super::super::Hasher;
use crate::hasher::{byte_size, HasherError, HashingFunction};

/// Hasher for Cairo variant of Blake2s
#[derive(Debug, Clone)]
pub struct StarkBlakeHasher {
    /// Boolean flag to indicate whether to zero first 4 bits of the hash
    truncate: bool,
}

impl Hasher for StarkBlakeHasher {
    fn get_name(&self) -> HashingFunction {
        HashingFunction::Blake
    }

    /// Hashes a data which is a vector of strings
    ///
    /// NOTE: data have no limit in length of elements
    fn hash(&self, data: Vec<String>) -> Result<String, HasherError> {
        let mut hasher = Blake2s256::new();

        for element in data {
            let mut bytes = match element.strip_prefix("0x") {
                Some(no_prefix) => {
                    let bytes =
                        hex::decode(no_prefix).map_err(|_| HasherError::InvalidElementsLength)?;
                    if bytes.len() % 4 != 0 {
                        return Err(HasherError::InvalidElementSize {
                            element_size: bytes.len(),
                            block_size_bits: self.get_block_size_bits(),
                        });
                    }
                    bytes
                }
                None => {
                    // Parse decimal
                    let bigint = BigInt::from_str(&element).unwrap();
                    let hex = format!(
                        "{:0>width$}",
                        bigint.to_str_radix(16),
                        width = self.get_block_size_bits() / 4
                    );
                    hex::decode(hex).unwrap()
                }
            };
            // Iterate over 4-byte words and reverse byte order within each word
            bytes.chunks_exact_mut(4).for_each(|chunk| chunk.reverse());
            hasher.update(&bytes);
        }

        let mut output = hasher.finalize().to_vec();
        // Iterate over 4-byte words and reverse byte order within each word
        output.chunks_exact_mut(4).for_each(|chunk| chunk.reverse());

        if self.truncate {
            // Zero first 4 bits of the hash so that we have only 252 significant bits
            output[0] &= 0x0f
        }

        let hash = format!("0x{}", hex::encode(output));
        Ok(hash)
    }

    fn is_element_size_valid(&self, element: &str) -> Result<bool, HasherError> {
        let size = byte_size(element);
        if size <= self.get_block_size_bits() / 8 {
            Ok(true)
        } else {
            Err(HasherError::InvalidElementSize {
                element_size: size,
                block_size_bits: self.get_block_size_bits(),
            })
        }
    }

    fn hash_single(&self, data: &str) -> Result<String, HasherError> {
        self.hash(vec![data.to_string()])
    }

    fn get_genesis(&self) -> Result<String, HasherError> {
        let genesis_str = "Chancellor on the brink of second bailout for banks.";
        let hex_str = format!("0x{}", hex::encode(genesis_str));
        self.hash_single(&hex_str)
    }

    fn get_block_size_bits(&self) -> usize {
        // NOTE that this is not the absorbtion block size (which is 512 for Blake2s256)
        256
    }
}

impl StarkBlakeHasher {
    pub fn new(truncate: bool) -> Self {
        Self { truncate }
    }
}

impl Default for StarkBlakeHasher {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2s_hasher_empty() {
        let hasher = StarkBlakeHasher::new(false);
        let hash = hasher.hash(vec![]).unwrap();
        assert_eq!(
            hash,
            "0x307a216994809079d02111e17c4a354248b6551f1ea5a12cfd0d251bf9eed01e"
        );
    }

    #[test]
    fn test_blake2s_hasher() {
        let hasher = StarkBlakeHasher::new(false);
        let hash = hasher
            .hash(vec![
                "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
            ])
            .unwrap();
        assert_eq!(
            hash,
            "0xa95e0b32c23b659e41db93b54e0ad1304c0b3afd67a6e1c2718d672bad33bddf"
        );
    }

    #[test]
    fn test_blake2s_hasher_long() {
        let hasher = StarkBlakeHasher::new(false);
        let hash = hasher.hash(vec!["0xc713e33d89122b85e2f646cc518c2e6ef88b06d3b016104faa95f84f878dab66c713e33d89122b85e2f646cc518c2e6ef88b06d3b016104faa95f84f878dab66".into()]).unwrap();
        assert_eq!(
            hash,
            "0x693aa1ab81c6362fe339fc4c7f6d8ddb1e515701e58c5bb2fb54a193c8287fdc"
        );
    }

    #[test]
    fn test_blake2s_hasher_pair() {
        let hasher = StarkBlakeHasher::new(false);
        let hash = hasher
            .hash(vec![
                "0xc713e33d89122b85e2f646cc518c2e6ef88b06d3b016104faa95f84f878dab66".into(),
                "0xc713e33d89122b85e2f646cc518c2e6ef88b06d3b016104faa95f84f878dab66".into(),
            ])
            .unwrap();
        assert_eq!(
            hash,
            "0x693aa1ab81c6362fe339fc4c7f6d8ddb1e515701e58c5bb2fb54a193c8287fdc"
        );
    }

    #[test]
    fn test_blake2s_hasher_truncate() {
        let hasher = StarkBlakeHasher::new(true);
        let hash = hasher
            .hash(vec![
                "0x0000000000000000000000000000000000000000000000000000000000000000".into(),
            ])
            .unwrap();
        assert_eq!(
            hash,
            "0x095e0b32c23b659e41db93b54e0ad1304c0b3afd67a6e1c2718d672bad33bddf"
        );
    }

    #[test]
    fn test_blake2s_hasher_multiple_elements() {
        let hasher = StarkBlakeHasher::new(false);
        let data1: Vec<String> = vec![
            "0x00000001".into(),
            "0x000000002a22cfee1f2c846adbd12b3e183d4f97683f85dad08a79780a84bd55".into(),
            "0x7dac2c5666815c17a3b36427de37bb9d2e2c5ccec3f8633eb91a4205cb4c10ff".into(),
            "0x496ab951".into(),
            "0x1d00ffff".into(),
            "0x709e3e28".into(),
        ];
        let hash1 = hasher.hash(data1.clone()).unwrap();
        let data2: String = data1
            .clone()
            .iter()
            .map(|e| e.strip_prefix("0x").unwrap_or(e).to_string())
            .reduce(|acc, e| format!("{acc}{e}"))
            .unwrap();
        let data2 = vec![format!("0x{}", data2)];
        let hash2 = hasher.hash(data2).unwrap();
        assert_eq!(hash1, hash2);
        assert_eq!(
            hash2,
            "0x0fcf8d89df790c8b0626b1ce495e22aca80b9332760b3c7bf9f46b7dd3b35556"
        );
    }
}
