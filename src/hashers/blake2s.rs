//! Cairo-flavored Blake2s hasher (word-reversed, optional 252-bit
//! truncation).
//!
//! Every 4-byte word of the input is byte-reversed before hashing and every
//! 4-byte word of the digest after — the Cairo memory convention the v0.5
//! hasher implemented. `hash_pair` feeds the two word-reversed values
//! sequentially (the v0.5 two-element path); `hash_leaf` accepts any
//! multiple of 4 bytes.

use crate::hashers::{Hasher, HasherError, HasherId};
use crate::primitives::Hash;
use alloc::borrow::Cow;
use blake2::Digest;

/// Cairo-flavored Blake2s hasher.
#[derive(Clone, Copy, Debug, Default)]
pub struct Blake2sHasher {
    /// Whether to zero the top 4 bits for a 252-bit output.
    pub truncate: bool,
}

/// Reverses each 4-byte word in place (length must be a multiple of 4).
fn reverse_words(bytes: &mut [u8]) {
    for chunk in bytes.as_chunks_mut::<4>().0 {
        chunk.reverse();
    }
}

impl Blake2sHasher {
    /// Shared digest pipeline: word-reversed input, word-reversed output,
    /// optional 252-bit truncation.
    fn digest(self, input: &[u8]) -> Hash {
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(input);
        let mut output = hasher.finalize().to_vec();
        reverse_words(&mut output);
        if self.truncate {
            output[0] &= 0x0f;
        }
        let mut out = [0; 32];
        out.copy_from_slice(&output);
        Hash::from_bytes(out)
    }
}

impl Hasher for Blake2sHasher {
    type Output = Hash;

    fn id(&self) -> HasherId {
        HasherId::Blake2s
    }

    fn config(&self) -> Cow<'static, str> {
        if self.truncate {
            Cow::Borrowed("truncate=true")
        } else {
            Cow::Borrowed("truncate=false")
        }
    }

    fn hash_pair(&self, left: Hash, right: Hash) -> Hash {
        let mut input = [0; 64];
        input[..32].copy_from_slice(left.as_bytes());
        input[32..].copy_from_slice(right.as_bytes());
        reverse_words(&mut input);
        self.digest(&input)
    }

    fn hash_leaf(&self, element: &[u8]) -> Result<Hash, HasherError> {
        if !element.len().is_multiple_of(4) {
            return Err(HasherError::InvalidElementAlignment {
                element_size: element.len(),
                alignment: 4,
            });
        }
        let mut input = alloc::vec::Vec::with_capacity(element.len());
        input.extend_from_slice(element);
        reverse_words(&mut input);
        Ok(self.digest(&input))
    }

    fn genesis(&self) -> Hash {
        // v0.5-pinned: blake2s of the word-reversed seed string (52 bytes,
        // a multiple of 4).
        self.digest(b"Chancellor on the brink of second bailout for banks.")
    }
}
