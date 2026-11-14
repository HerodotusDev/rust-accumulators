//! Starknet Poseidon hasher.
//!
//! `hash_pair` maps to `poseidon_hash` (the v0.5 two-element path);
//! `hash_leaf` maps to `poseidon_hash_single` over the element interpreted
//! as a big-endian field element — the single fallible entry point replaces
//! the v0.5 `unwrap_or_default`-to-zero bug.
//!
//! The `pad` flag affects output *rendering width* (felt-width hex in the
//! fixed-width encodings), not the stored 32-byte form; it is still part of
//! [`Hasher::config`] so a reloaded accumulator cannot silently disagree
//! with the hasher that created it.

use crate::hashers::stark::felt_from_element;
use crate::hashers::{Hasher, HasherError, HasherId};
use alloc::borrow::Cow;
use starknet_crypto::{Felt, poseidon_hash, poseidon_hash_single};

/// Starknet Poseidon hasher.
#[derive(Clone, Copy, Debug, Default)]
pub struct PoseidonHasher {
    /// Whether felt rendering pads to the full field width.
    pub pad: bool,
}

impl Hasher for PoseidonHasher {
    type Output = Felt;

    fn id(&self) -> HasherId {
        HasherId::Poseidon
    }

    fn config(&self) -> Cow<'static, str> {
        if self.pad {
            Cow::Borrowed("pad=true")
        } else {
            Cow::Borrowed("pad=false")
        }
    }

    fn hash_pair(&self, left: Felt, right: Felt) -> Felt {
        poseidon_hash(left, right)
    }

    fn hash_leaf(&self, element: &[u8]) -> Result<Felt, HasherError> {
        Ok(poseidon_hash_single(felt_from_element(element)?))
    }

    fn genesis(&self) -> Felt {
        // v0.5-pinned: `poseidon_hash_single` over the seed bytes as a
        // big-endian field element.
        poseidon_hash_single(Felt::from_bytes_be(&felt_seed(b"brave new world")))
    }
}

/// Left-pads a short ASCII seed into a felt-sized big-endian buffer.
pub(crate) const fn felt_seed(seed: &[u8]) -> [u8; 32] {
    let mut bytes = [0; 32];
    let mut i = 0;
    while i < seed.len() {
        bytes[32 - seed.len() + i] = seed[i];
        i += 1;
    }
    bytes
}
