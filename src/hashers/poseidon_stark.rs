//! Starknet-flavored Poseidon hasher (`poseidon_stark`).
//!
//! The flavor is the Starknet Poseidon primitives: `hash_pair` maps to
//! `poseidon_hash`; `hash_leaf` maps to
//! `poseidon_hash_single` over the element interpreted as a big-endian
//! field element — malformed elements are rejected, never substituted.
//!
//! The `pad` flag is **validation-only**: it is persisted in
//! [`Hasher::config`] so a reloaded accumulator cannot silently disagree
//! with the hasher that created it, but it has no effect on any output —
//! the stored 32-byte form is identical either way. *Rendering* (felt-width
//! hex vs padded word) is chosen at encode time, by the proof encoding's
//! [`HexStyle`](crate::mmr::proof::encoding::HexStyle), not by this flag.

use crate::hashers::stark::felt_from_element;
use crate::hashers::{Hasher, HasherError, HasherId};
use alloc::borrow::Cow;
use starknet_crypto::{Felt, poseidon_hash, poseidon_hash_single};

/// Starknet Poseidon hasher (`poseidon_stark`).
///
/// The flavor is the Starknet Poseidon primitive set; the persisted `pad`
/// flag only tunes validation/rendering width agreement, never the hash
/// outputs.
#[derive(Clone, Copy, Debug, Default)]
pub struct PoseidonStarkHasher {
    /// Validation-only flag: persisted and checked on open, with no effect
    /// on any output (see the module docs — rendering is an encode-time
    /// choice).
    pub pad: bool,
}

impl Hasher for PoseidonStarkHasher {
    type Output = Felt;

    fn id(&self) -> HasherId {
        HasherId::PoseidonStark
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
        // Pinned: `poseidon_hash_single` over the seed bytes as a
        // big-endian field element.
        poseidon_hash_single(Felt::from_bytes_be(&felt_seed(
            crate::hashers::GENESIS_SEED,
        )))
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
