//! Starknet Pedersen hasher.
//!
//! `hash_pair` maps to the 2-input Pedersen permutation — its only arity, so
//! the v0.5 `hash_single` quirk (hashing `[data, ""]`, a digest no other
//! hasher agreed with) disappears: single-element hashing is
//! [`Hasher::hash_leaf`]'s job, defined here as `pedersen(element, 0)`.

use crate::hashers::stark::felt_from_element;
use crate::hashers::{Hasher, HasherError, HasherId};
use alloc::borrow::Cow;
use starknet_crypto::{Felt, pedersen_hash};

/// Starknet Pedersen hasher.
#[derive(Clone, Copy, Debug, Default)]
pub struct PedersenHasher;

impl Hasher for PedersenHasher {
    type Output = Felt;

    fn id(&self) -> HasherId {
        HasherId::Pedersen
    }

    fn config(&self) -> Cow<'static, str> {
        Cow::Borrowed("")
    }

    fn hash_pair(&self, left: Felt, right: Felt) -> Felt {
        pedersen_hash(&left, &right)
    }

    fn hash_leaf(&self, element: &[u8]) -> Result<Felt, HasherError> {
        // v0.5's `hash_single` hashed `[data, ""]` and could not even parse
        // the empty string; `pedersen(element, 0)` is the defined, documented
        // single-element form for this hasher.
        Ok(pedersen_hash(&felt_from_element(element)?, &Felt::ZERO))
    }

    fn genesis(&self) -> Felt {
        // v0.5's Pedersen genesis was unreachable (its seed string was not
        // hex); defined here as the leaf hash of the shared seed.
        self.hash_leaf(b"brave new world")
            .expect("the genesis seed is a valid field element")
    }
}
