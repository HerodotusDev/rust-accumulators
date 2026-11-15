//! Starknet-flavored Pedersen hasher (`pedersen_stark`).
//!
//! The flavor is the Starknet Pedersen primitive:
//! `hash_pair` maps to the 2-input Pedersen permutation — its only arity.
//! Single-element hashing is [`Hasher::hash_leaf`]'s job, defined here as
//! `pedersen(element, 0)`. Both conventions are pinned; changing either is
//! a breaking change.

use crate::hashers::stark::felt_from_element;
use crate::hashers::{Hasher, HasherError, HasherId};
use alloc::borrow::Cow;
use starknet_crypto::{Felt, pedersen_hash};

/// Starknet Pedersen hasher (`pedersen_stark`).
#[derive(Clone, Copy, Debug, Default)]
pub struct PedersenStarkHasher;

impl Hasher for PedersenStarkHasher {
    type Output = Felt;

    fn id(&self) -> HasherId {
        HasherId::PedersenStark
    }

    fn config(&self) -> Cow<'static, str> {
        Cow::Borrowed("")
    }

    fn hash_pair(&self, left: Felt, right: Felt) -> Felt {
        pedersen_hash(&left, &right)
    }

    fn hash_leaf(&self, element: &[u8]) -> Result<Felt, HasherError> {
        // The defined single-element form: `pedersen(element, 0)`.
        Ok(pedersen_hash(&felt_from_element(element)?, &Felt::ZERO))
    }

    fn genesis(&self) -> Felt {
        // Defined as the leaf hash of the shared seed, keeping the
        // `genesis == hash_leaf(seed)` invariant shared by the other
        // hashers.
        #[expect(
            clippy::expect_used,
            reason = "the genesis seed is a compile-time constant, proven a valid field element"
        )]
        self.hash_leaf(crate::hashers::GENESIS_SEED)
            .expect("the genesis seed is a valid field element")
    }
}
