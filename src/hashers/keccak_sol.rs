//! Solidity-flavored Keccak-256 hasher (`keccak_sol`).
//!
//! The flavor is the Solidity keccak packing convention: `hash_pair` is
//! keccak over the concatenated 32-byte values; `hash_leaf` is plain keccak
//! over the element, with
//! no size limit — elements of any length are accepted. Both conventions
//! are pinned by golden tests and shared with every verifier of a deployed
//! keccak accumulator; changing either is a breaking change.

use crate::hashers::{Hasher, HasherError, HasherId};
use crate::primitives::Hash;
use alloc::borrow::Cow;
use tiny_keccak::{Hasher as _, Keccak};

/// Solidity-flavored Keccak-256 hasher: `hash_pair` uses the Solidity keccak
/// packing convention, `hash_leaf` is plain keccak over the raw element.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakSolHasher;

/// Keccak-256 over `input`.
pub(crate) fn keccak256(input: &[u8]) -> Hash {
    let mut keccak = Keccak::v256();
    keccak.update(input);
    let mut out = [0; 32];
    keccak.finalize(&mut out);
    Hash::from_bytes(out)
}

impl Hasher for KeccakSolHasher {
    type Output = Hash;

    fn id(&self) -> HasherId {
        HasherId::KeccakSol
    }

    fn config(&self) -> Cow<'static, str> {
        Cow::Borrowed("")
    }

    fn hash_pair(&self, left: Hash, right: Hash) -> Hash {
        let mut input = [0; 64];
        input[..32].copy_from_slice(left.as_bytes());
        input[32..].copy_from_slice(right.as_bytes());
        keccak256(&input)
    }

    fn hash_leaf(&self, element: &[u8]) -> Result<Hash, HasherError> {
        Ok(keccak256(element))
    }

    fn genesis(&self) -> Hash {
        // Pinned: keccak of the seed's ASCII bytes. Keeps the shared
        // `genesis == hash_leaf(GENESIS_SEED)` invariant with the other
        // hashers.
        keccak256(crate::hashers::GENESIS_SEED)
    }
}
