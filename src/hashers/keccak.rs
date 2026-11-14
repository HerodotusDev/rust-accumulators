//! Solidity-compatible Keccak-256 hasher.
//!
//! `hash_pair` is keccak over the concatenated 32-byte values (the "solidity
//! packing" convention, matching the v0.5 behavior and its golden tests);
//! `hash_leaf` is plain keccak over the element, with no size limit —
//! matching the v0.5 hasher, which deliberately skipped size validation to
//! allow hashing RLP-encoded blocks.

use crate::hashers::{Hasher, HasherError, HasherId};
use crate::primitives::Hash;
use alloc::borrow::Cow;
use tiny_keccak::{Hasher as _, Keccak};

/// Solidity-compatible Keccak-256 hasher.
///
/// The type alias [`SolKeccak`] exists so call sites can spell the intent
/// explicitly.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keccak256Hasher;

/// Explicit alias — same hasher, named for the Solidity convention it models.
pub type SolKeccak = Keccak256Hasher;

/// Keccak-256 over `input`.
pub(crate) fn keccak256(input: &[u8]) -> Hash {
    let mut keccak = Keccak::v256();
    keccak.update(input);
    let mut out = [0; 32];
    keccak.finalize(&mut out);
    Hash::from_bytes(out)
}

impl Hasher for Keccak256Hasher {
    type Output = Hash;

    fn id(&self) -> HasherId {
        HasherId::Keccak256
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
        // v0.5-pinned: keccak of the ASCII seed, exactly as `get_genesis`
        // computed it (hex of the seed, then keccak of the decoded bytes).
        keccak256(b"brave new world")
    }
}
