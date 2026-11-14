//! Shared Starknet field-element plumbing for the Poseidon and Pedersen
//! hashers.
//!
//! Both hashers use [`Felt`] as their [`HashValue`] — validity by
//! construction: every value in the system is either produced by the hasher
//! (always in range) or loaded through [`felt_from_bytes_be`], which rejects
//! out-of-range bytes instead of panicking.

use starknet_crypto::Felt;

use crate::primitives::HashValue;

/// Big-endian bytes of the Starknet field modulus
/// `2^251 + 17·2^192 + 1`.
const STARK_MODULUS_BE: [u8; 32] = [
    0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Builds a `Felt` from big-endian bytes, or `None` when the value is at or
/// above the field modulus.
///
/// `Felt::from_bytes_be` panics on out-of-range input; this checked variant
/// is the only way untrusted bytes (store loads, user-supplied values)
/// become felts.
#[must_use]
pub fn felt_from_bytes_be(bytes: &[u8; 32]) -> Option<Felt> {
    if bytes.as_slice() < STARK_MODULUS_BE.as_slice() {
        Some(Felt::from_bytes_be(bytes))
    } else {
        None
    }
}

/// Pads a raw element to 32 big-endian bytes (left zero padding) — the felt
/// interpretation v0.5 gave hex elements.
///
/// # Errors
///
/// [`HasherError::InvalidElementSize`] when the element exceeds 32 bytes,
/// [`HasherError::InvalidFieldElement`] when the padded value is not a valid
/// field element.
pub(crate) fn felt_from_element(element: &[u8]) -> Result<Felt, crate::hashers::HasherError> {
    use crate::hashers::HasherError;

    if element.len() > 32 {
        return Err(HasherError::InvalidElementSize {
            element_size: element.len(),
            block_size_bytes: 32,
            block_size_bits: 252,
        });
    }

    let mut bytes = [0; 32];
    bytes[32 - element.len()..].copy_from_slice(element);
    if element.len() == 32 && felt_from_bytes_be(&bytes).is_none() {
        return Err(HasherError::InvalidFieldElement);
    }
    Ok(Felt::from_bytes_be(&bytes))
}

impl HashValue for Felt {
    const LEN: usize = 32;

    fn from_u64(value: u64) -> Self {
        Felt::from(value)
    }

    fn write_bytes(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_bytes_be());
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let array: [u8; 32] = bytes.try_into().ok()?;
        felt_from_bytes_be(&array)
    }
}
