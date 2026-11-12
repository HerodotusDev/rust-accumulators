//! Hashing functions used by the accumulators.
//!
//! The [`Hasher`] trait defines the interface the accumulators rely on, and
//! [`HashingFunction`] enumerates the supported algorithms: Keccak256,
//! Poseidon, Pedersen, and the Cairo variant of Blake2s.

mod core;
pub use self::core::*;

mod hashers;
#[allow(unused_imports)]
pub use self::hashers::*;
