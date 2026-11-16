//! The toolbox: pure math, planning, and the custom-shell seam, outside the
//! main API.
//!
//! Everything here is re-exported from the canonical implementations — no
//! new behavior, no state. The shells and proof handles stay in
//! [`crate::mmr`] / [`crate::merkle`]; use the toolbox when writing a
//! custom shell, a standalone verifier, or capacity planning code.

/// MMR layout math, state transforms, and the MMR side of the custom-shell
/// seam (`mmr` feature).
#[cfg(feature = "mmr")]
pub mod mmr;

/// Merkle-tree heap math, planners, and the tree side of the custom-shell
/// seam (`merkle_tree` feature).
#[cfg(feature = "merkle_tree")]
pub mod merkle;
