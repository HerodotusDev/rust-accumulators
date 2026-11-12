//! MMR variants built on top of the core MMR implementation.

/// A draft MMR that operates in memory and can be committed to the backing
/// store or discarded.
#[cfg(feature = "draft_mmr")]
pub mod draft;
/// An MMR stacked on top of other MMRs, routing hash lookups to the sub MMR
/// that holds the requested element.
#[cfg(feature = "stacked_mmr")]
pub mod stacked;
