//! MMR math and the custom-shell seam, outside the main API.
//!
//! Re-exports from the canonical homes — [`crate::mmr::layout`] (the
//! node-index vocabulary's layout math), [`crate::mmr::state`] (the pure
//! state core), [`crate::mmr::proof`] (consistency planning) — so custom
//! shells and standalone verifiers find them all in one place. The main
//! API stays in [`crate::mmr`].

pub use crate::mmr::layout::{
    bag_peaks, largest_mountain, max_peak_height, merges_on_append, path_length, peak_count,
    peak_heights, peaks_of, root_from, sibling_path, size_of,
};
pub use crate::mmr::proof::{
    ConsistencyPlan, PrevSizeRejection, build_sibling_pool, consistency_bridge_nodes,
    consistency_from_loaded, consistency_plan, peak_position,
};
pub use crate::mmr::state::{
    AppendDelta, CounterCheck, Metadata, MmrState, apply_append, apply_append_batch,
    apply_append_many, checked_counters, encode_provenance, parse_provenance, validate_metadata,
};
