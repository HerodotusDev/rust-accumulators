//! Merkle-tree math and the custom-shell seam, outside the main API.
//!
//! Re-exports the tree's pure math from [`crate::merkle::math`] (heap-index
//! algebra, metadata codecs, write/proof planners) plus the
//! [`ZeroLadder`](crate::merkle::ZeroLadder) that makes unoccupied siblings
//! computable. Custom shells
//! run the exact code paths of the built-in ones; the main API stays in
//! [`crate::merkle`].

pub use crate::merkle::ZeroLadder;
pub use crate::merkle::math::{
    SetPlan, build_multiproof, build_proof, check_depth, check_index, create_batch,
    heap_level_and_index, leaf_heap, metadata_keys, multiproof_walk, parse_node_value,
    plan_multiproof, plan_set, proof_read_heaps, set_read_heaps, validate_metadata,
};
