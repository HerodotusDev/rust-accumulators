//! Layout-math tests: index types and the pure MMR layout functions checked
//! against a brute-force reference built by the incremental
//! append-then-merge procedure.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
use accumulators::hashers::{Hasher, KeccakSolHasher};
use accumulators::mmr::{Height, LeafCount, MmrSize, NodeIndex, Side};
use accumulators::primitives::{Hash, LeafIndex, MAX_LEAF_COUNT};
use accumulators::utils::mmr::{
    bag_peaks, largest_mountain, max_peak_height, merges_on_append, path_length, peak_count,
    peak_heights, peaks_of, root_from, sibling_path, size_of,
};

/// Vector slot for a 1-based node index.
fn slot(node: u64) -> usize {
    usize::try_from(node - 1).expect("node counts must fit usize")
}

/// A brute-force MMR: built by literally appending leaves and merging
/// equal-height peaks, recording every node's height and parent.
struct BruteMmr {
    /// `heights[slot(n)]` is the height of node `n`.
    heights: Vec<u8>,
    /// `parents[slot(n)]` is the parent of node `n`, or `None` while it is a
    /// peak (set once a later merge consumes it).
    parents: Vec<Option<u64>>,
    /// `leaf_of_node[slot(n)]` is the leaf index wrapped by leaf node `n`,
    /// or `None` for merge-created interior nodes.
    leaf_of_node: Vec<Option<u64>>,
    /// Peaks of the current MMR as `(node, height)`, left to right.
    peaks: Vec<(u64, u8)>,
    /// `peak_snapshots[l]` is the peak list of the MMR with `l` leaves.
    peak_snapshots: Vec<Vec<(u64, u8)>>,
    /// `merge_history[l]` is the number of merges triggered by appending the
    /// leaf at index `l` — the append that grows an `l`-leaf MMR.
    merge_history: Vec<u64>,
}

impl BruteMmr {
    /// Builds an MMR by appending `leaves` leaves.
    fn build(leaves: u64) -> Self {
        let mut mmr = Self {
            heights: Vec::new(),
            parents: Vec::new(),
            leaf_of_node: Vec::new(),
            peaks: Vec::new(),
            peak_snapshots: vec![Vec::new()],
            merge_history: Vec::new(),
        };
        for _ in 0..leaves {
            mmr.append_leaf();
        }
        mmr
    }

    /// Appends the next leaf: one new leaf node, then merges while the top
    /// two peaks share a height — the structural definition of the merge rule.
    fn append_leaf(&mut self) {
        let leaf = u64::try_from(self.merge_history.len()).expect("leaf counts fit u64");
        let node = 2 * leaf + 1 - u64::from(leaf.count_ones());
        assert_eq!(
            slot(node),
            self.heights.len(),
            "leaf {leaf} must occupy the next contiguous node slot"
        );
        self.heights.push(0);
        self.parents.push(None);
        self.leaf_of_node.push(Some(leaf));
        self.peaks.push((node, 0));
        self.merge_history.push(0);

        while self.peaks.len() >= 2 {
            let right = self.peaks[self.peaks.len() - 1];
            let left = self.peaks[self.peaks.len() - 2];
            if left.1 != right.1 {
                break;
            }
            let parent = u64::try_from(self.heights.len() + 1).expect("node counts fit u64");
            self.heights.push(right.1 + 1);
            self.parents.push(None);
            self.leaf_of_node.push(None);
            self.parents[slot(left.0)] = Some(parent);
            self.parents[slot(right.0)] = Some(parent);
            self.peaks.pop();
            self.peaks.pop();
            self.peaks.push((parent, right.1 + 1));
            *self.merge_history.last_mut().expect("just pushed") += 1;
        }

        self.peak_snapshots.push(self.peaks.clone());
    }
}

/// The structure-derived sibling path of `leaf`: climb recorded parents until
/// the node is a peak of the `size`-node MMR, reading each sibling off the
/// child geometry (left child of the parent = `parent − 1`, right child =
/// `parent − 2^(h+1)`). Also returns the mountain peak's height, which is the
/// path length.
fn brute_sibling_path(brute: &BruteMmr, leaf: u64, size: u64) -> (Vec<(u64, Side)>, u8) {
    let mut node = 2 * leaf + 1 - u64::from(leaf.count_ones());
    let mut steps = Vec::new();
    loop {
        let parent = match brute.parents[slot(node)] {
            Some(candidate) if candidate <= size => candidate,
            _ => return (steps, brute.heights[slot(node)]),
        };
        let height = brute.heights[slot(node)];
        if parent == node + 1 {
            let sibling = parent - (1 << (height + 1));
            assert!(
                (1..=size).contains(&sibling),
                "left sibling {sibling} of node {node} must exist at size {size}"
            );
            assert_eq!(
                brute.heights[slot(sibling)],
                height,
                "siblings must share a height"
            );
            steps.push((sibling, Side::Left));
        } else {
            let sibling = parent - 1;
            assert!(
                (1..=size).contains(&sibling),
                "right sibling {sibling} of node {node} must exist at size {size}"
            );
            assert_eq!(
                brute.heights[slot(sibling)],
                height,
                "siblings must share a height"
            );
            steps.push((sibling, Side::Right));
        }
        node = parent;
    }
}

/// Verifies `height` / `parent` / `as_leaf` of every node in the built
/// structure. Peaks (never merged) must report the geometric left-child
/// parent `n + 2^(h+1)` — a continuation always merges them as the left
/// operand, because the right operand of a merge is always the last node.
fn assert_node_structure(brute: &BruteMmr) {
    for index in 0..brute.heights.len() {
        let value = u64::try_from(index + 1).expect("node counts fit u64");
        let node = NodeIndex::try_new(value).expect("node indexes are nonzero");
        assert_eq!(
            node.height().get(),
            brute.heights[index],
            "height of node {value}"
        );

        let expected_parent = match brute.parents[index] {
            Some(parent) => NodeIndex::try_new(parent).expect("parents are valid nodes"),
            None => NodeIndex::try_new(value + (1 << (u32::from(brute.heights[index]) + 1)))
                .expect("geometric parent of a peak"),
        };
        assert_eq!(
            node.parent(),
            Some(expected_parent),
            "parent of node {value}"
        );

        if brute.heights[index] == 0 {
            let leaf = brute.leaf_of_node[index].expect("leaf nodes record their leaf");
            assert_eq!(
                node.as_leaf(),
                Some(LeafIndex::new(leaf)),
                "node {value} must wrap leaf {leaf}"
            );
        } else {
            assert_eq!(node.as_leaf(), None, "node {value} must not be a leaf");
        }
    }
}

/// Verifies every layout function against the brute-force structure at a
/// given leaf count (any count up to what was built).
fn assert_layout_at(brute: &BruteMmr, leaves: u64) {
    let size = size_of(LeafCount::new(leaves));
    let reconstructed = MmrSize::try_new(size.get()).expect("size_of always yields a valid size");
    assert_eq!(
        reconstructed
            .leaf_count()
            .expect("valid sizes have leaf counts")
            .get(),
        leaves,
        "size {} must round-trip to {leaves} leaves",
        size.get()
    );

    let snapshot = &brute.peak_snapshots[usize::try_from(leaves).expect("leaf counts fit usize")];
    let expected_peaks: Vec<u64> = snapshot.iter().map(|(node, _)| *node).collect();
    let expected_heights: Vec<u8> = snapshot.iter().map(|(_, height)| *height).collect();
    assert_eq!(
        peaks_of(size)
            .into_iter()
            .map(NodeIndex::get)
            .collect::<Vec<_>>(),
        expected_peaks,
        "peaks of an MMR with {leaves} leaves"
    );
    assert_eq!(
        peak_heights(size)
            .into_iter()
            .map(Height::get)
            .collect::<Vec<_>>(),
        expected_heights,
        "peak heights of an MMR with {leaves} leaves"
    );

    // The closed forms over the same snapshot: peak count is the popcount,
    // the tallest peak is the first mountain, and the largest mountain is
    // that height as a power of two.
    assert_eq!(
        peak_count(size) as usize,
        expected_peaks.len(),
        "peak count of an MMR with {leaves} leaves"
    );
    assert_eq!(
        max_peak_height(size).get(),
        expected_heights.first().copied().unwrap_or(0),
        "the tallest peak of an MMR with {leaves} leaves"
    );
    if leaves == 0 {
        assert_eq!(largest_mountain(0), 0, "no leaves, no mountain");
    } else {
        assert_eq!(
            largest_mountain(leaves),
            1_u64 << u32::from(expected_heights[0]),
            "the largest mountain at {leaves} leaves"
        );
    }

    for leaf in 0..leaves {
        let (expected_steps, peak_height) = brute_sibling_path(brute, leaf, size.get());
        let actual: Vec<(u64, Side)> = sibling_path(LeafIndex::new(leaf), size)
            .into_iter()
            .map(|step| (step.sibling.get(), step.side))
            .collect();
        assert_eq!(
            actual, expected_steps,
            "sibling path of leaf {leaf} at {leaves} leaves"
        );
        assert_eq!(
            actual.len(),
            usize::from(peak_height),
            "path length of leaf {leaf} must equal its mountain's peak height"
        );
        assert_eq!(
            path_length(LeafIndex::new(leaf), size) as usize,
            actual.len(),
            "the closed-form path length of leaf {leaf} at {leaves} leaves"
        );
    }
}

mod index_types {
    use super::*;

    #[test]
    fn zero_is_not_a_valid_node_index() {
        assert!(NodeIndex::try_new(0).is_none(), "the node space is 1-based");
        assert_eq!(NodeIndex::try_new(1), Some(NodeIndex::FIRST));
    }

    #[test]
    fn leaf_node_positions_follow_the_gap_formula() {
        let expected = [(0, 1), (1, 2), (2, 4), (3, 5), (4, 8), (7, 12)];
        for (leaf, node) in expected {
            assert_eq!(
                LeafIndex::new(leaf).node().get(),
                node,
                "leaf {leaf}'s node"
            );
        }
    }

    #[test]
    fn zero_constants_are_sane() {
        assert_eq!(LeafIndex::FIRST.get(), 0);
        assert_eq!(LeafCount::ZERO.get(), 0);
        assert_eq!(MmrSize::ZERO.get(), 0);
        assert_eq!(Height::LEAF.get(), 0);
    }

    #[test]
    fn index_display_is_the_raw_number() {
        assert_eq!(NodeIndex::try_new(12).expect("nonzero").to_string(), "12");
        assert_eq!(LeafIndex::new(3).to_string(), "3");
    }

    #[test]
    fn max_leaf_count_is_the_u64_safe_bound() {
        assert_eq!(MAX_LEAF_COUNT, (1 << 63) - 1, "2i + 1 must stay within u64");
        assert_eq!(
            merges_on_append(LeafCount::new(MAX_LEAF_COUNT)),
            63,
            "an all-ones count merges maximally"
        );
    }
}

mod size_accounting {
    use super::*;

    #[test]
    fn size_of_follows_two_l_minus_popcount_up_to_600() {
        for leaves in 0..=600_u64 {
            let expected = 2 * leaves - u64::from(leaves.count_ones());
            assert_eq!(
                size_of(LeafCount::new(leaves)).get(),
                expected,
                "size_of({leaves})"
            );
        }
    }

    #[test]
    fn merges_on_append_are_the_trailing_ones() {
        for leaves in 0..=600_u64 {
            assert_eq!(
                merges_on_append(LeafCount::new(leaves)),
                u64::from(leaves.trailing_ones()),
                "appending to a {leaves}-leaf MMR"
            );
        }
    }

    #[test]
    fn new_unchecked_skips_validation() {
        let invalid = MmrSize::new_unchecked(2);
        assert!(
            invalid.leaf_count().is_none(),
            "size 2 is not a well-formed MMR"
        );
        assert!(MmrSize::try_new(2).is_none());
        assert!(MmrSize::try_new(6).is_none());
        assert!(MmrSize::try_new(100).is_none());
        assert!(MmrSize::try_new(1).is_some(), "size 1 is a single-leaf MMR");
    }
}

mod brute_force_layout {
    use super::*;

    #[test]
    fn the_empty_mmr_has_no_peaks_and_no_paths() {
        assert_eq!(
            peaks_of(MmrSize::ZERO),
            Vec::new(),
            "the empty MMR has no peaks"
        );
        assert_eq!(
            peak_heights(MmrSize::ZERO),
            Vec::new(),
            "the empty MMR has no peak heights"
        );
        assert_eq!(
            sibling_path(LeafIndex::FIRST, MmrSize::ZERO),
            Vec::new(),
            "the empty MMR has no paths"
        );

        let zero = MmrSize::try_new(0).expect("size 0 is the empty MMR");
        assert_eq!(zero.leaf_count().expect("size 0 has a leaf count").get(), 0);
        assert_eq!(size_of(LeafCount::ZERO), MmrSize::ZERO);
        assert_eq!(merges_on_append(LeafCount::ZERO), 0);

        let single = MmrSize::try_new(1).expect("a single leaf is well-formed");
        assert!(
            sibling_path(LeafIndex::FIRST, single).is_empty(),
            "a lone leaf has no in-mountain sibling"
        );
        assert!(
            sibling_path(LeafIndex::new(1), single).is_empty(),
            "leaves at or past the size have no path"
        );
    }

    #[test]
    fn node_structure_matches_brute_force_up_to_600_leaves() {
        assert_node_structure(&BruteMmr::build(601));
    }

    #[test]
    fn children_compose_with_parents_up_to_600_leaves() {
        let brute = BruteMmr::build(601);
        for index in 0..brute.heights.len() {
            let value = u64::try_from(index + 1).expect("node counts fit u64");
            let node = NodeIndex::try_new(value).expect("node indexes are nonzero");
            let height = brute.heights[index];

            // Leaf nodes have phantom children — no index names them.
            if height == 0 {
                assert_eq!(node.left_child(), None, "leaf node {value} has no children");
                assert_eq!(
                    node.right_child(),
                    None,
                    "leaf node {value} has no children"
                );
                continue;
            }

            let left = node.left_child().expect("internal nodes have children");
            let right = node.right_child().expect("internal nodes have children");
            assert_eq!(
                u64::from(left.height().get()),
                u64::from(height) - 1,
                "the left child of node {value} sits one level down"
            );
            assert_eq!(
                u64::from(right.height().get()),
                u64::from(height) - 1,
                "the right child of node {value} sits one level down"
            );
            assert_eq!(right.get(), value - 1, "the right child is n − 1");
            assert_eq!(
                left.parent(),
                Some(node),
                "the left child of {value} climbs back to it"
            );
            assert_eq!(
                right.parent(),
                Some(node),
                "the right child of {value} climbs back to it"
            );

            // A recorded parent edge must invert through the matching child
            // accessor: the parent of a right child is n + 1; any other
            // recorded parent makes the node its left child.
            if let Some(parent) = brute.parents[index] {
                let parent_node =
                    NodeIndex::try_new(parent).expect("recorded parents are valid nodes");
                let expected_child = if parent == value + 1 {
                    parent_node.right_child()
                } else {
                    parent_node.left_child()
                };
                assert_eq!(
                    expected_child,
                    Some(node),
                    "the recorded edge {parent} → {value} must invert"
                );
            }
        }
    }

    #[test]
    fn layout_math_matches_brute_force_for_every_size_up_to_600_leaves() {
        let brute = BruteMmr::build(601);
        assert_eq!(
            u64::try_from(brute.heights.len()).expect("node counts fit u64"),
            size_of(LeafCount::new(601)).get(),
            "601 leaves must build exactly size_of(601) nodes"
        );

        for leaves in 0..=600_u64 {
            assert_layout_at(&brute, leaves);
            let merges = merges_on_append(LeafCount::new(leaves));
            assert_eq!(
                merges,
                u64::from(leaves.trailing_ones()),
                "the popcount formula at {leaves} leaves"
            );
            assert_eq!(
                merges,
                brute.merge_history[usize::try_from(leaves).expect("leaf counts fit usize")],
                "the structural merge rule at {leaves} leaves"
            );
        }
    }

    #[test]
    fn only_well_formed_sizes_are_accepted_up_to_600_leaves() {
        BruteMmr::build(600);
        let max_raw = size_of(LeafCount::new(600)).get();
        let mut expected_leaves = 0;
        for raw in 0..=max_raw {
            if raw == size_of(LeafCount::new(expected_leaves)).get() {
                let size =
                    MmrSize::try_new(raw).unwrap_or_else(|| panic!("size {raw} must be accepted"));
                assert_eq!(
                    size.leaf_count()
                        .expect("accepted sizes have leaf counts")
                        .get(),
                    expected_leaves
                );
                expected_leaves += 1;
            } else {
                assert!(
                    MmrSize::try_new(raw).is_none(),
                    "size {raw} must be rejected"
                );
                assert!(
                    peaks_of(MmrSize::new_unchecked(raw)).is_empty(),
                    "invalid size {raw} has no peaks"
                );
                assert!(
                    peak_heights(MmrSize::new_unchecked(raw)).is_empty(),
                    "invalid size {raw} has no peak heights"
                );
                assert_eq!(
                    peak_count(MmrSize::new_unchecked(raw)),
                    0,
                    "invalid size {raw} has no peak count"
                );
                assert_eq!(
                    max_peak_height(MmrSize::new_unchecked(raw)).get(),
                    0,
                    "invalid size {raw} has no tallest peak"
                );
            }
        }
        assert_eq!(
            expected_leaves, 601,
            "every leaf count up to 600 must be reachable"
        );
    }

    #[test]
    fn layout_math_matches_brute_force_at_5000_leaves() {
        let brute = BruteMmr::build(5001);
        assert_eq!(
            u64::try_from(brute.heights.len()).expect("node counts fit u64"),
            size_of(LeafCount::new(5001)).get(),
            "5001 leaves must build exactly size_of(5001) nodes"
        );
        assert_node_structure(&brute);
        for leaves in [4_096, 4_999, 5_000] {
            assert_layout_at(&brute, leaves);
        }
    }

    #[test]
    fn leaves_at_or_beyond_the_size_have_no_path() {
        for leaves in [1, 2, 3, 7, 8, 100] {
            let size = size_of(LeafCount::new(leaves));
            for leaf in [leaves, leaves + 1, leaves + 50] {
                assert!(
                    sibling_path(LeafIndex::new(leaf), size).is_empty(),
                    "leaf {leaf} does not exist at {leaves} leaves"
                );
                assert_eq!(
                    path_length(LeafIndex::new(leaf), size),
                    0,
                    "leaf {leaf} beyond {leaves} leaves has no path"
                );
            }
        }
    }
}

mod bagging_and_roots {
    use super::*;

    #[test]
    fn bagging_no_peaks_yields_the_genesis() {
        let hasher = KeccakSolHasher;
        assert_eq!(
            bag_peaks(&hasher, &[]),
            hasher.genesis(),
            "empty accumulators bag to the genesis value"
        );
    }

    #[test]
    fn bagging_one_peak_is_the_identity() {
        let hasher = KeccakSolHasher;
        let peak = Hash::from_u64(0x1234);
        assert_eq!(
            bag_peaks(&hasher, &[peak]),
            peak,
            "a single peak bags to itself"
        );
    }

    #[test]
    fn bagging_two_peaks_hashes_the_pair() {
        let hasher = KeccakSolHasher;
        let peaks = [Hash::from_u64(1), Hash::from_u64(2)];
        assert_eq!(
            bag_peaks(&hasher, &peaks),
            hasher.hash_pair(peaks[0], peaks[1]),
            "two peaks bag to hash_pair(left, right)"
        );
    }

    #[test]
    fn bagging_folds_right_to_left_with_the_leftmost_outermost() {
        let hasher = KeccakSolHasher;
        let peaks: Vec<Hash> = (1..=5).map(Hash::from_u64).collect();

        let mut expected = hasher.hash_pair(peaks[3], peaks[4]);
        for peak in peaks[..3].iter().rev() {
            expected = hasher.hash_pair(*peak, expected);
        }
        assert_eq!(
            bag_peaks(&hasher, &peaks),
            expected,
            "folding starts at the rightmost pair, leftmost peak outermost"
        );

        let mut mirrored = hasher.hash_pair(peaks[0], peaks[1]);
        for peak in &peaks[2..] {
            mirrored = hasher.hash_pair(mirrored, *peak);
        }
        assert_ne!(
            bag_peaks(&hasher, &peaks),
            mirrored,
            "the fold direction must matter"
        );
    }

    #[test]
    fn root_from_binds_the_node_count() {
        let hasher = KeccakSolHasher;
        let bag = Hash::from_u64(0xbeef);
        let size = size_of(LeafCount::new(500));
        assert_eq!(
            root_from(&hasher, bag, size),
            hasher.hash_pair(Hash::from_u64(size.get()), bag),
            "root = H(node_count, bagged_peaks)"
        );
    }
}

// ---------------------------------------------------------------- extremes

/// The documented panic bound of [`LeafIndex::new`]: beyond
/// [`MAX_LEAF_COUNT`] the leaf→node mapping would overflow `u64`, so the
/// constructor must reject it loudly rather than wrap to a wrong node.
#[test]
#[should_panic(expected = "leaf index beyond the layout range")]
fn leaf_index_beyond_the_layout_bound_panics() {
    let _ = LeafIndex::new(MAX_LEAF_COUNT + 1);
}

#[test]
fn the_max_leaf_index_is_constructible() {
    assert_eq!(LeafIndex::new(MAX_LEAF_COUNT).get(), MAX_LEAF_COUNT);
}

/// The u64-extreme closed forms, no brute force: `size_of` at the layout
/// bound, the last leaf's node position, the parent overflow guard, and the
/// malformed-size guard on `sibling_path` (a malformed size must return
/// empty, never shift-overflow or loop).
#[test]
fn u64_extreme_layout_is_closed_form() {
    // size_of(2^63 - 1) = 2L - popcount(L) = 2^64 - 2 - 63 = u64::MAX - 64.
    let max_leaves = LeafCount::new(MAX_LEAF_COUNT);
    assert_eq!(size_of(max_leaves).get(), u64::MAX - 64);

    // The last leaf sits at node 2i + 1 - popcount(i) = u64::MAX - 63 —
    // exactly one past the maximal MMR's last node.
    assert_eq!(LeafIndex::new(MAX_LEAF_COUNT).node().get(), u64::MAX - 63);
    assert_eq!(size_of(max_leaves).get() + 1, u64::MAX - 63);

    // A size of u64::MAX cannot be well-formed (size + 1 overflows the
    // mountain walk) and carries no leaf count, peaks, or paths.
    assert!(MmrSize::try_new(u64::MAX).is_none());
    assert!(MmrSize::new_unchecked(u64::MAX).leaf_count().is_none());
    assert_eq!(peaks_of(MmrSize::new_unchecked(u64::MAX)), Vec::new());
    assert_eq!(
        sibling_path(LeafIndex::FIRST, MmrSize::new_unchecked(u64::MAX)),
        Vec::new()
    );

    // The parent of the last possible node cannot exist: the u64 space ends.
    assert_eq!(
        NodeIndex::try_new(u64::MAX).expect("nonzero").parent(),
        None
    );

    // The largest mountain of any bound is its leading power of two.
    assert_eq!(largest_mountain(u64::MAX), 1 << 63);
    assert_eq!(largest_mountain(0), 0);

    // A leaf of the maximal MMR: leaf 0 sits in the single 2^62-leaf
    // mountain, so its path is 62 steps; the index at MAX_LEAF_COUNT is one
    // past the last leaf and has no path.
    assert_eq!(
        path_length(LeafIndex::FIRST, size_of(LeafCount::new(MAX_LEAF_COUNT))),
        62
    );
    assert_eq!(
        path_length(
            LeafIndex::new(MAX_LEAF_COUNT),
            size_of(LeafCount::new(MAX_LEAF_COUNT))
        ),
        0
    );
}
