//! Tests for the incremental Merkle tree (`accumulators::merkle`).
//!
//! Covers:
//! - sparse create/open with persisted, validated metadata,
//! - the `set_leaf` update gate and its `previous` semantics,
//! - proving *every* leaf of a scattered (non-power-of-2 occupancy) tree —
//!   unoccupied siblings come from the zero ladder, never a missing store
//!   record,
//! - self-contained proofs: verification against the proof's own root with
//!   no tree and no store, truncation as a typed error, tamper as `false`,
//! - multiproof dedup and standalone verification,
//! - persistence across reopen, and index bounds.
//!
//! Handle-level `verify`/`verify_multi` pin proofs to the tree's *current*
//! root; historical checks go through the standalone verifiers, which need
//! only the hasher.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
use accumulators::{
    hashers::{Blake2sStarkHasher, Hasher, KeccakSolHasher},
    ids::AccumulatorId,
    merkle::{
        IncrementalMerkleTree, TreeCorrupted, TreeError, TreeMultiProof, TreeProof,
        TreeProofInconsistent, TreeVerifyError,
        math::{heap_level_and_index, leaf_heap, multiproof_walk},
        verify_multi_proof, verify_proof,
    },
    primitives::{Hash, LeafIndex},
    store::memory::InMemoryStore,
};

/// A valid element for every hasher: the 32-byte big-endian encoding of
/// `index` (left-zero-padded, so distinct indexes give distinct elements).
fn element(index: u64) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&index.to_be_bytes());
    bytes
}

/// An empty keccak tree of `depth` levels with the all-zero null leaf,
/// stored under its own fresh `InMemoryStore`.
fn tree(depth: u8) -> IncrementalMerkleTree<KeccakSolHasher, InMemoryStore> {
    IncrementalMerkleTree::create(
        KeccakSolHasher,
        InMemoryStore::new(),
        AccumulatorId::ZERO,
        depth,
        Hash::ZERO,
    )
    .expect("tree creation succeeds")
}

#[test]
fn create_open_round_trip_and_empty_root() {
    let depth = 8;
    let store = InMemoryStore::new();
    let created = IncrementalMerkleTree::create(
        KeccakSolHasher,
        store.clone(),
        AccumulatorId::ZERO,
        depth,
        Hash::ZERO,
    )
    .expect("create succeeds");
    assert_eq!(created.capacity(), 1 << depth);
    assert_eq!(created.null_leaf(), Hash::ZERO);

    // The empty root is the top of the zero ladder: the null leaf folded
    // through `depth` pair hashes.
    let mut expected = Hash::ZERO;
    for _ in 0..depth {
        expected = KeccakSolHasher.hash_pair(expected, expected);
    }
    assert_eq!(created.root(), expected);

    let reopened = IncrementalMerkleTree::open(KeccakSolHasher, store, AccumulatorId::ZERO)
        .expect("open succeeds");
    assert_eq!(reopened.capacity(), 1 << depth);
    assert_eq!(reopened.null_leaf(), Hash::ZERO);
    assert_eq!(reopened.root(), created.root());
}

/// The depth accessor reports the persisted shape parameter: the depth the
/// tree was created at, identical after a reopen, with capacity derived
/// from it.
#[test]
fn depth_accessor_matches_the_persisted_shape() {
    let depth = 11;
    let store = InMemoryStore::new();
    let created = IncrementalMerkleTree::create(
        KeccakSolHasher,
        store.clone(),
        AccumulatorId::ZERO,
        depth,
        Hash::ZERO,
    )
    .expect("create succeeds");
    assert_eq!(created.depth(), depth);
    assert_eq!(
        created.capacity(),
        1_u64 << created.depth(),
        "capacity is 2^depth"
    );

    let reopened = IncrementalMerkleTree::open(KeccakSolHasher, store, AccumulatorId::ZERO)
        .expect("open succeeds");
    assert_eq!(reopened.depth(), depth, "depth persists across reopen");
}

/// `heap_level_and_index` decodes `leaf_heap` exactly: the leaf's heap index
/// resolves back to `(depth, index)` at every depth, including the u64
/// extremes of a depth-63 tree.
#[test]
fn heap_level_and_index_round_trips_leaf_heap() {
    for depth in [1_u8, 8, 63] {
        for index in [0_u64, 1, 42, (1_u64 << depth) - 1] {
            // Only indexes within the tree's capacity `2^depth` are leaves.
            if index >= 1_u64 << depth {
                continue;
            }
            assert_eq!(
                heap_level_and_index(leaf_heap(depth, LeafIndex::new(index))),
                (depth, index),
                "leaf {index} of a depth-{depth} tree"
            );
        }
    }
    assert_eq!(
        heap_level_and_index(1),
        (0, 0),
        "the root is level 0, position 0"
    );
}

/// The standalone walk is the exact plan the verifier consumes: the walk
/// over the proof's own indexes reproduces the sibling budget
/// `verify_multi_proof` checks, and the proof it plans verifies standalone
/// (the scattered-set analogue of
/// `multiproof_over_a_shared_parent_set_dedups_siblings`).
#[test]
fn multiproof_walk_matches_what_the_verifier_consumes() {
    let mut tree = tree(6);
    let scattered = [0_u64, 1, 7, 8, 20, 41, 63];
    for &index in &scattered {
        tree.set_leaf(LeafIndex::new(index), &element(index), None)
            .expect("leaf write succeeds");
    }
    let indexes: Vec<LeafIndex> = scattered.iter().copied().map(LeafIndex::new).collect();
    let multi = tree
        .multiproof(indexes.iter().copied())
        .expect("multiproof succeeds");
    assert_eq!(multi.indexes, indexes, "indexes stay ascending and unique");

    let plan = multiproof_walk(multi.depth, &multi.indexes);
    assert_eq!(
        plan.len(),
        multi.siblings.len(),
        "the walk over the proof's own indexes is its sibling budget"
    );
    assert!(
        plan.iter().all(|&heap| heap != 1),
        "the root is never a proof sibling"
    );

    let elements: Vec<[u8; 32]> = scattered.iter().copied().map(element).collect();
    assert!(
        verify_multi_proof(&KeccakSolHasher, &multi, elements).expect("verify succeeds"),
        "the proof the walk planned verifies standalone"
    );
}

#[test]
fn create_rejects_depth_out_of_range() {
    // Valid depth is 1..=63; both bounds must be rejected as invalid depth.
    for depth in [0, 64, 255] {
        let error = IncrementalMerkleTree::create(
            KeccakSolHasher,
            InMemoryStore::new(),
            AccumulatorId::ZERO,
            depth,
            Hash::ZERO,
        )
        .err()
        .expect("out-of-range depth is rejected");
        assert!(
            matches!(error, TreeError::InvalidDepth { depth: rejected } if rejected == depth),
            "depth {depth} must be rejected as invalid depth, got {error:?}"
        );
    }
}

#[test]
fn open_without_metadata_is_corrupted() {
    let error =
        IncrementalMerkleTree::open(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO)
            .err()
            .expect("opening an empty store cannot succeed");
    assert!(
        matches!(error, TreeError::Corrupted(TreeCorrupted::MissingMetadata)),
        "expected MissingMetadata, got {error:?}"
    );
}

#[test]
fn set_leaf_on_empty_tree_and_update_gate() {
    let mut tree = tree(8);
    let index = LeafIndex::new(5);
    let root_before = tree.root();

    // First write onto an unoccupied leaf: the leaf read as the null leaf.
    let first = tree
        .set_leaf(index, &element(5), None)
        .expect("first write succeeds");
    assert_eq!(first.index, index);
    assert_eq!(first.previous, Hash::ZERO);
    assert_ne!(first.root, root_before, "the write must change the root");

    // Re-writing requires the gate; `previous` is the hash of the stored
    // element, not the element itself.
    let first_hash = KeccakSolHasher
        .hash_leaf(&element(5))
        .expect("valid element");
    let second = tree
        .set_leaf(index, &element(6), Some(first_hash))
        .expect("gated write succeeds");
    assert_eq!(second.previous, first_hash);
    assert_ne!(second.root, first.root);

    // A wrong gate value is rejected and leaves the tree untouched.
    let error = tree
        .set_leaf(index, &element(7), Some(Hash::ZERO))
        .expect_err("wrong gate value is rejected");
    match error {
        TreeError::UpdateMismatch { index: rejected } => assert_eq!(rejected, index),
        other => panic!("expected UpdateMismatch, got {other:?}"),
    }

    // The correct gate value succeeds.
    let second_hash = KeccakSolHasher
        .hash_leaf(&element(6))
        .expect("valid element");
    let third = tree
        .set_leaf(index, &element(7), Some(second_hash))
        .expect("correct gate value is accepted");
    assert_eq!(third.previous, second_hash);
}

/// `root()` must track writes in-session and the persisted root must be
/// restored on reopen. This is the contract the proofs commit against.
#[test]
fn root_reflects_writes_and_reopens() {
    let store = InMemoryStore::new();
    let mut tree = IncrementalMerkleTree::create(
        KeccakSolHasher,
        store.clone(),
        AccumulatorId::ZERO,
        8,
        Hash::ZERO,
    )
    .expect("create succeeds");

    let first = tree
        .set_leaf(LeafIndex::new(5), &element(5), None)
        .expect("first write succeeds");
    assert_eq!(tree.root(), first.root, "root() must track set_leaf");

    let second = tree
        .set_leaf(LeafIndex::new(2), &element(2), None)
        .expect("second write succeeds");
    assert_eq!(tree.root(), second.root, "root() must track set_leaf");

    drop(tree);
    let reopened = IncrementalMerkleTree::open(KeccakSolHasher, store, AccumulatorId::ZERO)
        .expect("reopen succeeds");
    assert_eq!(
        reopened.root(),
        second.root,
        "open() must restore the persisted root"
    );
}

/// A scattered (non-power-of-2 occupancy) tree must prove *every* leaf:
/// sibling paths crossing unoccupied sub-trees resolve through the zero
/// ladder, never a missing store record. Occupied leaves verify against the
/// tree's current root (the proofs carry it — see `proof.root`).
#[test]
fn proofs_for_every_leaf_of_a_scattered_depth_10_tree() {
    let mut tree = tree(10);
    assert_eq!(tree.capacity(), 1024);

    let mut occupied: Vec<u64> = (0..300).step_by(7).collect();
    occupied.extend_from_slice(&[0, 1, 999, 1023]);
    occupied.sort_unstable();
    occupied.dedup();
    let mut root = tree.root();
    for &leaf in &occupied {
        let outcome = tree
            .set_leaf(LeafIndex::new(leaf), &element(leaf), None)
            .expect("leaf write succeeds");
        root = outcome.root;
    }

    for leaf in 0..1024 {
        let index = LeafIndex::new(leaf);
        // Must always succeed — including for leaves whose sibling path
        // crosses unoccupied sub-trees backed by the ladder.
        let proof = tree
            .proof(index)
            .expect("proof succeeds for every index within capacity");
        assert_eq!(
            proof.siblings.len(),
            10,
            "proof is exactly `depth` siblings"
        );
        assert_eq!(proof.root, root, "the proof carries the root it commits to");
        assert_eq!(proof.depth, 10);
        assert_eq!(proof.index, index);

        if occupied.binary_search(&leaf).is_ok() {
            assert!(
                tree.verify(&proof, &element(leaf))
                    .expect("verify succeeds"),
                "occupied leaf {leaf} must verify against the current root"
            );
            assert!(
                !tree
                    .verify(&proof, &element(leaf + 4096))
                    .expect("verify succeeds"),
                "a different element must not verify for leaf {leaf}"
            );
            // The standalone verifier reaches the same verdict with no tree.
            assert!(
                verify_proof(&KeccakSolHasher, &proof, &element(leaf)).expect("verify succeeds"),
                "the self-contained proof must verify standalone for leaf {leaf}"
            );
        }
    }
}

#[test]
fn verify_rejects_bad_proofs() {
    let mut tree = tree(8);
    let root = tree
        .set_leaf(LeafIndex::new(3), &element(3), None)
        .expect("leaf write succeeds")
        .root;
    let proof = tree.proof(LeafIndex::new(3)).expect("proof succeeds");
    assert_eq!(proof.root, root);

    // Structural failures are typed errors, not negative results: a truncated proof…
    let truncated = TreeProof {
        siblings: proof.siblings[..proof.siblings.len() - 1].to_vec(),
        ..proof.clone()
    };
    match verify_proof(&KeccakSolHasher, &truncated, &element(3)) {
        Err(TreeVerifyError::Inconsistent(TreeProofInconsistent::PathLengthMismatch {
            siblings,
            expected,
            ..
        })) => {
            assert_eq!(siblings, 7);
            assert_eq!(expected, 8);
        }
        other => panic!("expected PathLengthMismatch, got {other:?}"),
    }
    // …an over-long proof…
    let mut extended = proof.clone();
    extended.siblings.push(Hash::ZERO);
    assert!(
        matches!(
            verify_proof(&KeccakSolHasher, &extended, &element(3)),
            Err(TreeVerifyError::Inconsistent(
                TreeProofInconsistent::PathLengthMismatch { .. }
            ))
        ),
        "an over-long proof must be a typed structural error"
    );
    // …a leaf beyond the proof's own capacity…
    let mut out_of_range = proof.clone();
    out_of_range.index = LeafIndex::new(256);
    assert!(
        matches!(
            verify_proof(&KeccakSolHasher, &out_of_range, &element(3)),
            Err(TreeVerifyError::Inconsistent(
                TreeProofInconsistent::LeafOutOfRange { .. }
            ))
        ),
        "a leaf beyond 2^depth must be a typed structural error"
    );
    // …and a depth no real tree can have.
    let phantom = TreeProof {
        depth: 64,
        ..proof.clone()
    };
    assert!(
        matches!(
            verify_proof(&KeccakSolHasher, &phantom, &element(3)),
            Err(TreeVerifyError::Inconsistent(
                TreeProofInconsistent::InvalidDepth { .. }
            ))
        ),
        "an out-of-range proof depth must be a typed structural error"
    );

    // Tamper is a negative result, never an error or a panic: a flipped
    // sibling folds somewhere other than the proof's own root…
    let mut tampered = proof.clone();
    tampered.siblings[1] = Hash::ZERO;
    assert!(
        !verify_proof(&KeccakSolHasher, &tampered, &element(3)).expect("verify succeeds"),
        "a tampered sibling must not verify"
    );
    // …the right proof against the wrong element…
    assert!(
        !verify_proof(&KeccakSolHasher, &proof, &element(4)).expect("verify succeeds"),
        "a wrong element must not verify"
    );
    // …and the right proof at the wrong index (still within capacity — the
    // fold lands on a different root, so it is tamper, not a structural
    // error).
    let wrong_index = TreeProof {
        index: LeafIndex::new(2),
        ..proof.clone()
    };
    assert!(
        !verify_proof(&KeccakSolHasher, &wrong_index, &element(3)).expect("verify succeeds"),
        "a wrong index must not verify"
    );

    // The handle-level verify pins the proof to the tree's *current* root:
    // it holds while the tree is unchanged, and stops once it moves on —
    // the standalone verifier still accepts the captured commitment.
    assert!(tree.verify(&proof, &element(3)).expect("verify succeeds"));
    tree.set_leaf(LeafIndex::new(5), &element(5), None)
        .expect("write succeeds");
    assert!(
        !tree.verify(&proof, &element(3)).expect("verify succeeds"),
        "a stale proof must not verify against the new current root"
    );
    assert!(
        verify_proof(&KeccakSolHasher, &proof, &element(3)).expect("verify succeeds"),
        "the captured proof remains a standalone commitment to its own root"
    );
}

/// The point of self-containment: a proof verifies with no tree and no
/// store — the hasher and the proof are the whole verifier input.
#[test]
fn proofs_verify_without_the_tree_or_the_store() {
    let store = InMemoryStore::new();
    let mut tree = IncrementalMerkleTree::create(
        KeccakSolHasher,
        store.clone(),
        AccumulatorId::ZERO,
        8,
        Hash::ZERO,
    )
    .expect("create succeeds");
    let root = tree
        .set_leaf(LeafIndex::new(42), &element(42), None)
        .expect("write succeeds")
        .root;
    let proof = tree.proof(LeafIndex::new(42)).expect("proof succeeds");
    drop(tree);
    drop(store);

    assert_eq!(proof.root, root);
    assert!(
        verify_proof(&KeccakSolHasher, &proof, &element(42)).expect("verify succeeds"),
        "the proof verifies against its own root with nothing else alive"
    );
    assert!(
        !verify_proof(&KeccakSolHasher, &proof, &element(43)).expect("verify succeeds"),
        "a foreign element must not verify standalone"
    );
}

/// The multiproof dedup payoff: leaves {0, 1, 2, 3} share complete parent
/// sub-trees, so their pairwise siblings merge; only the ancestors above the
/// covered sub-tree remain, taken from the ladder. A complete cover (all
/// leaves of a small tree) needs no sibling hashes at all.
#[test]
fn multiproof_over_a_shared_parent_set_dedups_siblings() {
    // Complete cover: every sibling merges, the proof is sibling-free.
    let mut full = tree(3);
    for leaf in 0..8 {
        full.set_leaf(LeafIndex::new(leaf), &element(leaf), None)
            .expect("leaf write succeeds");
    }
    let indexes: Vec<LeafIndex> = (0..8).map(LeafIndex::new).collect();
    let multi = full
        .multiproof(indexes.iter().copied())
        .expect("multiproof succeeds within capacity");
    assert_eq!(multi.indexes, indexes, "indexes stay ascending");
    assert_eq!(multi.depth, 3);
    assert!(
        multi.siblings.is_empty(),
        "a complete sub-tree cover needs no sibling hashes"
    );
    let individual: usize = indexes
        .iter()
        .map(|&index| full.proof(index).expect("proof succeeds").siblings.len())
        .sum();
    assert!(
        multi.siblings.len() < individual,
        "the dedup payoff: {} siblings must beat {} individual entries",
        multi.siblings.len(),
        individual
    );

    // Partial cover {0, 1, 2, 3} of a depth-10 tree: the four leaves merge
    // into one sub-tree root; only the `depth - 2` ancestors above it remain
    // as ladder-backed siblings.
    let mut tree = tree(10);
    for leaf in 0..4 {
        tree.set_leaf(LeafIndex::new(leaf), &element(leaf), None)
            .expect("leaf write succeeds");
    }
    let partial = tree
        .multiproof([
            LeafIndex::FIRST,
            LeafIndex::new(1),
            LeafIndex::new(2),
            LeafIndex::new(3),
        ])
        .expect("multiproof succeeds within capacity");
    assert_eq!(
        partial.siblings.len(),
        8,
        "only the ladder-backed ancestors above the covered sub-tree remain"
    );
    let individual: usize = (0..4)
        .map(|leaf| {
            tree.proof(LeafIndex::new(leaf))
                .expect("proof succeeds")
                .siblings
                .len()
        })
        .sum();
    assert!(
        partial.siblings.len() < individual,
        "the dedup payoff: {} siblings must beat {} individual entries",
        partial.siblings.len(),
        individual
    );
}

#[test]
fn multiproof_over_a_scattered_set_round_trips() {
    let mut tree = tree(12);
    let mut leaves = vec![1, 5, 9, 3, 100, 4095];
    leaves.sort_unstable();
    for &leaf in &leaves {
        tree.set_leaf(LeafIndex::new(leaf), &element(leaf), None)
            .expect("leaf write succeeds");
    }

    // Unsorted input with a duplicate: the proof normalizes to ascending,
    // unique indexes.
    let multi = tree
        .multiproof([
            LeafIndex::new(9),
            LeafIndex::new(1),
            LeafIndex::new(1),
            LeafIndex::new(5),
            LeafIndex::new(3),
            LeafIndex::new(100),
            LeafIndex::new(4095),
        ])
        .expect("multiproof succeeds within capacity");
    let expected: Vec<LeafIndex> = leaves.iter().copied().map(LeafIndex::new).collect();
    assert_eq!(multi.indexes, expected);

    let elements: Vec<[u8; 32]> = leaves.iter().map(|&leaf| element(leaf)).collect();
    assert!(
        tree.verify_multi(&multi, &elements)
            .expect("verification is infallible here"),
        "the scattered multiproof must verify against the current root"
    );
    // And standalone against the proof's own root — no tree, no store.
    assert!(
        verify_multi_proof(&KeccakSolHasher, &multi, &elements).expect("verify succeeds"),
        "the self-contained multiproof must verify standalone"
    );

    // Positional alignment is enforced: shuffled elements fail.
    let mut shuffled = elements.clone();
    shuffled.reverse();
    assert!(
        !tree
            .verify_multi(&multi, &shuffled)
            .expect("verification is infallible here"),
        "shuffled elements must not verify"
    );
    // One wrong element fails.
    let mut wrong = elements.clone();
    wrong[0] = element(2);
    assert!(
        !tree
            .verify_multi(&multi, &wrong)
            .expect("verification is infallible here"),
        "one wrong element must not verify"
    );
    // A wrong element count is structural — a typed error, not a negative
    // result (a shorter list would let a truncated proof "verify" against
    // fewer commitments than it claims leaves).
    assert!(
        matches!(
            tree.verify_multi(&multi, &elements[..elements.len() - 1]),
            Err(TreeError::Proof(TreeVerifyError::Inconsistent(
                TreeProofInconsistent::ElementCountMismatch { .. }
            )))
        ),
        "a mismatched element count must be a typed structural error"
    );
}

/// A multiproof with a truncated sibling list is a typed structural error —
/// the minimal sibling set for the claimed indexes is derivable from the
/// indexes alone, so the budget mismatch is detectable before any hashing.
/// Tampering a sibling *value* (budget intact) stays a negative result.
#[test]
fn multiproof_truncation_is_a_typed_error_and_tamper_is_false() {
    let mut tree = tree(6);
    for leaf in [1_u64, 5, 9] {
        tree.set_leaf(LeafIndex::new(leaf), &element(leaf), None)
            .expect("write succeeds");
    }
    let multi = tree
        .multiproof([LeafIndex::new(1), LeafIndex::new(5), LeafIndex::new(9)])
        .expect("multiproof succeeds");
    let elements: Vec<[u8; 32]> = [1, 5, 9].iter().map(|&leaf| element(leaf)).collect();

    let truncated = TreeMultiProof {
        siblings: multi.siblings[..multi.siblings.len() - 1].to_vec(),
        ..multi.clone()
    };
    match verify_multi_proof(&KeccakSolHasher, &truncated, &elements) {
        Err(TreeVerifyError::Inconsistent(TreeProofInconsistent::SiblingCountMismatch {
            siblings,
            expected,
        })) => {
            assert_eq!(siblings + 1, expected);
        }
        other => panic!("expected SiblingCountMismatch, got {other:?}"),
    }

    let mut tampered = multi.clone();
    let last = tampered.siblings.len() - 1;
    tampered.siblings[last] = Hash::ZERO;
    assert!(
        !verify_multi_proof(&KeccakSolHasher, &tampered, &elements).expect("verify succeeds"),
        "a tampered sibling value must fold to something other than the proof's root"
    );

    // Unsorted or duplicated indexes are structural, and the producer never
    // emits them (it normalizes) — only hand-built proofs can.
    let mut unsorted = multi.clone();
    unsorted.indexes.reverse();
    assert!(matches!(
        verify_multi_proof(&KeccakSolHasher, &unsorted, &elements),
        Err(TreeVerifyError::Inconsistent(
            TreeProofInconsistent::UnsortedLeaves { .. }
        ))
    ));
    let mut duplicated = multi;
    duplicated.indexes[1] = duplicated.indexes[0];
    assert!(matches!(
        verify_multi_proof(&KeccakSolHasher, &duplicated, &elements),
        Err(TreeVerifyError::Inconsistent(
            TreeProofInconsistent::DuplicateLeaf { .. }
        ))
    ));
}

#[test]
fn index_beyond_capacity_is_rejected() {
    let mut tree = tree(4);
    let index = LeafIndex::new(16);
    let capacity = tree.capacity();

    let error = tree
        .set_leaf(index, &element(16), None)
        .expect_err("index at capacity is rejected");
    match error {
        TreeError::IndexOutOfRange {
            index: got,
            capacity: cap,
        } => {
            assert_eq!(got, index);
            assert_eq!(cap, capacity);
        }
        other => panic!("expected IndexOutOfRange, got {other:?}"),
    }

    assert!(
        matches!(tree.proof(index), Err(TreeError::IndexOutOfRange { .. })),
        "proof beyond capacity is rejected"
    );
    // The verifier side enforces the same bound against the proof's own
    // depth: an index at capacity cannot be folded into a valid proof.
    let proof = tree.proof(LeafIndex::new(0)).expect("proof succeeds");
    let beyond = TreeProof { index, ..proof };
    assert!(
        matches!(
            verify_proof(&KeccakSolHasher, &beyond, &element(0)),
            Err(TreeVerifyError::Inconsistent(
                TreeProofInconsistent::LeafOutOfRange { .. }
            ))
        ),
        "a proof claiming a leaf beyond its own capacity is rejected"
    );
    assert!(
        matches!(
            tree.multiproof([LeafIndex::new(0), index]),
            Err(TreeError::IndexOutOfRange { .. })
        ),
        "multiproof with any out-of-range index is rejected"
    );
}

#[test]
fn tree_persists_across_reopen() {
    let hasher = KeccakSolHasher;
    let store = InMemoryStore::new();
    let mut tree =
        IncrementalMerkleTree::create(hasher, store.clone(), AccumulatorId::ZERO, 8, Hash::ZERO)
            .expect("create succeeds");
    tree.set_leaf(LeafIndex::new(0), &element(0), None)
        .expect("leaf write succeeds");
    let root = tree
        .set_leaf(LeafIndex::new(17), &element(17), None)
        .expect("leaf write succeeds")
        .root;

    drop(tree);
    let mut reopened =
        IncrementalMerkleTree::open(hasher, store, AccumulatorId::ZERO).expect("reopen succeeds");
    assert_eq!(reopened.root(), root, "the root survives the reopen");
    assert_eq!(reopened.capacity(), 256);
    assert_eq!(reopened.null_leaf(), Hash::ZERO);

    // Proofs survive the reopen and verify against the restored root.
    let proof = reopened.proof(LeafIndex::new(17)).expect("proof succeeds");
    assert!(
        reopened
            .verify(&proof, &element(17))
            .expect("verify succeeds"),
        "a proof taken after the reopen must verify"
    );

    // Writes continue from the restored state, and earlier proofs stay
    // verifiable standalone — they are commitments to the root they were
    // taken at, not to whatever root the tree has now.
    reopened
        .set_leaf(LeafIndex::new(200), &element(200), None)
        .expect("post-reopen write succeeds");
    assert_ne!(reopened.root(), root);
    assert!(
        !reopened
            .verify(&proof, &element(17))
            .expect("verify succeeds"),
        "the stale proof no longer matches the tree's current root"
    );
    assert!(
        verify_proof(&KeccakSolHasher, &proof, &element(17)).expect("verify succeeds"),
        "the captured proof is a standalone commitment to the captured root"
    );
}

#[test]
fn open_rejects_a_different_hasher_config() {
    let store = InMemoryStore::new();
    let created = IncrementalMerkleTree::create(
        Blake2sStarkHasher { truncate: false },
        store.clone(),
        AccumulatorId::ZERO,
        8,
        Hash::ZERO,
    )
    .expect("create succeeds");
    drop(created);

    // Same hasher id, different persisted config: the truncation flag is
    // part of the metadata and must not be silently ignored.
    let error = IncrementalMerkleTree::open(
        Blake2sStarkHasher { truncate: true },
        store,
        AccumulatorId::ZERO,
    )
    .err()
    .expect("config mismatch must be rejected");
    match error {
        TreeError::Corrupted(TreeCorrupted::HasherMismatch { stored, .. }) => {
            assert!(
                stored.contains("truncate=false"),
                "the stored config names the truncation flag, got: {stored}"
            );
        }
        other => panic!("expected HasherMismatch, got {other:?}"),
    }
}

#[test]
fn open_rejects_a_different_hasher_id() {
    let store = InMemoryStore::new();
    let created = IncrementalMerkleTree::create(
        KeccakSolHasher,
        store.clone(),
        AccumulatorId::ZERO,
        4,
        Hash::ZERO,
    )
    .expect("create succeeds");
    drop(created);

    let error = IncrementalMerkleTree::open(
        Blake2sStarkHasher { truncate: false },
        store,
        AccumulatorId::ZERO,
    )
    .err()
    .expect("hasher id mismatch must be rejected");
    assert!(
        matches!(
            error,
            TreeError::Corrupted(TreeCorrupted::HasherMismatch { .. })
        ),
        "expected HasherMismatch, got {error:?}"
    );
}

/// `leaf_hash` distinguishes occupied from unoccupied (never substitutes the
/// ladder's null value), and rejects out-of-range indexes.
#[test]
fn leaf_hash_distinguishes_occupied_from_unoccupied() {
    let mut tree = tree(6);
    tree.set_leaf(LeafIndex::new(3), &element(3), None)
        .expect("write succeeds");

    let occupied = tree
        .leaf_hash(LeafIndex::new(3))
        .expect("read succeeds")
        .expect("leaf 3 is occupied");
    assert_eq!(
        occupied,
        KeccakSolHasher.hash_leaf(&element(3)).expect("hash")
    );

    assert_eq!(
        tree.leaf_hash(LeafIndex::new(4)).expect("read succeeds"),
        None,
        "an unoccupied leaf reads as None, never the ladder's null value"
    );

    let error = tree
        .leaf_hash(LeafIndex::new(64))
        .expect_err("beyond capacity is rejected");
    assert!(
        matches!(error, TreeError::IndexOutOfRange { .. }),
        "expected IndexOutOfRange, got {error:?}"
    );
}

/// A gate of `Some(null_leaf)` over an unoccupied leaf succeeds (the
/// unoccupied leaf's current value IS the null leaf), and the write reports
/// the null leaf as `previous`.
#[test]
fn set_leaf_gate_over_an_unoccupied_leaf_compares_the_null_leaf() {
    let mut tree = tree(6);
    let outcome = tree
        .set_leaf(LeafIndex::new(2), &element(2), Some(Hash::ZERO))
        .expect("the null leaf is the unoccupied value, so the gate passes");
    assert_eq!(
        outcome.previous,
        Hash::ZERO,
        "previous on an unoccupied leaf is the null leaf, not an Option"
    );

    // A stale gate over an occupied leaf still fails.
    let error = tree
        .set_leaf(LeafIndex::new(2), &element(9), Some(Hash::ZERO))
        .expect_err("the leaf is now occupied by a non-null value");
    assert!(
        matches!(error, TreeError::UpdateMismatch { .. }),
        "expected UpdateMismatch, got {error:?}"
    );
}

/// An empty multiproof is rejected at the producer (typed error) — the
/// verifier could never reproduce a root from a zero-leaf proof.
#[test]
fn empty_multiproofs_are_rejected() {
    let tree = tree(6);
    match tree.multiproof(Vec::<LeafIndex>::new()) {
        Err(TreeError::EmptyProof) => {}
        other => panic!("expected EmptyProof, got {other:?}"),
    }
}

/// A captured multiproof is a commitment to the root it was taken at: the
/// standalone verifier accepts it against its own root forever; the
/// handle-level `verify_multi` pins it to the tree's *current* root.
#[test]
fn verify_multi_against_a_historical_root() {
    let mut tree = tree(6);
    let historical = tree
        .set_leaf(LeafIndex::new(1), &element(1), None)
        .expect("write succeeds")
        .root;
    let multi = tree
        .multiproof([LeafIndex::new(1)])
        .expect("multiproof succeeds");
    assert_eq!(multi.root, historical);
    let elements = [element(1)];

    // Against the proof's own (historical) root: authentic.
    assert!(
        verify_multi_proof(&KeccakSolHasher, &multi, elements).expect("verify succeeds"),
        "the captured multiproof verifies against the root it was taken at"
    );
    // Against the current root: not — the tree has moved on since the proof
    // was taken, so the current root differs.
    tree.set_leaf(LeafIndex::new(5), &element(5), None)
        .expect("write succeeds");
    assert!(
        !tree
            .verify_multi(&multi, elements)
            .expect("verification is infallible here"),
        "the multiproof does not verify against the new root"
    );
    assert!(
        verify_multi_proof(&KeccakSolHasher, &multi, elements).expect("verify succeeds"),
        "it still verifies against the historical root"
    );
}

// ------------------------------------------------------------- corruption

/// A present-but-unparsable sibling node is [`TreeCorrupted::MalformedNode`]
/// — never a ladder substitution producing a wrong proof, and
/// never a silent overwrite corrupting the root on the next write.
#[test]
fn a_poisoned_sibling_node_is_malformed_never_a_wrong_proof() {
    let store = InMemoryStore::new();
    let mut tree = IncrementalMerkleTree::create(
        KeccakSolHasher,
        store.clone(),
        AccumulatorId::ZERO,
        4,
        Hash::ZERO,
    )
    .expect("create succeeds");
    // Leaf 0 occupies heap 16; leaf 1's sibling path reads heap 16.
    tree.set_leaf(LeafIndex::new(0), &element(0), None)
        .expect("write succeeds");

    let mut batch = accumulators::store::Batch::new();
    batch.put_owned(
        accumulators::store::keys::encode(
            &AccumulatorId::ZERO,
            accumulators::store::keys::Table::TreeNode,
            16,
        ),
        vec![0xff; 3],
    );
    accumulators::store::Store::write(&store, batch).expect("in-memory writes are infallible");

    match tree.proof(LeafIndex::new(1)) {
        Err(TreeError::Corrupted(TreeCorrupted::MalformedNode)) => {}
        other => panic!("expected MalformedNode, got {other:?}"),
    }
    match tree.leaf_hash(LeafIndex::new(0)) {
        Err(TreeError::Corrupted(TreeCorrupted::MalformedNode)) => {}
        other => panic!("expected MalformedNode, got {other:?}"),
    }
    // The write path fails closed too: a poisoned sibling on the edit path
    // must refuse the write rather than fold the ladder hash over garbage.
    match tree.set_leaf(LeafIndex::new(1), &element(1), None) {
        Err(TreeError::Corrupted(TreeCorrupted::MalformedNode)) => {}
        other => panic!("expected MalformedNode on the write path, got {other:?}"),
    }
}

/// Tampered persisted metadata (a depth byte out of range) is diagnosed as
/// [`TreeCorrupted::MalformedMetadata`] on open.
#[test]
fn tampered_metadata_is_malformed_metadata() {
    let store = InMemoryStore::new();
    IncrementalMerkleTree::create(
        KeccakSolHasher,
        store.clone(),
        AccumulatorId::ZERO,
        8,
        Hash::ZERO,
    )
    .expect("create succeeds");

    let mut batch = accumulators::store::Batch::new();
    batch.put_owned(
        accumulators::store::keys::encode(
            &AccumulatorId::ZERO,
            accumulators::store::keys::Table::TreeMeta,
            0,
        ),
        vec![0xff, 0x00],
    );
    accumulators::store::Store::write(&store, batch).expect("in-memory writes are infallible");

    match IncrementalMerkleTree::open(KeccakSolHasher, store, AccumulatorId::ZERO) {
        Err(TreeError::Corrupted(TreeCorrupted::MalformedMetadata)) => {}
        Err(other) => panic!("expected MalformedMetadata, got {other:?}"),
        Ok(_) => panic!("expected MalformedMetadata, but the tree opened"),
    }
}

// -------------------------------------------------------------- boundaries

/// Depth 1 is the smallest valid tree: one level, one sibling per proof.
#[test]
fn depth_one_trees_prove_and_verify() {
    let mut tree = tree(1);
    assert_eq!(tree.capacity(), 2);
    tree.set_leaf(LeafIndex::FIRST, &element(0), None)
        .expect("write succeeds");
    let proof = tree.proof(LeafIndex::FIRST).expect("proof succeeds");
    assert_eq!(
        proof.siblings.len(),
        1,
        "a depth-1 proof is exactly one sibling"
    );
    assert_eq!(proof.depth, 1);
    assert!(
        tree.verify(&proof, &element(0)).expect("verify succeeds"),
        "the depth-1 proof verifies"
    );
    assert!(
        verify_proof(&KeccakSolHasher, &proof, &element(0)).expect("verify succeeds"),
        "the depth-1 proof verifies standalone"
    );
}

/// Depth 63 is the largest valid depth (the u64 heap-index bound): creation
/// is accepted, the ladder spans 64 levels, and a proof at the very last
/// capacity index — whose heap index is `u64::MAX` — succeeds via the ladder
/// without overflow.
#[test]
fn depth_sixty_three_is_accepted_and_extreme_indexes_hold() {
    let mut tree = tree(63);
    assert_eq!(tree.capacity(), 1_u64 << 63);

    tree.set_leaf(LeafIndex::FIRST, &element(0), None)
        .expect("write succeeds");
    let proof = tree.proof(LeafIndex::FIRST).expect("proof succeeds");
    assert_eq!(proof.siblings.len(), 63);
    assert!(
        tree.verify(&proof, &element(0)).expect("verify succeeds"),
        "the depth-63 proof verifies"
    );

    // The last capacity index: leaf_heap(63, 2^63 - 1) = u64::MAX. The proof
    // resolves entirely from the ladder — no panic, no overflow — and a
    // foreign element does not verify at the tail index.
    let last = LeafIndex::new((1_u64 << 63) - 1);
    let tail_proof = tree.proof(last).expect("proof at the u64::MAX heap index");
    assert_eq!(tail_proof.siblings.len(), 63);
    assert!(
        !tree
            .verify(&tail_proof, &element(1))
            .expect("verify succeeds"),
        "a foreign element must not verify at the tail index"
    );
}

// ---------------------------------------------------------------- ordering

/// The multiproof ordering contract, asserted exactly: siblings
/// are emitted bottom-up, level by level, left to right within a level. For
/// leaves {0, 1, 2, 3, 4} of a depth-4 tree the needed sibling heaps are 21
/// (level 0), 11 (level 1), 3 (level 3) — all unoccupied, so the expected
/// values are exactly the ladder levels 0, 1, 3 in that order.
#[test]
fn multiproof_sibling_order_is_bottom_up_level_by_level_left_to_right() {
    let depth = 4;
    let mut tree = tree(depth);
    for leaf in [0_u64, 1, 2, 3, 4] {
        tree.set_leaf(LeafIndex::new(leaf), &element(leaf), None)
            .expect("write succeeds");
    }

    // The ladder, recomputed independently of the tree's own.
    let mut ladder = vec![Hash::ZERO];
    for _ in 0..depth {
        let previous = ladder[ladder.len() - 1];
        ladder.push(KeccakSolHasher.hash_pair(previous, previous));
    }

    let multi = tree
        .multiproof([
            LeafIndex::new(0),
            LeafIndex::new(1),
            LeafIndex::new(2),
            LeafIndex::new(3),
            LeafIndex::new(4),
        ])
        .expect("multiproof succeeds");
    assert_eq!(
        multi.siblings,
        vec![
            ladder[0], // heap 21
            ladder[1], // heap 11
            ladder[3], // heap 3
        ],
        "exact bottom-up, level-by-level, left-to-right order"
    );

    // And the ordered proof verifies.
    let elements: Vec<[u8; 32]> = [0_u64, 1, 2, 3, 4]
        .iter()
        .map(|&leaf| element(leaf))
        .collect();
    assert!(
        tree.verify_multi(&multi, &elements)
            .expect("verification is infallible here"),
        "the ordered multiproof verifies"
    );
}

/// The `expected_current` gate semantics: `None` is an unconditional
/// write — over an *occupied* leaf it bypasses the gate, and the outcome
/// reports the overwritten value as `previous`.
#[test]
fn overwriting_an_occupied_leaf_with_no_gate_bypasses_the_gate() {
    let mut tree = tree(6);
    tree.set_leaf(LeafIndex::new(3), &element(3), None)
        .expect("first write succeeds");

    let outcome = tree
        .set_leaf(LeafIndex::new(3), &element(9), None)
        .expect("None is an unconditional overwrite");
    assert_eq!(
        outcome.previous,
        KeccakSolHasher.hash_leaf(&element(3)).expect("hash"),
        "previous reports the overwritten value"
    );
    assert_eq!(
        tree.leaf_hash(LeafIndex::new(3))
            .expect("read succeeds")
            .expect("occupied"),
        KeccakSolHasher.hash_leaf(&element(9)).expect("hash"),
        "the overwrite landed"
    );

    // While Some(expected) over the occupied leaf is still a compare-and-swap.
    let error = tree
        .set_leaf(LeafIndex::new(3), &element(4), Some(Hash::ZERO))
        .expect_err("a stale gate over an occupied leaf is rejected");
    assert!(
        matches!(error, TreeError::UpdateMismatch { .. }),
        "expected UpdateMismatch, got {error:?}"
    );
}
