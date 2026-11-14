//! Tests for the incremental Merkle tree (`accumulators::merkle`).
//!
//! Covers the properties the redesign promises over v0.5:
//! - sparse create/open with persisted, validated metadata,
//! - the `set_leaf` update gate and its `previous` semantics,
//! - **the v0.5 non-power-of-2 regression**: proofs for *every* leaf of a
//!   scattered depth-10 tree succeed and verify — unoccupied siblings come
//!   from the zero ladder, never a missing store record,
//! - multiproof dedup and standalone verification,
//! - persistence across reopen, and index bounds.
//!
//! Roots used for verification come from [`SetOutcome::root`](accumulators::merkle::SetOutcome)
//! wherever the assertion is about *proof correctness*; assertions about the
//! tree's own `root()` tracking live in
//! [`root_reflects_writes_and_reopens`].

use accumulators::{
    hashers::{Blake2sHasher, Hasher, Keccak256Hasher},
    ids::AccumulatorId,
    merkle::{IncrementalMerkleTree, TreeCorrupted, TreeError},
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
fn tree(depth: u8) -> IncrementalMerkleTree<Keccak256Hasher, InMemoryStore> {
    IncrementalMerkleTree::create(
        Keccak256Hasher,
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
        Keccak256Hasher,
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
        expected = Keccak256Hasher.hash_pair(expected, expected);
    }
    assert_eq!(created.root(), expected);

    let reopened = IncrementalMerkleTree::open(Keccak256Hasher, store, AccumulatorId::ZERO)
        .expect("open succeeds");
    assert_eq!(reopened.capacity(), 1 << depth);
    assert_eq!(reopened.null_leaf(), Hash::ZERO);
    assert_eq!(reopened.root(), created.root());
}

#[test]
fn create_rejects_depth_out_of_range() {
    // Valid depth is 1..=63; both bounds must be rejected as invalid depth.
    for depth in [0, 64, 255] {
        let error = IncrementalMerkleTree::create(
            Keccak256Hasher,
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
        IncrementalMerkleTree::open(Keccak256Hasher, InMemoryStore::new(), AccumulatorId::ZERO)
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
    assert_eq!(first.previous, Some(Hash::ZERO));
    assert_ne!(first.root, root_before, "the write must change the root");

    // Re-writing requires the gate; `previous` is the hash of the stored
    // element, not the element itself.
    let first_hash = Keccak256Hasher
        .hash_leaf(&element(5))
        .expect("valid element");
    let second = tree
        .set_leaf(index, &element(6), Some(first_hash))
        .expect("gated write succeeds");
    assert_eq!(second.previous, Some(first_hash));
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
    let second_hash = Keccak256Hasher
        .hash_leaf(&element(6))
        .expect("valid element");
    let third = tree
        .set_leaf(index, &element(7), Some(second_hash))
        .expect("correct gate value is accepted");
    assert_eq!(third.previous, Some(second_hash));
}

/// `root()` must track writes in-session and the persisted root must be
/// restored on reopen. This is the contract the proofs commit against.
#[test]
fn root_reflects_writes_and_reopens() {
    let store = InMemoryStore::new();
    let mut tree = IncrementalMerkleTree::create(
        Keccak256Hasher,
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
    let reopened = IncrementalMerkleTree::open(Keccak256Hasher, store, AccumulatorId::ZERO)
        .expect("reopen succeeds");
    assert_eq!(
        reopened.root(),
        second.root,
        "open() must restore the persisted root"
    );
}

/// The v0.5 non-power-of-2 regression: in v0.5, `get_inclusion_proof` hit
/// missing store keys (`NotFound`) for ~18% of leaves whose sibling path ran
/// through null-padded sub-trees. Here proofs for *every* leaf of a
/// scattered depth-10 tree must succeed, and the occupied ones must verify
/// against the current root.
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
        assert_eq!(proof.len(), 10, "proof is exactly `depth` siblings");

        if occupied.binary_search(&leaf).is_ok() {
            assert!(
                tree.verify(index, &element(leaf), &proof, root)
                    .expect("verify succeeds"),
                "occupied leaf {leaf} must verify against the root"
            );
            assert!(
                !tree
                    .verify(index, &element(leaf + 4096), &proof, root)
                    .expect("verify succeeds"),
                "a different element must not verify for leaf {leaf}"
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

    // Structural failures are `Ok(false)`, not errors: a truncated proof…
    assert!(
        !tree
            .verify(
                LeafIndex::new(3),
                &element(3),
                &proof[..proof.len() - 1],
                root
            )
            .expect("verify succeeds"),
        "a truncated proof must not verify"
    );
    // …an over-long proof…
    let mut extended = proof.clone();
    extended.push(Hash::ZERO);
    assert!(
        !tree
            .verify(LeafIndex::new(3), &element(3), &extended, root)
            .expect("verify succeeds"),
        "an over-long proof must not verify"
    );
    // …the right proof against the wrong root…
    assert!(
        !tree
            .verify(LeafIndex::new(3), &element(3), &proof, Hash::ZERO)
            .expect("verify succeeds"),
        "a wrong root must not verify"
    );
    // …and the right proof at the wrong index.
    assert!(
        !tree
            .verify(LeafIndex::new(2), &element(3), &proof, root)
            .expect("verify succeeds"),
        "a wrong index must not verify"
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
        .map(|&index| full.proof(index).expect("proof succeeds").len())
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
    // A wrong element count fails structurally, not with an error.
    assert!(
        !tree
            .verify_multi(&multi, &elements[..elements.len() - 1])
            .expect("verification is infallible here"),
        "a mismatched element count must not verify"
    );
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
    assert!(
        matches!(
            tree.verify(index, &element(0), &[], Hash::ZERO),
            Err(TreeError::IndexOutOfRange { .. })
        ),
        "verify beyond capacity is rejected"
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
    let hasher = Keccak256Hasher;
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
            .verify(LeafIndex::new(17), &element(17), &proof, root)
            .expect("verify succeeds"),
        "a proof taken after the reopen must verify"
    );

    // Writes continue from the restored state, and earlier proofs stay
    // verifiable against the root they were taken at.
    reopened
        .set_leaf(LeafIndex::new(200), &element(200), None)
        .expect("post-reopen write succeeds");
    assert_ne!(reopened.root(), root);
    assert!(
        reopened
            .verify(LeafIndex::new(17), &element(17), &proof, root)
            .expect("verify succeeds"),
        "the captured proof is a standalone commitment to the captured root"
    );
}

#[test]
fn open_rejects_a_different_hasher_config() {
    let store = InMemoryStore::new();
    let created = IncrementalMerkleTree::create(
        Blake2sHasher { truncate: false },
        store.clone(),
        AccumulatorId::ZERO,
        8,
        Hash::ZERO,
    )
    .expect("create succeeds");
    drop(created);

    // Same hasher id, different persisted config: the truncation flag is
    // part of the metadata and must not be silently ignored.
    let error =
        IncrementalMerkleTree::open(Blake2sHasher { truncate: true }, store, AccumulatorId::ZERO)
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
        Keccak256Hasher,
        store.clone(),
        AccumulatorId::ZERO,
        4,
        Hash::ZERO,
    )
    .expect("create succeeds");
    drop(created);

    let error = IncrementalMerkleTree::open(
        Blake2sHasher { truncate: false },
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
