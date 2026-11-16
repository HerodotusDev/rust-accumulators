//! Async-tree parity tests over the SQLite store: create/open round trips,
//! the `set_leaf` gate, proving every leaf of a scattered tree, self-
//! contained proofs (truncation as a typed error, tamper as `false`),
//! multiproofs, and the `open` metadata validation — mirroring the sync
//! suite's shape (`tests/merkle.rs`).

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "merkle_tree",
    feature = "sqlite",
    feature = "keccak_sol",
    not(target_family = "wasm")
))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::{Blake2sStarkHasher, Hasher, KeccakSolHasher};
use accumulators::ids::AccumulatorId;
use accumulators::merkle::{
    AsyncIncrementalMerkleTree, TreeCorrupted, TreeError, TreeMultiProof, TreeProof,
    TreeProofInconsistent, TreeVerifyError, verify_multi_proof, verify_proof,
};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::keys::{self, Table};
use accumulators::store::sqlite::SqliteStore;
use accumulators::store::{AsyncStore as _, Batch};

use common::{TempDb, element, id};

type TestTree = AsyncIncrementalMerkleTree<KeccakSolHasher, SqliteStore>;

/// An empty keccak tree of `depth` levels with the all-zero null leaf,
/// stored in the database named by `db` — the guard must outlive the tree
/// (the pool opens connections lazily; an unlinked file would be re-created
/// empty on the next connection).
async fn tree(db: &TempDb, depth: u8) -> TestTree {
    let store = SqliteStore::connect(db.path())
        .await
        .expect("connect succeeds");
    AsyncIncrementalMerkleTree::create(KeccakSolHasher, store, id(1), depth, Hash::ZERO)
        .await
        .expect("tree creation succeeds")
}

/// Overwrites a single-subkey record straight through the store — the
/// corruption-injection helper mirroring the sync suite's `poke`.
async fn poke(store: &SqliteStore, id: AccumulatorId, table: Table, value: &[u8]) {
    let mut batch = Batch::new();
    batch.put_owned(keys::encode(&id, table, 0), value.to_vec());
    store
        .write(batch)
        .await
        .expect("sqlite writes only fail on I/O");
}

// ------------------------------------------------------- lifecycle + roots

mod lifecycle {
    use super::*;

    #[tokio::test]
    async fn create_open_round_trip_and_empty_root() {
        let db = TempDb::new("round-trip");
        let path = db.path();
        let store = SqliteStore::connect(path).await.expect("connect");
        let created =
            AsyncIncrementalMerkleTree::create(KeccakSolHasher, store, id(1), 8, Hash::ZERO)
                .await
                .expect("create succeeds");
        assert_eq!(created.capacity(), 1 << 8);
        assert_eq!(created.null_leaf(), Hash::ZERO);

        // The empty root is the top of the zero ladder: the null leaf folded
        // through `depth` pair hashes.
        let mut expected = Hash::ZERO;
        for _ in 0..8 {
            expected = KeccakSolHasher.hash_pair(expected, expected);
        }
        assert_eq!(created.root(), expected);

        let reopened_store = SqliteStore::connect(path).await.expect("reconnect");
        let reopened = TestTree::open(KeccakSolHasher, reopened_store, id(1))
            .await
            .expect("open succeeds");
        assert_eq!(reopened.capacity(), 1 << 8);
        assert_eq!(reopened.null_leaf(), Hash::ZERO);
        assert_eq!(reopened.root(), created.root());
    }

    /// The pure gates reject through the async shell: out-of-range depth at
    /// create, out-of-range index on every leaf-addressing operation.
    #[tokio::test]
    async fn pure_gates_reject_through_the_async_shell() {
        // Valid depth is 1..=63; both bounds must be rejected as invalid depth.
        for depth in [0_u8, 64, 255] {
            let db = TempDb::new("depth");
            let store = SqliteStore::connect(db.path()).await.expect("connect");
            let error = AsyncIncrementalMerkleTree::create(
                KeccakSolHasher,
                store,
                id(1),
                depth,
                Hash::ZERO,
            )
            .await
            .err()
            .expect("out-of-range depth is rejected");
            assert!(
                matches!(error, TreeError::InvalidDepth { depth: rejected } if rejected == depth),
                "depth {depth} must be rejected as invalid depth, got {error:?}"
            );
        }

        // The index gate guards every leaf-addressing operation.
        let db = TempDb::new("bounds");
        let mut tree = tree(&db, 4).await;
        let index = LeafIndex::new(16);
        let capacity = tree.capacity();

        let error = tree
            .set_leaf(index, &element(16), None)
            .await
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
            matches!(
                tree.proof(index).await,
                Err(TreeError::IndexOutOfRange { .. })
            ),
            "proof beyond capacity is rejected"
        );
        assert!(
            matches!(
                tree.leaf_hash(index).await,
                Err(TreeError::IndexOutOfRange { .. })
            ),
            "leaf_hash beyond capacity is rejected"
        );
        assert!(
            matches!(
                tree.multiproof([LeafIndex::new(0), index]).await,
                Err(TreeError::IndexOutOfRange { .. })
            ),
            "multiproof with any out-of-range index is rejected"
        );
    }

    /// Open validation: a store without metadata is `MissingMetadata`;
    /// tampered persisted metadata (a depth byte out of range) is
    /// `MalformedMetadata`.
    #[tokio::test]
    async fn open_without_metadata_is_corrupted() {
        let db = TempDb::new("empty-store");
        let store = SqliteStore::connect(db.path()).await.expect("connect");
        let error = TestTree::open(KeccakSolHasher, store, id(1))
            .await
            .err()
            .expect("opening an empty store cannot succeed");
        assert!(
            matches!(error, TreeError::Corrupted(TreeCorrupted::MissingMetadata)),
            "expected MissingMetadata, got {error:?}"
        );

        // A present-but-unparsable metadata record: the depth byte is out
        // of range, diagnosed as MalformedMetadata — never a silent open.
        let db = TempDb::new("tampered-meta");
        let path = db.path();
        let store = SqliteStore::connect(path).await.expect("connect");
        AsyncIncrementalMerkleTree::create(KeccakSolHasher, store.clone(), id(1), 8, Hash::ZERO)
            .await
            .expect("create succeeds");
        poke(&store, id(1), Table::TreeMeta, &[0xff, 0x00]).await;

        let reopened = SqliteStore::connect(path).await.expect("reconnect");
        match TestTree::open(KeccakSolHasher, reopened, id(1)).await {
            Err(TreeError::Corrupted(TreeCorrupted::MalformedMetadata)) => {}
            Err(other) => panic!("expected MalformedMetadata, got {other:?}"),
            Ok(_) => panic!("expected MalformedMetadata, but the tree opened"),
        }
    }

    #[tokio::test]
    async fn open_rejects_a_different_hasher() {
        let db = TempDb::new("hasher-mismatch");
        let path = db.path();
        let store = SqliteStore::connect(path).await.expect("connect");
        AsyncIncrementalMerkleTree::create(
            Blake2sStarkHasher { truncate: false },
            store,
            id(1),
            4,
            Blake2sStarkHasher { truncate: false }.genesis(),
        )
        .await
        .expect("create succeeds");

        let reopened = SqliteStore::connect(path).await.expect("reconnect");
        let error = AsyncIncrementalMerkleTree::<Blake2sStarkHasher, _>::open(
            Blake2sStarkHasher { truncate: true },
            reopened,
            id(1),
        )
        .await
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

    /// `root()` must track writes in-session and the persisted root must be
    /// restored on reopen. This is the contract the proofs commit against.
    #[tokio::test]
    async fn root_reflects_writes_and_reopens() {
        let db = TempDb::new("root-tracking");
        let path = db.path();
        let store = SqliteStore::connect(path).await.expect("connect");
        let mut tree =
            AsyncIncrementalMerkleTree::create(KeccakSolHasher, store, id(1), 8, Hash::ZERO)
                .await
                .expect("create succeeds");

        let first = tree
            .set_leaf(LeafIndex::new(5), &element(5), None)
            .await
            .expect("first write succeeds");
        assert_eq!(tree.root(), first.root, "root() must track set_leaf");

        drop(tree);
        let reopened_store = SqliteStore::connect(path).await.expect("reconnect");
        let reopened = TestTree::open(KeccakSolHasher, reopened_store, id(1))
            .await
            .expect("reopen succeeds");
        assert_eq!(
            reopened.root(),
            first.root,
            "open() must restore the persisted root"
        );
    }
}

// ------------------------------------------------------------- set + gate

mod set_leaf {
    use super::*;

    /// First write onto an unoccupied leaf, the gate, a wrong gate value,
    /// and the correct one — the sync suite's `set_leaf` contract, awaited.
    #[tokio::test]
    async fn update_gate_and_previous_semantics() {
        let db = TempDb::new("gate");
        let mut tree = tree(&db, 8).await;
        let index = LeafIndex::new(5);
        let root_before = tree.root();

        // First write onto an unoccupied leaf: the leaf read as the null leaf.
        let first = tree
            .set_leaf(index, &element(5), None)
            .await
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
            .await
            .expect("gated write succeeds");
        assert_eq!(second.previous, first_hash);
        assert_ne!(second.root, first.root);

        // A wrong gate value is rejected and leaves the tree untouched.
        let error = tree
            .set_leaf(index, &element(7), Some(Hash::ZERO))
            .await
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
            .await
            .expect("correct gate value is accepted");
        assert_eq!(third.previous, second_hash);
    }

    #[tokio::test]
    async fn leaf_hash_distinguishes_occupied_from_unoccupied() {
        let db = TempDb::new("leaf-hash");
        let mut tree = tree(&db, 6).await;
        tree.set_leaf(LeafIndex::new(3), &element(3), None)
            .await
            .expect("write succeeds");

        let occupied = tree
            .leaf_hash(LeafIndex::new(3))
            .await
            .expect("read succeeds")
            .expect("leaf 3 is occupied");
        assert_eq!(
            occupied,
            KeccakSolHasher.hash_leaf(&element(3)).expect("hash")
        );

        assert_eq!(
            tree.leaf_hash(LeafIndex::new(4))
                .await
                .expect("read succeeds"),
            None,
            "an unoccupied leaf reads as None, never the ladder's null value"
        );
    }
}

// ----------------------------------------------------------------- proofs

mod proofs {
    use super::*;

    /// A scattered (non-power-of-2 occupancy) tree must prove *every* leaf:
    /// sibling paths crossing unoccupied sub-trees resolve through the zero
    /// ladder, never a missing store record. The proof is self-contained —
    /// the standalone verifier accepts it with no tree and no store.
    #[tokio::test]
    async fn every_leaf_of_a_scattered_tree_proves_and_verifies() {
        let db = TempDb::new("scattered");
        let mut tree = tree(&db, 8).await;
        assert_eq!(tree.capacity(), 256);

        let mut occupied: Vec<u64> = (0..256).step_by(7).collect();
        occupied.extend_from_slice(&[0, 1, 254, 255]);
        occupied.sort_unstable();
        occupied.dedup();
        for &leaf in &occupied {
            tree.set_leaf(LeafIndex::new(leaf), &element(leaf), None)
                .await
                .expect("leaf write succeeds");
        }

        for leaf in 0..256_u64 {
            let index = LeafIndex::new(leaf);
            let proof = tree
                .proof(index)
                .await
                .expect("proof succeeds for every index within capacity");
            assert_eq!(proof.siblings.len(), 8, "proof is exactly `depth` siblings");
            assert_eq!(proof.root, tree.root());

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
            }
        }

        // Self-containment through the async shell: the standalone verifier
        // needs no tree and no store.
        let proof = tree
            .proof(LeafIndex::new(42))
            .await
            .expect("proof succeeds");
        drop(tree);
        assert!(
            verify_proof(&KeccakSolHasher, &proof, &element(42)).expect("verify succeeds"),
            "the proof verifies against its own root with nothing else alive"
        );
        assert!(
            !verify_proof(&KeccakSolHasher, &proof, &element(43)).expect("verify succeeds"),
            "a foreign element must not verify standalone"
        );
    }

    /// Structural truncation is a typed error; tamper is `Ok(false)`; the
    /// handle-level verify pins the proof to the tree's *current* root.
    #[tokio::test]
    async fn verify_rejects_bad_proofs() {
        let db = TempDb::new("bad-proofs");
        let mut tree = tree(&db, 8).await;
        tree.set_leaf(LeafIndex::new(3), &element(3), None)
            .await
            .expect("write succeeds");
        let proof = tree.proof(LeafIndex::new(3)).await.expect("proof succeeds");

        // A truncated proof is a typed structural error, not a negative result.
        let truncated = TreeProof {
            siblings: proof.siblings[..proof.siblings.len() - 1].to_vec(),
            ..proof.clone()
        };
        assert!(matches!(
            verify_proof(&KeccakSolHasher, &truncated, &element(3)),
            Err(TreeVerifyError::Inconsistent(
                TreeProofInconsistent::PathLengthMismatch { .. }
            ))
        ));

        // A tampered sibling folds somewhere other than the proof's root.
        let mut tampered = proof.clone();
        tampered.siblings[1] = Hash::ZERO;
        assert!(
            !verify_proof(&KeccakSolHasher, &tampered, &element(3)).expect("verify succeeds"),
            "a tampered sibling must not verify"
        );

        // The handle-level verify pins the proof to the current root; after
        // another write the standalone verdict is unchanged.
        assert!(tree.verify(&proof, &element(3)).expect("verify succeeds"));
        tree.set_leaf(LeafIndex::new(5), &element(5), None)
            .await
            .expect("write succeeds");
        assert!(!tree.verify(&proof, &element(3)).expect("verify succeeds"));
        assert!(
            verify_proof(&KeccakSolHasher, &proof, &element(3)).expect("verify succeeds"),
            "the captured proof remains a standalone commitment to its own root"
        );
    }

    #[tokio::test]
    async fn multiproof_round_trips_and_verifies_standalone() {
        let db = TempDb::new("multiproof");
        let mut tree = tree(&db, 12).await;
        let leaves = [1_u64, 5, 9, 3, 100, 4095];
        for &leaf in &leaves {
            tree.set_leaf(LeafIndex::new(leaf), &element(leaf), None)
                .await
                .expect("write succeeds");
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
            .await
            .expect("multiproof succeeds within capacity");
        let expected: Vec<LeafIndex> = [1_u64, 3, 5, 9, 100, 4095]
            .iter()
            .copied()
            .map(LeafIndex::new)
            .collect();
        assert_eq!(multi.indexes, expected);
        assert_eq!(multi.root, tree.root());

        // Elements must align positionally with the proof's (normalized,
        // ascending) indexes.
        let elements: Vec<Vec<u8>> = [1_u64, 3, 5, 9, 100, 4095]
            .iter()
            .map(|&leaf| element(leaf))
            .collect();
        assert!(
            tree.verify_multi(&multi, &elements)
                .expect("verification is infallible here"),
            "the scattered multiproof must verify against the current root"
        );
        assert!(
            verify_multi_proof(&KeccakSolHasher, &multi, &elements).expect("verify succeeds"),
            "the self-contained multiproof must verify standalone"
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
        // A wrong element count is structural — a typed error.
        assert!(matches!(
            tree.verify_multi(&multi, &elements[..elements.len() - 1]),
            Err(TreeError::Proof(TreeVerifyError::Inconsistent(
                TreeProofInconsistent::ElementCountMismatch { .. }
            )))
        ));

        // A truncated sibling list is a typed structural error.
        let truncated = TreeMultiProof {
            siblings: multi.siblings[..multi.siblings.len() - 1].to_vec(),
            ..multi.clone()
        };
        assert!(matches!(
            verify_multi_proof(&KeccakSolHasher, &truncated, &elements),
            Err(TreeVerifyError::Inconsistent(
                TreeProofInconsistent::SiblingCountMismatch { .. }
            ))
        ));
    }
}

// ------------------------------------------------------------- corruption

mod corruption {
    use super::*;

    /// A present-but-unparsable sibling node is
    /// [`TreeCorrupted::MalformedNode`] — never a ladder substitution
    /// producing a wrong proof.
    #[tokio::test]
    async fn a_poisoned_sibling_node_is_malformed_never_a_wrong_proof() {
        let db = TempDb::new("poisoned");
        let path = db.path();
        let store = SqliteStore::connect(path).await.expect("connect");
        let mut tree = AsyncIncrementalMerkleTree::create(
            KeccakSolHasher,
            store.clone(),
            id(1),
            4,
            Hash::ZERO,
        )
        .await
        .expect("create succeeds");
        // Leaf 0 occupies heap 16; leaf 1's sibling path reads heap 16.
        tree.set_leaf(LeafIndex::new(0), &element(0), None)
            .await
            .expect("write succeeds");

        // The poisoned node: heap 16 (leaf 0), an unparsable value.
        let mut batch = Batch::new();
        batch.put_owned(keys::encode(&id(1), Table::TreeNode, 16), vec![0xff; 3]);
        store
            .write(batch)
            .await
            .expect("in-memory writes are infallible");

        match tree.proof(LeafIndex::new(1)).await {
            Err(TreeError::Corrupted(TreeCorrupted::MalformedNode)) => {}
            other => panic!("expected MalformedNode, got {other:?}"),
        }
        match tree.leaf_hash(LeafIndex::new(0)).await {
            Err(TreeError::Corrupted(TreeCorrupted::MalformedNode)) => {}
            other => panic!("expected MalformedNode, got {other:?}"),
        }
        // The write path fails closed too: a poisoned sibling on the edit
        // path must refuse the write rather than fold the ladder hash over
        // garbage.
        match tree.set_leaf(LeafIndex::new(1), &element(1), None).await {
            Err(TreeError::Corrupted(TreeCorrupted::MalformedNode)) => {}
            other => panic!("expected MalformedNode on the write path, got {other:?}"),
        }
    }
}

// ------------------------------------------------------------ send bounds

mod send_bounds {
    use super::*;

    /// Compile-time Send assertions for the documented bounds (see the
    /// `async_tree` module docs): `S: AsyncStore + Send + Sync + 'static`,
    /// `H: Hasher + Send + Sync` with `H::Output: Send + Sync`,
    /// `Id: TreeId + Send + Sync`. Every `assert_send` call is the
    /// assertion; awaiting keeps the futures real.
    #[tokio::test]
    async fn the_public_futures_are_send_under_the_documented_bounds() {
        fn assert_send<T: Send>(future: T) -> T {
            future
        }

        let db = TempDb::new("send-bounds");
        let path = db.path();
        let store = SqliteStore::connect(path).await.expect("connect");
        let mut tree = TestTree::create(KeccakSolHasher, store, id(1), 8, Hash::ZERO)
            .await
            .expect("create");
        tree.set_leaf(LeafIndex::new(0), &element(0), None)
            .await
            .expect("set_leaf");

        // The `&self` methods (proof reads, verification inputs).
        let proof = assert_send(tree.proof(LeafIndex::new(0)))
            .await
            .expect("proof");
        assert!(tree.verify(&proof, &element(0)).expect("verify"));
        assert_send(tree.multiproof([LeafIndex::new(0)]))
            .await
            .expect("multiproof");
        assert_send(tree.leaf_hash(LeafIndex::new(0)))
            .await
            .expect("leaf hash");

        // The `&mut self` methods (writes).
        assert_send(tree.set_leaf(LeafIndex::new(1), &element(1), None))
            .await
            .expect("set_leaf");

        // An associated async constructor's future.
        drop(tree);
        let store = SqliteStore::connect(path).await.expect("reconnect");
        let reopened = assert_send(TestTree::open(KeccakSolHasher, store, id(1)))
            .await
            .expect("open");
        assert_eq!(reopened.capacity(), 256);
    }
}
