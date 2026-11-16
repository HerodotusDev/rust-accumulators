//! Async stacked-MMR test suite: the async twins of the sync `tests/stacked.rs`
//! contract over the SQLite store — pin/stack construction, root equality
//! with a single-MMR reference, independent growth under a pin, the
//! nullifier pin rules (shallow vs deep, including the middle-layer
//! resolution), `open_stacked` over retrievable async stores, and the
//! sub-view validation contract.
//!
//! Every root assertion is checked against an independent reference
//! computation built directly on [`Hasher::hash_pair`].

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "stacked_mmr",
    feature = "sqlite",
    feature = "keccak_sol",
    not(target_family = "wasm")
))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::{Blake2sStarkHasher, Hasher as _, KeccakSolHasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::async_mmr::open_stacked_append_only;
use accumulators::mmr::{
    AsyncMmr, AsyncStackedAppendMmr, AsyncStackedNullifyingMmr, Corrupted, InvalidSubViews,
    MmrError, NullifierRecord, Nullifying, Plain, Stacked, StackingError, SubView,
};
use accumulators::mmr::{LeafCount, MmrSize};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::keys::{self, Table};
use accumulators::store::sqlite::SqliteStore;
use accumulators::store::{AsyncStore as _, Batch, ErasedAsyncStore};
use accumulators::utils::mmr::size_of;

use common::{TempDb, element, elements, id, reference_root, slices};

type TestMmr = AsyncMmr<KeccakSolHasher, SqliteStore>;
type TestMmrNull = AsyncMmr<KeccakSolHasher, SqliteStore, Plain, Nullifying>;
type TestStacked = AsyncStackedAppendMmr<KeccakSolHasher, SqliteStore>;
type TestStackedNull = AsyncStackedNullifyingMmr<KeccakSolHasher, SqliteStore>;
type TestError = MmrError<SqliteStore>;

// ---------------------------------------------------------------- helpers

fn hasher() -> KeccakSolHasher {
    KeccakSolHasher
}

async fn fresh(label: &str) -> (TempDb, SqliteStore) {
    let db = TempDb::new(label);
    let store = SqliteStore::connect(db.path()).await.expect("connect");
    (db, store)
}

async fn poke(store: &SqliteStore, id: AccumulatorId, table: Table, value: &[u8]) {
    let mut batch = Batch::new();
    batch.put_owned(keys::encode(&id, table, 0), value.to_vec());
    store
        .write(batch)
        .await
        .expect("sqlite writes only fail on I/O");
}

fn expect_nullified(proof: Result<accumulators::mmr::Proof<Hash>, TestError>, leaf: LeafIndex) {
    match proof {
        Err(MmrError::LeafNullified { leaf: refused }) => {
            assert_eq!(refused, leaf, "the error must name the requested leaf");
        }
        Err(other) => panic!("expected LeafNullified for leaf {leaf}, got {other:?}"),
        Ok(_) => panic!("expected LeafNullified for leaf {leaf}, but the proof was issued"),
    }
}

// ----------------------------------------------------------- construction

mod construction {
    use super::*;

    #[tokio::test]
    async fn stacked_root_equals_the_reference_over_all_layers() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-construction-a").await;
        let (_db_b, store_b) = fresh("astack-construction-b").await;
        let mut base = TestMmr::create(h, store_a, id(1))
            .await
            .expect("create base");
        for i in 0..8 {
            base.append(&element(i)).await.expect("append must succeed");
        }

        let pin = base.pin();
        assert_eq!(
            pin.pinned_size(),
            base.size(),
            "the pin freezes the node count"
        );
        assert_eq!(pin.id(), id(1), "the pin carries the sub-MMR's id");

        let mut stacked = TestStacked::stack(h, store_b, id(2), [pin])
            .await
            .expect("stack");
        assert_eq!(
            stacked.leaf_count(),
            LeafCount::new(8),
            "the stack starts at the pin's leaf count"
        );
        assert_eq!(
            stacked.size(),
            base.size(),
            "with no own appends the size equals the pin"
        );

        for i in 8..12 {
            stacked
                .append(&element(i))
                .await
                .expect("append on the stack");
        }
        assert_eq!(stacked.leaf_count(), LeafCount::new(12));
        assert_eq!(
            stacked.root(),
            reference_root(&h, &slices(&elements(12))),
            "the stacked root must equal a single MMR over all layers' elements"
        );
        for leaf in [0_u64, 3, 7, 11] {
            let proof = stacked
                .proof(LeafIndex::new(leaf))
                .await
                .expect("proof through the stack");
            assert!(
                stacked.verify(&proof, &element(leaf)).expect("verify"),
                "leaf {leaf} must verify through the stack"
            );
        }
        drop(stacked);
        drop(base);
    }

    #[tokio::test]
    async fn the_pin_freezes_the_stack_against_base_growth() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-freeze-a").await;
        let (_db_b, store_b) = fresh("astack-freeze-b").await;
        let mut base = TestMmr::create(h, store_a, id(1))
            .await
            .expect("create base");
        for i in 0..8 {
            base.append(&element(i)).await.expect("append must succeed");
        }

        let pin = base.pin();
        let stacked = TestStacked::stack(h, store_b, id(2), [pin])
            .await
            .expect("stack");
        let frozen_root = stacked.root();
        let frozen_size = stacked.size();

        for i in 8..14 {
            base.append(&element(i)).await.expect("append must succeed");
        }
        assert_eq!(base.leaf_count(), LeafCount::new(14));
        assert_eq!(
            base.root(),
            reference_root(&h, &slices(&elements(14))),
            "the base's own root reflects its growth"
        );
        assert_eq!(
            stacked.root(),
            frozen_root,
            "the stack must not see the base's post-pin growth"
        );
        assert_eq!(stacked.size(), frozen_size);

        let proof = stacked
            .proof(LeafIndex::new(3))
            .await
            .expect("proof through the stack");
        assert!(
            stacked.verify(&proof, &element(3)).expect("verify"),
            "stacked proofs stay pinned to the frozen view"
        );
        drop(stacked);
        drop(base);
    }

    #[tokio::test]
    async fn three_layers_stack_and_route_reads_through_both_pins() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-three-a").await;
        let (_db_b, store_b) = fresh("astack-three-b").await;
        let (_db_c, store_c) = fresh("astack-three-c").await;
        let mut a = TestMmr::create(h, store_a, id(1)).await.expect("create a");
        for i in 0..4 {
            a.append(&element(i)).await.expect("append must succeed");
        }
        let pin_a = a.pin();
        let mut b = TestStacked::stack(h, store_b, id(2), [pin_a])
            .await
            .expect("stack b");
        for i in 4..7 {
            b.append(&element(i)).await.expect("append must succeed");
        }

        let pin_a = a.pin();
        let pin_b = b.pin();
        assert_eq!(pin_b.pinned_size(), b.size());
        let mut c = TestStacked::stack(h, store_c, id(3), [pin_a, pin_b])
            .await
            .expect("stack c");
        for i in 7..9 {
            c.append(&element(i)).await.expect("append must succeed");
        }

        assert_eq!(
            c.root(),
            reference_root(&h, &slices(&elements(9))),
            "three layers must equal one flat MMR over all nine elements"
        );
        for leaf in [0_u64, 5, 8] {
            let proof = c
                .proof(LeafIndex::new(leaf))
                .await
                .expect("proof through both pins");
            assert!(c.verify(&proof, &element(leaf)).expect("verify"));
        }
        drop(c);
        drop(b);
        drop(a);
    }

    #[tokio::test]
    async fn an_append_only_layer_can_stack_over_a_nullifying_pin() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-null-pin-a").await;
        let (_db_b, store_b) = fresh("astack-null-pin-b").await;
        let mut base = TestMmrNull::create_nullifying(h, store_a, id(1))
            .await
            .expect("create");
        for i in 0..5 {
            base.append(&element(i)).await.expect("append must succeed");
        }
        base.nullify_shallow(LeafIndex::new(2))
            .await
            .expect("nullify");

        let pin = base.pin();
        let stacked: TestStacked = AsyncMmr::stack(h, store_b, id(2), [pin])
            .await
            .expect("stack");
        assert_eq!(
            stacked.root(),
            reference_root(&h, &slices(&elements(5))),
            "stacking is orthogonal to the base's mode"
        );
        drop(stacked);
        drop(base);
    }

    #[tokio::test]
    async fn an_erased_pin_builds_a_session_local_mixed_stack() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-erased-a").await;
        let mut base = TestMmr::create(h, store_a, id(1))
            .await
            .expect("create base");
        for i in 0..5 {
            base.append(&element(i)).await.expect("append must succeed");
        }

        let pin: SubView<ErasedAsyncStore, AccumulatorId> = base.pin().erased_async();
        assert_eq!(
            pin.pinned_size(),
            base.size(),
            "erasure keeps the pin metadata"
        );
        let stacked = AsyncMmr::<KeccakSolHasher, ErasedAsyncStore, Stacked>::stack(
            h,
            ErasedAsyncStore::new(
                SqliteStore::connect(TempDb::new("astack-erased-top").path())
                    .await
                    .expect("connect"),
            ),
            id(2),
            [pin],
        )
        .await
        .expect("stack over erased stores");
        assert_eq!(
            stacked.root(),
            reference_root(&h, &slices(&elements(5))),
            "an erased stack behaves like a concrete one"
        );
        drop(stacked);
        drop(base);
    }
}

// --------------------------------------------------- cross-layer multiproofs

mod cross_layer_multiproofs {
    use super::*;

    /// A stacked multiproof whose leaves span BOTH layers, with the pool
    /// dedup contract asserted against the per-leaf sibling sum.
    #[tokio::test]
    async fn a_multiproof_spanning_layers_dedups_and_verifies() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-multi-a").await;
        let (_db_b, store_b) = fresh("astack-multi-b").await;
        let mut base = TestMmr::create(h, store_a, id(1))
            .await
            .expect("create base");
        let base_els = elements(20);
        for el in &base_els {
            base.append(el).await.expect("append must succeed");
        }
        let pin = base.pin();
        let mut stacked = TestStacked::stack(h, store_b, id(2), [pin])
            .await
            .expect("stack");
        let top_els: Vec<Vec<u8>> = (20..40).map(element).collect();
        for el in &top_els {
            stacked.append(el).await.expect("append must succeed");
        }

        // Two adjacent leaves from the pinned layer (they share every
        // sibling above height 0) plus one from the stack's own layer.
        let leaves = [LeafIndex::new(4), LeafIndex::new(5), LeafIndex::new(30)];
        let multi = stacked
            .multiproof(leaves)
            .await
            .expect("cross-layer multiproof");
        assert!(
            stacked
                .verify_multi(&multi, [&base_els[4], &base_els[5], &top_els[10]])
                .expect("verify"),
            "the spanning multiproof must verify"
        );
        assert!(
            !stacked
                .verify_multi(&multi, [&base_els[6], &base_els[5], &top_els[10]])
                .expect("verify"),
            "a wrong element must not verify"
        );

        let per_leaf: usize = {
            let mut sum = 0;
            for &leaf in &leaves {
                sum += stacked.proof(leaf).await.expect("proof").siblings.len();
            }
            sum
        };
        assert!(
            multi.sibling_pool.len() < per_leaf,
            "pool dedup: {} pooled siblings must beat {} per-leaf siblings",
            multi.sibling_pool.len(),
            per_leaf
        );
        drop(stacked);
        drop(base);
    }

    /// `leaf_hash` reads through the stack for both pinned-layer and
    /// own-layer leaves — the gate-sourcing read works at every layer.
    #[tokio::test]
    async fn leaf_hash_reads_through_the_stack() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-leaf-hash-a").await;
        let (_db_b, store_b) = fresh("astack-leaf-hash-b").await;
        let mut base = TestMmr::create(h, store_a, id(1))
            .await
            .expect("create base");
        for el in &elements(5) {
            base.append(el).await.expect("append must succeed");
        }
        let pin = base.pin();
        let mut stacked = TestStacked::stack(h, store_b, id(2), [pin])
            .await
            .expect("stack");
        stacked.append(b"own").await.expect("append must succeed");

        for leaf in 0..5_u64 {
            assert_eq!(
                stacked.leaf_hash(LeafIndex::new(leaf)).await.expect("read"),
                Some(h.hash_leaf(&element(leaf)).expect("hash")),
                "pinned-layer leaf {leaf} reads through the stack"
            );
        }
        assert_eq!(
            stacked.leaf_hash(LeafIndex::new(5)).await.expect("read"),
            Some(h.hash_leaf(b"own").expect("hash")),
            "the stack's own leaf reads directly"
        );
        assert!(stacked.leaf_hash(LeafIndex::new(6)).await.is_err());
        drop(stacked);
        drop(base);
    }
}

// ------------------------------------------------------------ validation

mod validation {
    use super::*;

    #[tokio::test]
    async fn stacking_rejects_duplicate_pin_sizes() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-dup-a").await;
        let (_db_b, store_b) = fresh("astack-dup-b").await;
        let mut base = TestMmr::create(h, store_a, id(1))
            .await
            .expect("create base");
        base.append(b"a").await.expect("append must succeed");
        let first = base.pin();
        let second = base.pin();

        match TestStacked::stack(h, store_b, id(2), [first, second]).await {
            Err(StackingError::SubViews(InvalidSubViews::DuplicateSize { size })) => {
                assert_eq!(size, base.size(), "the duplicate pin size must be named");
            }
            Err(other) => panic!("expected DuplicateSize, got {other:?}"),
            Ok(_) => panic!("expected DuplicateSize, but the stack was built"),
        }
        drop(base);
    }

    #[tokio::test]
    async fn stacking_rejects_unsorted_pins() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-unsorted-a").await;
        let (_db_b, store_b) = fresh("astack-unsorted-b").await;
        let (_db_c, store_c) = fresh("astack-unsorted-c").await;
        let mut small = TestMmr::create(h, store_a, id(1))
            .await
            .expect("create small");
        for i in 0..2 {
            small
                .append(&element(i))
                .await
                .expect("append must succeed");
        }
        let mut big = TestMmr::create(h, store_b, id(2))
            .await
            .expect("create big");
        for i in 0..5 {
            big.append(&element(i)).await.expect("append must succeed");
        }

        let big_pin = big.pin();
        let small_pin = small.pin();
        match TestStacked::stack(h, store_c, id(3), [big_pin, small_pin]).await {
            Err(StackingError::SubViews(InvalidSubViews::Unsorted { prev, next })) => {
                assert_eq!(prev, big.size(), "the earlier, larger pin must be named");
                assert_eq!(next, small.size(), "the later, smaller pin must be named");
            }
            Err(other) => panic!("expected Unsorted, got {other:?}"),
            Ok(_) => panic!("expected Unsorted, but the stack was built"),
        }
        drop(big);
        drop(small);
    }

    #[tokio::test]
    async fn stacking_requires_at_least_one_pin() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-empty").await;
        let subs = Vec::<SubView<SqliteStore, AccumulatorId>>::new();
        match TestStacked::stack(h, store_a, id(1), subs).await {
            Err(StackingError::SubViews(InvalidSubViews::Empty)) => {}
            Err(other) => panic!("expected Empty, got {other:?}"),
            Ok(_) => panic!("expected Empty, but the stack was built"),
        }
    }

    #[tokio::test]
    async fn a_forged_pin_without_backed_peaks_is_a_typed_error() {
        // `SubView::single_async` is a forgeable constructor: shape-valid,
        // but this store holds nothing, so the pinned peaks are absent.
        // `stack` must report a typed sub-view error.
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-forged").await;
        let pin = SubView::single_async(id(1), store_a, size_of(LeafCount::new(4)));
        let (_db_b, store_b) = fresh("astack-forged-top").await;
        match TestStacked::stack(h, store_b, id(2), [pin]).await {
            Err(StackingError::SubViews(InvalidSubViews::MissingPeakNodes)) => {}
            Err(other) => panic!("expected MissingPeakNodes, got {other:?}"),
            Ok(_) => panic!("expected MissingPeakNodes, but the stack was built"),
        }
    }
}

// ---------------------------------------------------- nullifier pin rules

mod nullifier_pin_rules {
    use super::*;

    /// The owner's worked example (the sync suite's fixture, async twin).
    async fn worked_example() -> (TempDb, TempDb, TestMmrNull, TestStackedNull) {
        let h = hasher();
        let (db_a, store_a) = fresh("astack-worked-a").await;
        let (db_b, store_b) = fresh("astack-worked-b").await;
        let mut base = TestMmrNull::create_nullifying(h, store_a, id(1))
            .await
            .expect("create");
        for i in 0..10 {
            base.append(&element(i)).await.expect("append must succeed");
        }
        base.nullify_shallow(LeafIndex::new(8))
            .await
            .expect("nullify leaf 8");
        for i in 10..12 {
            base.append(&element(i)).await.expect("append must succeed");
        }

        let pin = base.pin();
        let stacked = TestStackedNull::stack(h, store_b, id(2), [pin])
            .await
            .expect("stack");

        for i in 12..20 {
            base.append(&element(i)).await.expect("append must succeed");
        }
        base.nullify_shallow(LeafIndex::new(3))
            .await
            .expect("shallow-nullify leaf 3 after the pin");
        base.nullify_deep(LeafIndex::new(5))
            .await
            .expect("deep-nullify leaf 5");
        (db_a, db_b, base, stacked)
    }

    #[tokio::test]
    async fn shallow_records_resolve_only_up_to_the_pin_size() {
        let (_db_a, _db_b, base, stacked) = worked_example().await;

        // The record for leaf 8 was written before the pin → resolves through it.
        expect_nullified(stacked.proof(LeafIndex::new(8)).await, LeafIndex::new(8));
        // The record for leaf 3 was written after the pin → later history is
        // invisible through the pin, the proof is issued and verifies.
        let proof = stacked
            .proof(LeafIndex::new(3))
            .await
            .expect("a post-pin shallow record must not resolve through the stack");
        assert!(stacked.verify(&proof, &element(3)).expect("verify"));

        // The base's own records always resolve, regardless of timing.
        expect_nullified(base.proof(LeafIndex::new(8)).await, LeafIndex::new(8));
        expect_nullified(base.proof(LeafIndex::new(3)).await, LeafIndex::new(3));

        // Record sizes are the node counts at nullification time, read
        // through the async `nullifier_set` accessor.
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(8))
                .await
                .expect("read"),
            Some(NullifierRecord::Shallow {
                at: size_of(LeafCount::new(10))
            })
        );
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(3))
                .await
                .expect("read"),
            Some(NullifierRecord::Shallow {
                at: size_of(LeafCount::new(20))
            })
        );
    }

    #[tokio::test]
    async fn deep_records_resolve_through_any_pin() {
        let h = hasher();
        let (_db_a, _db_b, base, stacked) = worked_example().await;

        expect_nullified(stacked.proof(LeafIndex::new(5)).await, LeafIndex::new(5));
        expect_nullified(base.proof(LeafIndex::new(5)).await, LeafIndex::new(5));
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(5))
                .await
                .expect("read"),
            Some(NullifierRecord::Deep),
            "the deep record lands in the layer that holds the value"
        );

        // Nullifiers never touch data: both roots still match the references.
        assert_eq!(stacked.leaf_count(), LeafCount::new(12));
        assert_eq!(stacked.root(), reference_root(&h, &slices(&elements(12))));
        assert_eq!(base.root(), reference_root(&h, &slices(&elements(20))));
    }

    #[tokio::test]
    async fn a_record_written_exactly_at_the_pin_size_resolves() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-exact-pin-a").await;
        let (_db_b, store_b) = fresh("astack-exact-pin-b").await;
        let mut base = TestMmrNull::create_nullifying(h, store_a, id(1))
            .await
            .expect("create");
        for i in 0..5 {
            base.append(&element(i)).await.expect("append must succeed");
        }
        base.nullify_shallow(LeafIndex::new(2))
            .await
            .expect("nullify");
        let pin = base.pin();

        let stacked = TestStackedNull::stack(h, store_b, id(2), [pin])
            .await
            .expect("stack");
        expect_nullified(stacked.proof(LeafIndex::new(2)).await, LeafIndex::new(2));
        drop(stacked);
        drop(base);
    }

    #[tokio::test]
    async fn deep_nullify_on_a_stacked_mmr_lands_in_the_owning_layer() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-deep-owner-a").await;
        let (_db_b, store_b) = fresh("astack-deep-owner-b").await;
        let mut base = TestMmrNull::create_nullifying(h, store_a, id(1))
            .await
            .expect("create");
        for i in 0..6 {
            base.append(&element(i)).await.expect("append must succeed");
        }
        let pin = base.pin();
        let mut stacked = TestStackedNull::stack(h, store_b, id(2), [pin])
            .await
            .expect("stack");
        stacked
            .append(&element(6))
            .await
            .expect("append must succeed");

        // A leaf below the pin: the record must land in the base's store
        // under the base's id, so every stack above the base sees it.
        stacked
            .nullify_deep(LeafIndex::new(2))
            .await
            .expect("nullify");
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(2))
                .await
                .expect("read"),
            Some(NullifierRecord::Deep)
        );
        expect_nullified(base.proof(LeafIndex::new(2)).await, LeafIndex::new(2));
        expect_nullified(stacked.proof(LeafIndex::new(2)).await, LeafIndex::new(2));

        // A leaf in the stacked layer's own range lands in the top store.
        stacked
            .nullify_deep(LeafIndex::new(6))
            .await
            .expect("nullify");
        assert_eq!(
            stacked
                .nullifier_set()
                .record(LeafIndex::new(6))
                .await
                .expect("read"),
            Some(NullifierRecord::Deep)
        );
        expect_nullified(stacked.proof(LeafIndex::new(6)).await, LeafIndex::new(6));
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(6))
                .await
                .expect("read"),
            None,
            "the base cannot hold records for leaves it never owned"
        );
        drop(stacked);
        drop(base);
    }

    #[tokio::test]
    async fn stacked_on_stacked_resolution_sees_the_middle_layers_own_records() {
        // The MMR3-over-MMR2 trace: MMR2 (stacked over MMR1) holds a shallow
        // record for leaf 3 in its OWN layer. MMR3's pin covers leaf 3's
        // node through BOTH layers of MMR2's view — the record must resolve
        // through the outer covering layer, not be hidden behind the first
        // (inner) one.
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-middle-a").await;
        let (_db_b, store_b) = fresh("astack-middle-b").await;
        let (_db_c, store_c) = fresh("astack-middle-c").await;
        let mut mmr1 = TestMmrNull::create_nullifying(h, store_a, id(1))
            .await
            .expect("create");
        for i in 0..10 {
            mmr1.append(&element(i)).await.expect("append must succeed");
        }
        let pin1 = mmr1.pin();
        let mut mmr2 = TestStackedNull::stack(h, store_b, id(2), [pin1])
            .await
            .expect("stack MMR2 over MMR1");
        for i in 10..12 {
            mmr2.append(&element(i)).await.expect("append must succeed");
        }
        mmr2.nullify_shallow(LeafIndex::new(3))
            .await
            .expect("the middle layer nullifies leaf 3");

        // MMR2's own records always resolve.
        expect_nullified(mmr2.proof(LeafIndex::new(3)).await, LeafIndex::new(3));

        // MMR3 over MMR2: the record (2, 3) at MMR2's current size resolves
        // (size ≤ MMR3's pin of MMR2), even though leaf 3's node routes its
        // DATA through MMR1's layer.
        let pin2 = mmr2.pin();
        let mmr3 = TestStackedNull::stack(h, store_c, id(3), [pin2])
            .await
            .expect("stack MMR3 over MMR2");
        expect_nullified(mmr3.proof(LeafIndex::new(3)).await, LeafIndex::new(3));

        // Later history stays invisible: MMR2 grows past MMR3's pin, then
        // nullifies leaf 4 — the record's size exceeds the pin, so MMR3
        // still proves leaf 4 while MMR2 refuses it.
        mmr2.append(&element(20)).await.expect("grow past the pin");
        mmr2.nullify_shallow(LeafIndex::new(4))
            .await
            .expect("nullify after growth");
        expect_nullified(mmr2.proof(LeafIndex::new(4)).await, LeafIndex::new(4));
        let proof4 = mmr3
            .proof(LeafIndex::new(4))
            .await
            .expect("a post-pin shallow record must not resolve through the stack");
        assert!(mmr3.verify(&proof4, &element(4)).expect("verify"));
        drop(mmr3);
        drop(mmr2);
        drop(mmr1);
    }
}

// ------------------------------------------------------------ open_stacked

mod open_stacked_tests {
    use super::*;

    #[tokio::test]
    async fn open_stacked_rebuilds_a_stack_from_distinct_layer_stores() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-reopen-distinct-a").await;
        let (_db_b, store_b) = fresh("astack-reopen-distinct-b").await;
        let (db_top, store_top) = fresh("astack-reopen-distinct-top").await;

        let mut a = TestMmr::create(h, store_a, id(1)).await.expect("create a");
        for i in 0..5 {
            a.append(&element(i)).await.expect("append must succeed");
        }
        let pin_a = a.pin();
        let mut b = TestStacked::stack(h, store_b, id(2), [pin_a])
            .await
            .expect("stack b");
        for i in 5..8 {
            b.append(&element(i)).await.expect("append must succeed");
        }

        let pin_a = a.pin();
        let pin_b = b.pin();
        let mut c = TestStacked::stack(h, store_top.clone(), id(3), [pin_a, pin_b])
            .await
            .expect("stack c");
        for i in 8..10 {
            c.append(&element(i)).await.expect("append must succeed");
        }
        drop(c);
        drop(b);
        drop(a);

        // Re-open from the top layer's database file; every sub-layer store
        // is reconstructed from its persisted locator.
        let reopened_store = SqliteStore::connect(db_top.path())
            .await
            .expect("reconnect");
        let mut reopened: AsyncStackedAppendMmr<KeccakSolHasher, SqliteStore> =
            open_stacked_append_only::<KeccakSolHasher, SqliteStore, AccumulatorId>(
                h,
                reopened_store,
                id(3),
            )
            .await
            .expect("re-open from the persisted layer metadata");
        assert_eq!(reopened.leaf_count(), LeafCount::new(10));
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(10))),
            "the reopened stack must reproduce the original root"
        );
        for leaf in [0_u64, 4, 7, 9] {
            let proof = reopened
                .proof(LeafIndex::new(leaf))
                .await
                .expect("proof after reopen");
            assert!(reopened.verify(&proof, &element(leaf)).expect("verify"));
        }

        reopened
            .append(&element(10))
            .await
            .expect("reopened stack keeps appending");
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(11))),
            "growth after reopen must track the reference"
        );
        drop(reopened);
    }

    #[tokio::test]
    async fn open_stacked_rebuilds_a_stack_sharing_one_store() {
        let h = hasher();
        let (db, store) = fresh("astack-reopen-shared").await;

        let mut a = TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create a");
        for i in 0..4 {
            a.append(&element(i)).await.expect("append must succeed");
        }
        let pin_a = a.pin();
        let mut b = TestStacked::stack(h, store.clone(), id(2), [pin_a])
            .await
            .expect("stack b");
        for i in 4..7 {
            b.append(&element(i)).await.expect("append must succeed");
        }
        drop(b);
        drop(a);

        let reopened_store = SqliteStore::connect(db.path()).await.expect("reconnect");
        let reopened = open_stacked_append_only::<KeccakSolHasher, SqliteStore, AccumulatorId>(
            h,
            reopened_store,
            id(2),
        )
        .await
        .expect("re-open with all layers in one store");
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(7))),
            "one shared store for every layer must reopen identically"
        );
        let proof = reopened.proof(LeafIndex::new(6)).await.expect("proof");
        assert!(reopened.verify(&proof, &element(6)).expect("verify"));
        drop(reopened);
    }

    #[tokio::test]
    async fn open_stacked_requires_persisted_layer_metadata() {
        let (db, store) = fresh("astack-reopen-empty").await;
        match open_stacked_append_only::<KeccakSolHasher, SqliteStore, AccumulatorId>(
            hasher(),
            store,
            id(9),
        )
        .await
        {
            Err(MmrError::Corrupted(Corrupted::MissingRecord { table })) => {
                assert_eq!(table, Table::Subviews);
            }
            Err(other) => panic!("expected MissingRecord(Subviews), got {other:?}"),
            Ok(_) => panic!("expected MissingRecord(Subviews), but the stack opened"),
        }
        drop(db);
    }

    /// The nullifying named variant re-opens a stack whose top layer is
    /// [`Nullifying`] (the mode is validated against the persisted record).
    #[tokio::test]
    async fn open_stacked_nullifying_reopens_a_nullifying_top_layer() {
        let h = hasher();
        let (_db_a, store_a) = fresh("astack-reopen-null-a").await;
        let (db_top, store_top) = fresh("astack-reopen-null-top").await;
        let mut base = TestMmrNull::create_nullifying(h, store_a, id(1))
            .await
            .expect("create");
        for i in 0..4 {
            base.append(&element(i)).await.expect("append must succeed");
        }
        let pin = base.pin();
        let mut stacked = TestStackedNull::stack(h, store_top, id(2), [pin])
            .await
            .expect("stack");
        stacked
            .nullify_shallow(LeafIndex::new(1))
            .await
            .expect("nullify");
        drop(stacked);
        drop(base);

        let reopened_store = SqliteStore::connect(db_top.path())
            .await
            .expect("reconnect");
        let reopened = accumulators::mmr::async_mmr::open_stacked_nullifying::<
            KeccakSolHasher,
            SqliteStore,
            AccumulatorId,
        >(h, reopened_store, id(2))
        .await
        .expect("re-open the nullifying stack");
        expect_nullified(reopened.proof(LeafIndex::new(1)).await, LeafIndex::new(1));
        drop(reopened);

        // The persisted mode is validated: the append-only named open of a
        // nullifying top layer is rejected.
        let reopened_store = SqliteStore::connect(db_top.path())
            .await
            .expect("reconnect");
        match open_stacked_append_only::<KeccakSolHasher, SqliteStore, AccumulatorId>(
            h,
            reopened_store,
            id(2),
        )
        .await
        {
            Err(MmrError::Corrupted(Corrupted::ModeMismatch { .. })) => {}
            Err(other) => panic!("expected ModeMismatch, got {other:?}"),
            Ok(_) => panic!("expected ModeMismatch, but the stack opened"),
        }
    }
}

// ------------------------------------------------ cross-layer validation

mod cross_layer_validation {
    use super::*;

    /// A pinned layer whose store persists a different hasher identity is
    /// refused at `stack` time: the stack root could never equal the
    /// reference root of the same elements.
    #[tokio::test]
    async fn a_layer_with_a_different_hasher_is_refused_at_stack_time() {
        let h = hasher();
        // Blake2s base: same output type (`Hash`), different hasher record.
        let blake = Blake2sStarkHasher { truncate: false };
        let (_db_a, store_a) = fresh("astack-hash-tamper-a").await;
        let (_db_top, store_top) = fresh("astack-hash-tamper-top").await;
        let mut base = AsyncMmr::<Blake2sStarkHasher, SqliteStore>::create(blake, store_a, id(7))
            .await
            .expect("create");
        base.append(&[0_u8; 12]).await.expect("append must succeed");
        let pin = base.pin();

        match TestStacked::stack(h, store_top, id(8), [pin]).await {
            Err(StackingError::LayerHasherMismatch { stored }) => {
                assert!(
                    stored.contains("blake2s_stark"),
                    "the error names the layer's hasher, got {stored}"
                );
            }
            Err(other) => panic!("expected LayerHasherMismatch, got {other:?}"),
            Ok(_) => panic!("expected LayerHasherMismatch, but the stack was built"),
        }
        drop(base);
    }

    /// A layer store whose `HasherInfo` record is unparsable fails the
    /// stacked re-open (fail closed, never read as "matching").
    #[tokio::test]
    async fn a_layer_with_an_unreadable_hasher_record_fails_the_reopen() {
        let h = hasher();
        let (_db_a, base_store) = fresh("astack-unreadable-a").await;
        let (db_top, top_store) = fresh("astack-unreadable-top").await;
        let mut base = TestMmr::create(h, base_store.clone(), id(1))
            .await
            .expect("create");
        base.append(&element(0)).await.expect("append must succeed");
        let pin = base.pin();
        let stack = TestStacked::stack(h, top_store, id(2), [pin])
            .await
            .expect("stack");

        // Poison the layer's HasherInfo: the top layer's own record still
        // matches, so the failure must come from the *layer* check.
        let key = keys::encode(&id(1), Table::HasherInfo, 0);
        let mut batch = Batch::new();
        batch.put_owned(key, vec![0xff, 0xff, 0xff]);
        base_store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");
        drop(stack);
        drop(base);

        let reopened_store = SqliteStore::connect(db_top.path())
            .await
            .expect("reconnect");
        match open_stacked_append_only::<KeccakSolHasher, SqliteStore, AccumulatorId>(
            h,
            reopened_store,
            id(2),
        )
        .await
        {
            Err(MmrError::Corrupted(Corrupted::HasherMismatch { stored, .. })) => {
                assert!(
                    stored.contains("unreadable"),
                    "the layer's record cannot be parsed, got {stored}"
                );
            }
            Err(other) => panic!("expected HasherMismatch, got {other:?}"),
            Ok(_) => panic!("expected HasherMismatch, but the stack opened"),
        }
    }

    /// A layer whose node count does not back its pin is reported as
    /// `PinSizeMismatch` — the pin-vs-layer finding, distinct from a
    /// peak-count mismatch.
    #[tokio::test]
    async fn a_layer_shrunk_below_its_pin_is_a_pin_size_mismatch() {
        let h = hasher();
        let (_db_a, base_store) = fresh("astack-pin-size-a").await;
        let (db_top, top_store) = fresh("astack-pin-size-top").await;
        let mut base = TestMmr::create(h, base_store.clone(), id(1))
            .await
            .expect("create");
        for el in &elements(4) {
            base.append(el).await.expect("append must succeed");
        }
        let pin = base.pin();
        let stack = TestStacked::stack(h, top_store, id(2), [pin])
            .await
            .expect("stack");

        // Shrink the layer's node counter below the pin (4 leaves = 7 nodes
        // → 3 nodes).
        poke(
            &base_store,
            id(1),
            Table::NodeCount,
            &MmrSize::new_unchecked(3).get().to_be_bytes(),
        )
        .await;
        drop(stack);
        drop(base);

        let reopened_store = SqliteStore::connect(db_top.path())
            .await
            .expect("reconnect");
        match open_stacked_append_only::<KeccakSolHasher, SqliteStore, AccumulatorId>(
            h,
            reopened_store,
            id(2),
        )
        .await
        {
            Err(MmrError::Corrupted(Corrupted::PinSizeMismatch { pinned, layer_size })) => {
                assert_eq!(pinned, MmrSize::new_unchecked(7));
                assert_eq!(layer_size, MmrSize::new_unchecked(3));
            }
            Err(other) => panic!("expected PinSizeMismatch, got {other:?}"),
            Ok(_) => panic!("expected PinSizeMismatch, but the stack opened"),
        }
    }
}

// ------------------------------------------------------ cross-store fan-out

mod cross_store_fan_out {
    use super::*;
    use common::FaultyStore;

    type FaultyMmr = AsyncMmr<KeccakSolHasher, FaultyStore<SqliteStore>>;
    type FaultyStacked = AsyncMmr<KeccakSolHasher, FaultyStore<SqliteStore>, Stacked>;

    /// A 3-layer stack over three distinct stores: root and proofs stay
    /// byte-identical to the flat reference, a spanning multiproof issues
    /// exactly one concurrent batched read per distinct store, and the
    /// re-open (whose per-layer counter checks fan out the same way)
    /// reproduces the root and keeps growing on the reference curve.
    #[tokio::test]
    async fn three_distinct_stores_fan_out_and_match_the_reference() {
        let h = hasher();
        let (db_a, store_a) = fresh("astack-fanout-a").await;
        let (db_b, store_b) = fresh("astack-fanout-b").await;
        let (db_top, store_top) = fresh("astack-fanout-top").await;
        let fa = FaultyStore::new(store_a);
        let fb = FaultyStore::new(store_b);
        let ftop = FaultyStore::new(store_top.clone());

        let mut a = FaultyMmr::create(h, fa.clone(), id(1))
            .await
            .expect("create a");
        for i in 0..4 {
            a.append(&element(i)).await.expect("append must succeed");
        }
        let pin_a = a.pin();
        let mut b = FaultyStacked::stack(h, fb.clone(), id(2), [pin_a])
            .await
            .expect("stack b");
        for i in 4..7 {
            b.append(&element(i)).await.expect("append must succeed");
        }

        let pin_a = a.pin();
        let pin_b = b.pin();
        let mut c = FaultyStacked::stack(h, ftop.clone(), id(3), [pin_a, pin_b])
            .await
            .expect("stack c");
        for i in 7..11 {
            c.append(&element(i)).await.expect("append must succeed");
        }

        assert_eq!(
            c.root(),
            reference_root(&h, &slices(&elements(11))),
            "three distinct stores must equal one flat MMR over all eleven elements"
        );
        for leaf in [0_u64, 5, 10] {
            let proof = c
                .proof(LeafIndex::new(leaf))
                .await
                .expect("proof across layers");
            assert!(c.verify(&proof, &element(leaf)).expect("verify"));
        }

        let before = (
            fa.fault().read_calls(),
            fb.fault().read_calls(),
            ftop.fault().read_calls(),
        );
        let leaves = [LeafIndex::new(1), LeafIndex::new(6), LeafIndex::new(9)];
        let multi = c.multiproof(leaves).await.expect("cross-store multiproof");
        assert!(
            c.verify_multi(&multi, [&element(1), &element(6), &element(9)])
                .expect("verify"),
            "the spanning multiproof must verify"
        );
        assert_eq!(
            (
                fa.fault().read_calls(),
                fb.fault().read_calls(),
                ftop.fault().read_calls(),
            ),
            (before.0 + 1, before.1 + 1, before.2 + 1),
            "one concurrent batched read per distinct store"
        );

        let mut reopened: AsyncStackedAppendMmr<KeccakSolHasher, SqliteStore> =
            open_stacked_append_only(h, store_top, id(3))
                .await
                .expect("re-open from the persisted layer metadata");
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(11))),
            "the reopened stack must reproduce the original root"
        );
        reopened
            .append(&element(11))
            .await
            .expect("append after reopen");
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(12))),
            "growth after reopen must track the reference"
        );

        drop(c);
        drop(b);
        drop(a);
        drop(db_a);
        drop(db_b);
        drop(db_top);
    }

    /// The same 3-layer shape on one shared store: the router merges every
    /// layer into one group and a proof stays a single batched read (the
    /// sequential fast path — no fan-out machinery).
    #[tokio::test]
    async fn one_shared_store_merges_layers_into_one_batch() {
        let h = hasher();
        let (db, store_raw) = fresh("astack-fanout-shared").await;
        let store = FaultyStore::new(store_raw);

        let mut a = FaultyMmr::create(h, store.clone(), id(1))
            .await
            .expect("create a");
        for i in 0..4 {
            a.append(&element(i)).await.expect("append must succeed");
        }
        let pin_a = a.pin();
        let mut b = FaultyStacked::stack(h, store.clone(), id(2), [pin_a])
            .await
            .expect("stack b");
        for i in 4..7 {
            b.append(&element(i)).await.expect("append must succeed");
        }

        let pin_a = a.pin();
        let pin_b = b.pin();
        let mut c = FaultyStacked::stack(h, store.clone(), id(3), [pin_a, pin_b])
            .await
            .expect("stack c");
        for i in 7..11 {
            c.append(&element(i)).await.expect("append must succeed");
        }

        assert_eq!(
            c.root(),
            reference_root(&h, &slices(&elements(11))),
            "the shared-store stack must equal the flat reference"
        );
        let before = store.fault().read_calls();
        let proof = c
            .proof(LeafIndex::new(9))
            .await
            .expect("proof through all layers");
        assert!(c.verify(&proof, &element(9)).expect("verify"));
        assert_eq!(
            store.fault().read_calls(),
            before + 1,
            "the whole chain reads as one batched call"
        );

        drop(c);
        drop(b);
        drop(a);
        drop(db);
    }
}
