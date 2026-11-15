//! Stacked-MMR test suite: pin/stack construction, root equality with a
//! single-MMR reference, independent growth under a pin, the nullifier pin
//! rules (shallow vs deep), `open_stacked` over retrievable stores, and the
//! sub-view validation contract.
//!
//! Every root assertion is checked against an independent reference
//! computation built directly on [`Hasher::hash_pair`].

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(feature = "stacked_mmr", feature = "memory", feature = "keccak_sol"))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::{Hasher as _, KeccakSolHasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::stacked::open_stacked_append_only;
use accumulators::mmr::{
    Corrupted, InvalidSubViews, Mmr, MmrError, NullifierRecord, Nullifying, Plain, Stacked,
    StackedAppendMmr, StackedNullifyingMmr, StackingError, SubView,
};
use accumulators::mmr::{LeafCount, size_of};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::ErasedStore;
use accumulators::store::keys::Table;
use accumulators::store::memory::InMemoryStore;

use common::{element, elements, id, reference_root, slices};

type TestMmr = Mmr<KeccakSolHasher, InMemoryStore>;
type TestMmrNull = Mmr<KeccakSolHasher, InMemoryStore, Plain, Nullifying>;
type TestStacked = Mmr<KeccakSolHasher, InMemoryStore, Stacked>;
type TestStackedNull = Mmr<KeccakSolHasher, InMemoryStore, Stacked, Nullifying>;

// ---------------------------------------------------------------- helpers

fn hasher() -> KeccakSolHasher {
    KeccakSolHasher
}

fn expect_nullified(
    proof: Result<accumulators::mmr::Proof<Hash>, MmrError<InMemoryStore>>,
    leaf: LeafIndex,
) {
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

    #[test]
    fn stacked_root_equals_the_reference_over_all_layers() {
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create base");
        for i in 0..8 {
            base.append(&element(i)).expect("append must succeed");
        }

        let pin = base.pin();
        assert_eq!(
            pin.pinned_size(),
            base.size(),
            "the pin freezes the node count"
        );
        assert_eq!(pin.id(), id(1), "the pin carries the sub-MMR's id");

        let mut stacked = TestStacked::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");
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
            stacked.append(&element(i)).expect("append on the stack");
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
                .expect("proof through the stack");
            assert!(
                stacked.verify(&proof, &element(leaf)).expect("verify"),
                "leaf {leaf} must verify through the stack"
            );
        }
    }

    #[test]
    fn the_pin_freezes_the_stack_against_base_growth() {
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create base");
        for i in 0..8 {
            base.append(&element(i)).expect("append must succeed");
        }

        let pin = base.pin();
        let stacked = TestStacked::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");
        let frozen_root = stacked.root();
        let frozen_size = stacked.size();

        for i in 8..14 {
            base.append(&element(i)).expect("append must succeed");
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
            .expect("proof through the stack");
        assert!(
            stacked.verify(&proof, &element(3)).expect("verify"),
            "stacked proofs stay pinned to the frozen view"
        );
    }

    #[test]
    fn three_layers_stack_and_route_reads_through_both_pins() {
        let h = hasher();
        let mut a = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create a");
        for i in 0..4 {
            a.append(&element(i)).expect("append must succeed");
        }
        let pin_a = a.pin();
        let mut b = TestStacked::stack(h, InMemoryStore::new(), id(2), [pin_a]).expect("stack b");
        for i in 4..7 {
            b.append(&element(i)).expect("append must succeed");
        }

        let pin_a = a.pin();
        let pin_b = b.pin();
        assert_eq!(pin_b.pinned_size(), b.size());
        let mut c =
            TestStacked::stack(h, InMemoryStore::new(), id(3), [pin_a, pin_b]).expect("stack c");
        for i in 7..9 {
            c.append(&element(i)).expect("append must succeed");
        }

        assert_eq!(
            c.root(),
            reference_root(&h, &slices(&elements(9))),
            "three layers must equal one flat MMR over all nine elements"
        );
        for leaf in [0_u64, 5, 8] {
            let proof = c
                .proof(LeafIndex::new(leaf))
                .expect("proof through both pins");
            assert!(c.verify(&proof, &element(leaf)).expect("verify"));
        }
    }

    #[test]
    fn an_append_only_layer_can_stack_over_a_nullifying_pin() {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..5 {
            base.append(&element(i)).expect("append must succeed");
        }
        base.nullify_shallow(LeafIndex::new(2)).expect("nullify");

        let pin = base.pin();
        let stacked: TestStacked =
            Mmr::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");
        assert_eq!(
            stacked.root(),
            reference_root(&h, &slices(&elements(5))),
            "stacking is orthogonal to the base's mode"
        );
    }

    #[test]
    fn an_erased_pin_builds_a_session_local_mixed_stack() {
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create base");
        for i in 0..5 {
            base.append(&element(i)).expect("append must succeed");
        }

        let pin = base.pin().erased();
        assert_eq!(
            pin.pinned_size(),
            base.size(),
            "erasure keeps the pin metadata"
        );
        let stacked = Mmr::<KeccakSolHasher, ErasedStore, Stacked>::stack(
            h,
            ErasedStore::new(InMemoryStore::new()),
            id(2),
            [pin],
        )
        .expect("stack over erased stores");
        assert_eq!(
            stacked.root(),
            reference_root(&h, &slices(&elements(5))),
            "an erased stack behaves like a concrete one"
        );
    }
}

// --------------------------------------------------- cross-layer multiproofs

mod cross_layer_multiproofs {
    use super::*;

    /// A stacked multiproof whose leaves span BOTH layers, with the pool
    /// dedup contract asserted against the per-leaf sibling sum:
    /// the pool must be strictly smaller than proving each leaf alone.
    #[test]
    fn a_multiproof_spanning_layers_dedups_and_verifies() {
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create base");
        let base_els = elements(20);
        for el in &base_els {
            base.append(el).expect("append must succeed");
        }
        let pin = base.pin();
        let mut stacked = TestStacked::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");
        let top_els: Vec<Vec<u8>> = (20..40).map(element).collect();
        for el in &top_els {
            stacked.append(el).expect("append must succeed");
        }

        // Two adjacent leaves from the pinned layer (they share every
        // sibling above height 0) plus one from the stack's own layer.
        let leaves = [LeafIndex::new(4), LeafIndex::new(5), LeafIndex::new(30)];
        let multi = stacked.multiproof(leaves).expect("cross-layer multiproof");
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

        let per_leaf: usize = leaves
            .iter()
            .map(|&leaf| stacked.proof(leaf).expect("proof").siblings.len())
            .sum();
        assert!(
            multi.sibling_pool.len() < per_leaf,
            "pool dedup: {} pooled siblings must beat {} per-leaf siblings",
            multi.sibling_pool.len(),
            per_leaf
        );
    }

    /// `leaf_hash` reads through the stack for both pinned-layer and
    /// own-layer leaves — the gate-sourcing read works at every layer.
    #[test]
    fn leaf_hash_reads_through_the_stack() {
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create base");
        for el in &elements(5) {
            base.append(el).expect("append must succeed");
        }
        let pin = base.pin();
        let mut stacked = TestStacked::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");
        stacked.append(b"own").expect("append must succeed");

        for leaf in 0..5_u64 {
            assert_eq!(
                stacked.leaf_hash(LeafIndex::new(leaf)).expect("read"),
                Some(h.hash_leaf(&element(leaf)).expect("hash")),
                "pinned-layer leaf {leaf} reads through the stack"
            );
        }
        assert_eq!(
            stacked.leaf_hash(LeafIndex::new(5)).expect("read"),
            Some(h.hash_leaf(b"own").expect("hash")),
            "the stack's own leaf reads directly"
        );
        assert!(stacked.leaf_hash(LeafIndex::new(6)).is_err());
    }
}

// ------------------------------------------------------------ validation

mod validation {
    use super::*;

    #[test]
    fn stacking_rejects_duplicate_pin_sizes() {
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create base");
        base.append(b"a").expect("append must succeed");
        let first = base.pin();
        let second = base.pin();

        match TestStacked::stack(h, InMemoryStore::new(), id(2), [first, second]) {
            Err(StackingError::SubViews(InvalidSubViews::DuplicateSize { size })) => {
                assert_eq!(size, base.size(), "the duplicate pin size must be named");
            }
            Err(other) => panic!("expected DuplicateSize, got {other:?}"),
            Ok(_) => panic!("expected DuplicateSize, but the stack was built"),
        }
    }

    #[test]
    fn stacking_rejects_unsorted_pins() {
        let h = hasher();
        let mut small = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create small");
        for i in 0..2 {
            small.append(&element(i)).expect("append must succeed");
        }
        let mut big = TestMmr::create(h, InMemoryStore::new(), id(2)).expect("create big");
        for i in 0..5 {
            big.append(&element(i)).expect("append must succeed");
        }

        let big_pin = big.pin();
        let small_pin = small.pin();
        match TestStacked::stack(h, InMemoryStore::new(), id(3), [big_pin, small_pin]) {
            Err(StackingError::SubViews(InvalidSubViews::Unsorted { prev, next })) => {
                assert_eq!(prev, big.size(), "the earlier, larger pin must be named");
                assert_eq!(next, small.size(), "the later, smaller pin must be named");
            }
            Err(other) => panic!("expected Unsorted, got {other:?}"),
            Ok(_) => panic!("expected Unsorted, but the stack was built"),
        }
    }

    #[test]
    fn stacking_requires_at_least_one_pin() {
        let h = hasher();
        let subs = Vec::<SubView<InMemoryStore, AccumulatorId>>::new();
        match TestStacked::stack(h, InMemoryStore::new(), id(1), subs) {
            Err(StackingError::SubViews(InvalidSubViews::Empty)) => {}
            Err(other) => panic!("expected Empty, got {other:?}"),
            Ok(_) => panic!("expected Empty, but the stack was built"),
        }
    }

    #[test]
    fn a_forged_pin_without_backed_peaks_is_a_typed_error() {
        // `SubView::single` is a forgeable constructor: shape-valid, but
        // this store holds nothing, so the pinned peaks are absent. `stack`
        // must report a typed sub-view error.
        let h = hasher();
        let pin = SubView::single(id(1), InMemoryStore::new(), size_of(LeafCount::new(4)));
        match TestStacked::stack(h, InMemoryStore::new(), id(2), [pin]) {
            Err(StackingError::SubViews(InvalidSubViews::MissingPeakNodes)) => {}
            Err(other) => panic!("expected MissingPeakNodes, got {other:?}"),
            Ok(_) => panic!("expected MissingPeakNodes, but the stack was built"),
        }
    }
}

// ---------------------------------------------------- nullifier pin rules

mod nullifier_pin_rules {
    use super::*;

    /// The owner's worked example. The base grows to 10 leaves, shallow-nullifies
    /// leaf 8 (record size = node count at 10 leaves), grows to 12 leaves and is
    /// pinned; then it grows to 20 leaves and nullifies leaf 3 shallow and leaf 5
    /// deep. Returns both handles.
    fn worked_example() -> (TestMmrNull, TestStackedNull) {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..10 {
            base.append(&element(i)).expect("append must succeed");
        }
        base.nullify_shallow(LeafIndex::new(8))
            .expect("nullify leaf 8");
        for i in 10..12 {
            base.append(&element(i)).expect("append must succeed");
        }

        let pin = base.pin();
        // Annotation pins the alias: `StackedNullifyingMmr<H, S>` is exactly
        // `Mmr<H, S, Stacked, Nullifying>`.
        let stacked: StackedNullifyingMmr<KeccakSolHasher, InMemoryStore> =
            TestStackedNull::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");

        for i in 12..20 {
            base.append(&element(i)).expect("append must succeed");
        }
        base.nullify_shallow(LeafIndex::new(3))
            .expect("shallow-nullify leaf 3 after the pin");
        base.nullify_deep(LeafIndex::new(5))
            .expect("deep-nullify leaf 5");
        (base, stacked)
    }

    #[test]
    fn shallow_records_resolve_only_up_to_the_pin_size() {
        let (base, stacked) = worked_example();

        // The record for leaf 8 was written before the pin → resolves through it.
        expect_nullified(stacked.proof(LeafIndex::new(8)), LeafIndex::new(8));
        // The record for leaf 3 was written after the pin → later history is
        // invisible through the pin, the proof is issued and verifies.
        let proof = stacked
            .proof(LeafIndex::new(3))
            .expect("a post-pin shallow record must not resolve through the stack");
        assert!(stacked.verify(&proof, &element(3)).expect("verify"));

        // The base's own records always resolve, regardless of timing.
        expect_nullified(base.proof(LeafIndex::new(8)), LeafIndex::new(8));
        expect_nullified(base.proof(LeafIndex::new(3)), LeafIndex::new(3));

        // Record sizes are the node counts at nullification time.
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(8))
                .expect("read"),
            Some(NullifierRecord::Shallow {
                at: size_of(LeafCount::new(10))
            })
        );
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(3))
                .expect("read"),
            Some(NullifierRecord::Shallow {
                at: size_of(LeafCount::new(20))
            })
        );
    }

    #[test]
    fn deep_records_resolve_through_any_pin() {
        let h = hasher();
        let (base, stacked) = worked_example();

        expect_nullified(stacked.proof(LeafIndex::new(5)), LeafIndex::new(5));
        expect_nullified(base.proof(LeafIndex::new(5)), LeafIndex::new(5));
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(5))
                .expect("read"),
            Some(NullifierRecord::Deep),
            "the deep record lands in the layer that holds the value"
        );

        // Nullifiers never touch data: both roots still match the references.
        assert_eq!(stacked.leaf_count(), LeafCount::new(12));
        assert_eq!(stacked.root(), reference_root(&h, &slices(&elements(12))));
        assert_eq!(base.root(), reference_root(&h, &slices(&elements(20))));
    }

    #[test]
    fn a_record_written_exactly_at_the_pin_size_resolves() {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..5 {
            base.append(&element(i)).expect("append must succeed");
        }
        base.nullify_shallow(LeafIndex::new(2)).expect("nullify");
        let pin = base.pin();

        let stacked = TestStackedNull::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");
        expect_nullified(stacked.proof(LeafIndex::new(2)), LeafIndex::new(2));
    }

    #[test]
    fn deep_nullify_on_a_stacked_mmr_lands_in_the_owning_layer() {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..6 {
            base.append(&element(i)).expect("append must succeed");
        }
        let pin = base.pin();
        let mut stacked =
            TestStackedNull::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");
        stacked.append(&element(6)).expect("append must succeed");

        // A leaf below the pin: the record must land in the base's store under
        // the base's id, so every stack above the base sees it.
        stacked.nullify_deep(LeafIndex::new(2)).expect("nullify");
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(2))
                .expect("read"),
            Some(NullifierRecord::Deep)
        );
        expect_nullified(base.proof(LeafIndex::new(2)), LeafIndex::new(2));
        expect_nullified(stacked.proof(LeafIndex::new(2)), LeafIndex::new(2));

        // A leaf in the stacked layer's own range lands in the top store.
        stacked.nullify_deep(LeafIndex::new(6)).expect("nullify");
        assert_eq!(
            stacked
                .nullifier_set()
                .record(LeafIndex::new(6))
                .expect("read"),
            Some(NullifierRecord::Deep)
        );
        expect_nullified(stacked.proof(LeafIndex::new(6)), LeafIndex::new(6));
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(6))
                .expect("read"),
            None,
            "the base cannot hold records for leaves it never owned"
        );
    }

    #[test]
    fn stacked_on_stacked_resolution_sees_the_middle_layers_own_records() {
        // The MMR3-over-MMR2 trace: MMR2 (stacked over MMR1) holds a shallow
        // record for leaf 3 in its OWN layer. MMR3's pin covers leaf 3's
        // node through BOTH layers of MMR2's view — the record must resolve
        // through the outer covering layer, not be hidden behind the first
        // (inner) one.
        let h = hasher();
        let mut mmr1 =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..10 {
            mmr1.append(&element(i)).expect("append must succeed");
        }
        let pin1 = mmr1.pin();
        let mut mmr2 = TestStackedNull::stack(h, InMemoryStore::new(), id(2), [pin1])
            .expect("stack MMR2 over MMR1");
        for i in 10..12 {
            mmr2.append(&element(i)).expect("append must succeed");
        }
        mmr2.nullify_shallow(LeafIndex::new(3))
            .expect("the middle layer nullifies leaf 3");

        // MMR2's own records always resolve.
        expect_nullified(mmr2.proof(LeafIndex::new(3)), LeafIndex::new(3));

        // MMR3 over MMR2: the record (2, 3) at MMR2's current size resolves
        // (size ≤ MMR3's pin of MMR2), even though leaf 3's node routes its
        // DATA through MMR1's layer.
        let pin2 = mmr2.pin();
        let mmr3 = TestStackedNull::stack(h, InMemoryStore::new(), id(3), [pin2])
            .expect("stack MMR3 over MMR2");
        expect_nullified(mmr3.proof(LeafIndex::new(3)), LeafIndex::new(3));

        // Later history stays invisible: MMR2 grows past MMR3's pin, then
        // nullifies leaf 4 — the record's size exceeds the pin, so MMR3
        // still proves leaf 4 while MMR2 refuses it.
        mmr2.append(&element(20)).expect("grow past the pin");
        mmr2.nullify_shallow(LeafIndex::new(4))
            .expect("nullify after growth");
        expect_nullified(mmr2.proof(LeafIndex::new(4)), LeafIndex::new(4));
        let proof4 = mmr3
            .proof(LeafIndex::new(4))
            .expect("a post-pin shallow record must not resolve through the stack");
        assert!(mmr3.verify(&proof4, &element(4)).expect("verify"));
    }
}

// ------------------------------------------------------------ open_stacked

mod open_stacked_tests {
    use super::*;

    #[test]
    fn open_stacked_rebuilds_a_stack_from_distinct_layer_stores() {
        let h = hasher();
        let store_a = InMemoryStore::shared("stacked-test-distinct-a");
        let store_b = InMemoryStore::shared("stacked-test-distinct-b");
        let store_top = InMemoryStore::shared("stacked-test-distinct-top");

        let mut a = TestMmr::create(h, store_a, id(1)).expect("create a");
        for i in 0..5 {
            a.append(&element(i)).expect("append must succeed");
        }
        let pin_a = a.pin();
        let mut b = TestStacked::stack(h, store_b, id(2), [pin_a]).expect("stack b");
        for i in 5..8 {
            b.append(&element(i)).expect("append must succeed");
        }

        let pin_a = a.pin();
        let pin_b = b.pin();
        let mut c =
            TestStacked::stack(h, store_top.clone(), id(3), [pin_a, pin_b]).expect("stack c");
        for i in 8..10 {
            c.append(&element(i)).expect("append must succeed");
        }

        // Annotation pins the alias: `StackedAppendMmr<H, S>` is exactly
        // `Mmr<H, S, Stacked, AppendOnly>`.
        let mut reopened: StackedAppendMmr<KeccakSolHasher, InMemoryStore> =
            open_stacked_append_only::<KeccakSolHasher, InMemoryStore, AccumulatorId>(
                h,
                store_top,
                id(3),
            )
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
                .expect("proof after reopen");
            assert!(reopened.verify(&proof, &element(leaf)).expect("verify"));
        }

        reopened
            .append(&element(10))
            .expect("reopened stack keeps appending");
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(11))),
            "growth after reopen must track the reference"
        );
    }

    #[test]
    fn open_stacked_rebuilds_a_stack_sharing_one_store() {
        let h = hasher();
        let store = InMemoryStore::shared("stacked-test-one-store");

        let mut a = TestMmr::create(h, store.clone(), id(1)).expect("create a");
        for i in 0..4 {
            a.append(&element(i)).expect("append must succeed");
        }
        let pin_a = a.pin();
        let mut b = TestStacked::stack(h, store.clone(), id(2), [pin_a]).expect("stack b");
        for i in 4..7 {
            b.append(&element(i)).expect("append must succeed");
        }

        let reopened = open_stacked_append_only::<KeccakSolHasher, InMemoryStore, AccumulatorId>(
            h,
            store,
            id(2),
        )
        .expect("re-open with all layers in one store");
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(7))),
            "one shared store for every layer must reopen identically"
        );
        let proof = reopened.proof(LeafIndex::new(6)).expect("proof");
        assert!(reopened.verify(&proof, &element(6)).expect("verify"));
    }

    #[test]
    fn open_stacked_requires_persisted_layer_metadata() {
        let store = InMemoryStore::shared("stacked-test-empty");
        match open_stacked_append_only::<KeccakSolHasher, InMemoryStore, AccumulatorId>(
            hasher(),
            store,
            id(9),
        ) {
            Err(MmrError::Corrupted(Corrupted::MissingRecord { table })) => {
                assert_eq!(table, Table::Subviews);
            }
            Err(other) => panic!("expected MissingRecord(Subviews), got {other:?}"),
            Ok(_) => panic!("expected MissingRecord(Subviews), but the stack opened"),
        }
    }
}

// ------------------------------------------------ cross-layer validation

mod cross_layer_validation {
    use super::*;
    use accumulators::hashers::Blake2sStarkHasher;
    use accumulators::mmr::MmrSize;
    use accumulators::store::{Batch, Store as _};

    /// A pinned layer whose store persists a different hasher identity is
    /// refused at `stack` time: the stack root could never equal the
    /// reference root of the same elements.
    #[test]
    fn a_layer_with_a_different_hasher_is_refused_at_stack_time() {
        // Blake2s base: same output type (`Hash`), different hasher record.
        let blake = Blake2sStarkHasher { truncate: false };
        let mut base =
            Mmr::<Blake2sStarkHasher, InMemoryStore>::create(blake, InMemoryStore::new(), id(7))
                .expect("create");
        base.append(&[0_u8; 12]).expect("append must succeed");
        let pin = base.pin();

        match TestStacked::stack(hasher(), InMemoryStore::new(), id(8), [pin]) {
            Err(StackingError::LayerHasherMismatch { stored }) => {
                assert!(
                    stored.contains("blake2s_stark"),
                    "the error names the layer's hasher, got {stored}"
                );
            }
            Err(other) => panic!("expected LayerHasherMismatch, got {other:?}"),
            Ok(_) => panic!("expected LayerHasherMismatch, but the stack was built"),
        }
    }

    /// A draft `commit_as_stacked` over a hasher-divergent base is likewise
    /// rejected — with the hasher-mismatch corruption finding.
    #[cfg(feature = "draft_mmr")]
    #[test]
    fn commit_as_stacked_refuses_a_hasher_divergent_base() {
        use accumulators::mmr::Optimise;

        let blake = Blake2sStarkHasher { truncate: false };
        let mut base =
            Mmr::<Blake2sStarkHasher, InMemoryStore>::create(blake, InMemoryStore::new(), id(7))
                .expect("create");
        base.append(&[0_u8; 12]).expect("append must succeed");
        let mut draft = base.start_draft();
        draft.append(&[1_u8; 12]).expect("buffered append");

        match draft.commit_as_stacked(
            Blake2sStarkHasher { truncate: true },
            InMemoryStore::new(),
            id(8),
            Optimise::Off,
        ) {
            Err(failure) => match failure.error {
                MmrError::Corrupted(Corrupted::HasherMismatch {
                    stored, supplied, ..
                }) => {
                    assert!(
                        stored.contains("blake2s_stark") && !stored.contains("truncate=true"),
                        "the error names the layer's hasher, got {stored}"
                    );
                    assert!(
                        supplied.contains("truncate=true"),
                        "the supplied side names the caller's hasher, got {supplied}"
                    );
                }
                other => panic!("expected Corrupted(HasherMismatch), got {other:?}"),
            },
            Ok(_) => panic!("expected a rejection, but the stack was built"),
        }
    }

    /// A layer store whose `HasherInfo` record is unparsable fails the
    /// stacked re-open (fail closed, never read as "matching").
    #[test]
    fn a_layer_with_an_unreadable_hasher_record_fails_the_reopen() {
        let h = hasher();
        let base_store = InMemoryStore::shared("stacked-test-hash-tamper-a");
        let top_store = InMemoryStore::shared("stacked-test-hash-tamper-top");
        let mut base = TestMmr::create(h, base_store.clone(), id(1)).expect("create");
        base.append(&element(0)).expect("append must succeed");
        let pin = base.pin();
        let _stack = TestStacked::stack(h, top_store.clone(), id(2), [pin]).expect("stack");

        // Poison the layer's HasherInfo: the top layer's own record still
        // matches, so the failure must come from the *layer* check.
        let key = accumulators::store::keys::encode(&id(1), Table::HasherInfo, 0);
        let mut batch = Batch::new();
        batch.put(key.as_slice(), b"\xff\xff\xff");
        base_store
            .write(batch)
            .expect("in-memory writes are infallible");

        match open_stacked_append_only::<KeccakSolHasher, InMemoryStore, AccumulatorId>(
            h,
            top_store,
            id(2),
        ) {
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
    #[test]
    fn a_layer_shrunk_below_its_pin_is_a_pin_size_mismatch() {
        let h = hasher();
        let base_store = InMemoryStore::shared("stacked-test-pin-size-a");
        let top_store = InMemoryStore::shared("stacked-test-pin-size-top");
        let mut base = TestMmr::create(h, base_store.clone(), id(1)).expect("create");
        for el in &elements(4) {
            base.append(el).expect("append must succeed");
        }
        let pin = base.pin();
        let _stack = TestStacked::stack(h, top_store.clone(), id(2), [pin]).expect("stack");

        // Shrink the layer's node counter below the pin (4 leaves = 7 nodes
        // → 3 nodes).
        let key = accumulators::store::keys::encode(&id(1), Table::NodeCount, 0);
        let count = MmrSize::new_unchecked(3).get().to_be_bytes();
        let mut batch = Batch::new();
        batch.put(key.as_slice(), &count);
        base_store
            .write(batch)
            .expect("in-memory writes are infallible");

        match open_stacked_append_only::<KeccakSolHasher, InMemoryStore, AccumulatorId>(
            h,
            top_store,
            id(2),
        ) {
            Err(MmrError::Corrupted(Corrupted::PinSizeMismatch { pinned, layer_size })) => {
                assert_eq!(pinned, MmrSize::new_unchecked(7));
                assert_eq!(layer_size, MmrSize::new_unchecked(3));
            }
            Err(other) => panic!("expected PinSizeMismatch, got {other:?}"),
            Ok(_) => panic!("expected PinSizeMismatch, but the stack opened"),
        }
    }
}
