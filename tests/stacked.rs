//! Stacked-MMR test suite: pin/stack construction, root equality with a
//! single-MMR reference, independent growth under a pin, the nullifier pin
//! rules (shallow vs deep), `open_stacked` over retrievable stores, and the
//! sub-view validation contract.
//!
//! Every root assertion is checked against an independent reference
//! computation built directly on [`Hasher::hash_pair`].

#![cfg(all(feature = "stacked_mmr", feature = "memory", feature = "keccak"))]

use accumulators::hashers::{Hasher, Keccak256Hasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::stacked::open_stacked;
use accumulators::mmr::{
    AppendOnly, Corrupted, InvalidSubViews, Mmr, MmrError, NullifierRecord, Nullifying, Plain,
    Stacked, StackingError, SubView,
};
use accumulators::mmr::{LeafCount, size_of};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::ErasedStore;
use accumulators::store::keys::Table;
use accumulators::store::memory::InMemoryStore;

type TestMmr = Mmr<Keccak256Hasher, InMemoryStore>;
type TestMmrNull = Mmr<Keccak256Hasher, InMemoryStore, Plain, Nullifying>;
type TestStacked = Mmr<Keccak256Hasher, InMemoryStore, Stacked>;
type TestStackedNull = Mmr<Keccak256Hasher, InMemoryStore, Stacked, Nullifying>;

// ---------------------------------------------------------------- helpers

fn hasher() -> Keccak256Hasher {
    Keccak256Hasher
}

fn element(index: u64) -> Vec<u8> {
    format!("element-{index}").into_bytes()
}

fn elements(count: u64) -> Vec<Vec<u8>> {
    (0..count).map(element).collect()
}

fn slices(elements: &[Vec<u8>]) -> Vec<&[u8]> {
    elements.iter().map(Vec::as_slice).collect()
}

fn id(byte: u8) -> AccumulatorId {
    AccumulatorId::from_bytes([byte; 16])
}

/// Brute-force peaks: leaf hashes merged with `trailing_ones` pair merges per
/// append. Independent of the crate's state core.
fn reference_peaks(hasher: Keccak256Hasher, elements: &[&[u8]]) -> Vec<Hash> {
    let mut peaks: Vec<Hash> = Vec::new();
    for (index, element) in elements.iter().enumerate() {
        peaks.push(
            hasher
                .hash_leaf(element)
                .expect("keccak accepts elements of any size"),
        );
        for _ in 0..(index as u64).trailing_ones() {
            let right = peaks.pop().expect("merge consumes a right peak");
            let left = peaks.pop().expect("merge consumes a left peak");
            peaks.push(hasher.hash_pair(left, right));
        }
    }
    peaks
}

/// Brute-force reference root: bag the peaks right-to-left with the leftmost
/// peak outermost, then bind `root = H(node_count, bag)`.
fn reference_root(hasher: Keccak256Hasher, elements: &[&[u8]]) -> Hash {
    let peaks = reference_peaks(hasher, elements);
    let leaves = elements.len() as u64;
    let size = 2 * leaves - u64::from(leaves.count_ones());
    let bag = match peaks.len() {
        0 => hasher.genesis(),
        1 => peaks[0],
        n => {
            let mut acc = hasher.hash_pair(peaks[n - 2], peaks[n - 1]);
            for peak in peaks[..n - 2].iter().rev() {
                acc = hasher.hash_pair(*peak, acc);
            }
            acc
        }
    };
    hasher.hash_pair(Hash::from_u64(size), bag)
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

    /// Defect reference: `Mmr::init_stack` (src/mmr/handle.rs) reads the pinned
    /// peaks through `load_nodes` before installing `self.subs`, so the read is
    /// never routed to the sub-MMRs' stores. `Mmr::stack` therefore panics with
    /// `unreachable!()` (MissingRecord(Nodes)) for any non-empty pin — the
    /// re-open path (`open_stack`) installs the subs first and is correct.
    /// These tests pin the intended stacked semantics; un-ignore them once the
    /// routing order is fixed.
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
            reference_root(h, &slices(&elements(12))),
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
            reference_root(h, &slices(&elements(14))),
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
            reference_root(h, &slices(&elements(9))),
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
            reference_root(h, &slices(&elements(5))),
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
        let stacked = Mmr::<Keccak256Hasher, ErasedStore, Stacked>::stack(
            h,
            ErasedStore::new(InMemoryStore::new()),
            id(2),
            [pin],
        )
        .expect("stack over erased stores");
        assert_eq!(
            stacked.root(),
            reference_root(h, &slices(&elements(5))),
            "an erased stack behaves like a concrete one"
        );
    }
}

// ------------------------------------------------------------ validation

mod validation {
    use super::*;

    #[test]
    fn stacking_over_a_nonempty_pin_constructs() {
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create base");
        for i in 0..4 {
            base.append(&element(i)).expect("append must succeed");
        }
        let pin = base.pin();
        let stacked = TestStacked::stack(h, InMemoryStore::new(), id(2), [pin]);
        assert!(
            stacked.is_ok(),
            "stacking over a pinned non-empty MMR must construct: {:?}",
            stacked.err()
        );
    }

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
        let stacked = TestStackedNull::stack(h, InMemoryStore::new(), id(2), [pin]).expect("stack");

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
        assert_eq!(stacked.root(), reference_root(h, &slices(&elements(12))));
        assert_eq!(base.root(), reference_root(h, &slices(&elements(20))));
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

        let mut reopened =
            open_stacked::<Keccak256Hasher, InMemoryStore, AppendOnly, AccumulatorId>(
                h,
                store_top,
                id(3),
            )
            .expect("re-open from the persisted layer metadata");
        assert_eq!(reopened.leaf_count(), LeafCount::new(10));
        assert_eq!(
            reopened.root(),
            reference_root(h, &slices(&elements(10))),
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
            reference_root(h, &slices(&elements(11))),
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

        let reopened = open_stacked::<Keccak256Hasher, InMemoryStore, AppendOnly, AccumulatorId>(
            h,
            store,
            id(2),
        )
        .expect("re-open with all layers in one store");
        assert_eq!(
            reopened.root(),
            reference_root(h, &slices(&elements(7))),
            "one shared store for every layer must reopen identically"
        );
        let proof = reopened.proof(LeafIndex::new(6)).expect("proof");
        assert!(reopened.verify(&proof, &element(6)).expect("verify"));
    }

    #[test]
    fn open_stacked_requires_persisted_layer_metadata() {
        let store = InMemoryStore::shared("stacked-test-empty");
        match open_stacked::<Keccak256Hasher, InMemoryStore, AppendOnly, AccumulatorId>(
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
