//! Draft-overlay test suite: in-memory appends and proofs, commit (both
//! `Optimise` modes), discard, `commit_as_stacked`, and the lost-update gate
//! semantics.
//!
//! Every root assertion is checked against an independent reference
//! computation built directly on [`Hasher::hash_pair`].

#![cfg(all(feature = "draft_mmr", feature = "memory", feature = "keccak"))]

use accumulators::hashers::{Hasher, Keccak256Hasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::{
    Editable, Mmr, MmrError, NullifierRecord, Nullifying, Optimise, Plain, Stacked,
};
use accumulators::mmr::{LeafCount, size_of};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::Store;
use accumulators::store::keys::{self, Table};
use accumulators::store::memory::InMemoryStore;

type TestMmr = Mmr<Keccak256Hasher, InMemoryStore>;
type TestMmrEdit = Mmr<Keccak256Hasher, InMemoryStore, Plain, Editable>;
type TestMmrNull = Mmr<Keccak256Hasher, InMemoryStore, Plain, Nullifying>;
type TestStacked = Mmr<Keccak256Hasher, InMemoryStore, Stacked>;
type TestStackedNull = Mmr<Keccak256Hasher, InMemoryStore, Stacked, Nullifying>;
type TestError = MmrError<InMemoryStore>;

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

/// Reads the persisted leaf counter straight from the store — the honest way
/// to observe "the draft wrote nothing" while the draft still borrows the base.
fn stored_leaf_count(store: &InMemoryStore, id: AccumulatorId) -> u64 {
    let key = keys::encode(&id, Table::LeafCount, 0);
    let value = store
        .read(&[&key])
        .expect("in-memory reads are infallible")
        .pop()
        .flatten()
        .expect("the leaf counter record exists");
    u64::from_be_bytes(value.as_slice().try_into().expect("counters are 8 bytes"))
}

fn expect_nullified(proof: Result<accumulators::mmr::Proof<Hash>, TestError>, leaf: LeafIndex) {
    match proof {
        Err(MmrError::LeafNullified { leaf: refused }) => {
            assert_eq!(refused, leaf, "the error must name the requested leaf");
        }
        other => panic!("expected LeafNullified for leaf {leaf}, got {other:?}"),
    }
}

// ------------------------------------------------------- reads and buffers

mod reads_and_buffers {
    use super::*;

    #[test]
    fn draft_appends_compose_over_the_base_without_store_writes() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut base = TestMmr::create(h, store.clone(), id(1)).expect("create");
        let base_els = elements(4);
        for el in &base_els {
            base.append(el).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        let outcome = draft
            .append_batch(&[element(4), element(5), element(6)])
            .expect("draft append");
        assert_eq!(outcome.first_leaf, LeafIndex::new(4));
        assert_eq!(outcome.appended, LeafCount::new(3));

        // The composed (base + draft) view.
        assert_eq!(draft.leaf_count(), LeafCount::new(7));
        assert_eq!(draft.draft_len(), LeafCount::new(3));
        assert_eq!(draft.size(), size_of(LeafCount::new(7)));
        assert_eq!(
            draft.root(),
            reference_root(h, &slices(&elements(7))),
            "the draft root must match the flat reference over base + draft elements"
        );
        assert_eq!(
            draft.peaks(),
            reference_peaks(h, &slices(&elements(7))),
            "the composed peaks must match the reference"
        );

        // Nothing reached the store yet.
        assert_eq!(
            stored_leaf_count(&store, id(1)),
            4,
            "draft appends must not grow the base's persisted state"
        );

        // Commit lands the log.
        let report = match draft.commit(Optimise::Off) {
            Ok(report) => report,
            Err(failure) => panic!("commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(report.appended, LeafCount::new(3));
        assert_eq!(report.edits, 0);
        assert_eq!(report.nullifications, 0);
        assert_eq!(
            report.root,
            reference_root(h, &slices(&elements(7))),
            "the committed root must equal the draft's composed root"
        );
        assert_eq!(base.leaf_count(), LeafCount::new(7));
        assert_eq!(base.root(), reference_root(h, &slices(&elements(7))));
    }

    #[test]
    fn draft_proofs_cover_base_and_draft_leaves() {
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..4 {
            base.append(&element(i)).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        for i in 4..7 {
            draft.append(&element(i)).expect("draft append");
        }

        for leaf in 0..7_u64 {
            let proof = draft.proof(LeafIndex::new(leaf)).expect("composed proof");
            assert!(
                draft.verify(&proof, &element(leaf)).expect("verify"),
                "draft leaf {leaf} must verify against the composed root"
            );
        }
        let multi = draft
            .multiproof([LeafIndex::new(0), LeafIndex::new(5)])
            .expect("multiproof over the composed view");
        assert!(
            draft
                .verify_multi(&multi, [&element(0), &element(5)])
                .expect("verify"),
            "a multiproof spanning base and draft leaves must verify"
        );
    }

    #[test]
    fn discard_throws_the_log_away() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut base = TestMmr::create(h, store.clone(), id(1)).expect("create");
        let els = elements(3);
        for el in &els {
            base.append(el).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft.append(&element(3)).expect("draft append");
        draft.append(&element(4)).expect("draft append");
        draft.discard();

        assert_eq!(
            base.leaf_count(),
            LeafCount::new(3),
            "discard must not grow the base"
        );
        assert_eq!(base.root(), reference_root(h, &slices(&els)));
        assert_eq!(stored_leaf_count(&store, id(1)), 3);
    }
}

// ----------------------------------------------------------------- commit

mod commit {
    use super::*;

    #[test]
    fn commit_replays_edits_and_reports_them() {
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..4 {
            base.append(&element(i)).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft
            .update(LeafIndex::new(1), b"rewritten", None)
            .expect("buffer update");
        draft
            .delete(LeafIndex::new(3), None)
            .expect("buffer delete");
        let composed_root = draft.root();

        let report = match draft.commit(Optimise::Off) {
            Ok(report) => report,
            Err(failure) => panic!("commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(report.edits, 2);
        assert_eq!(report.appended, LeafCount::ZERO);
        assert_eq!(
            base.root(),
            composed_root,
            "the base must land exactly on the draft's composed root"
        );
        assert_eq!(
            base.leaf_hash(LeafIndex::new(1)).expect("read"),
            Some(h.hash_leaf(b"rewritten").expect("hash"))
        );
        assert_eq!(
            base.leaf_hash(LeafIndex::new(3)).expect("read"),
            Some(h.genesis()),
            "delete writes the genesis value"
        );
        let proof = base.proof(LeafIndex::new(1)).expect("proof");
        assert!(base.verify(&proof, b"rewritten").expect("verify"));
    }

    #[test]
    fn a_failed_commit_returns_the_draft_and_keeps_the_applied_prefix() {
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        let els = elements(4);
        for el in &els {
            base.append(el).expect("append must succeed");
        }

        let (error, returned) = {
            let mut draft = base.start_draft();
            draft.append(&element(4)).expect("draft append");
            draft.append(&element(5)).expect("draft append");
            draft
                .update(LeafIndex::new(0), b"contested", Some(Hash::ZERO))
                .expect("the gate is only evaluated at commit time");
            match draft.commit(Optimise::Off) {
                Err(failure) => (failure.error, failure.draft),
                Ok(report) => panic!("a stale gate must fail the commit, got {report:?}"),
            }
        };
        match error {
            MmrError::UpdateMismatch { leaf } => assert_eq!(leaf, LeafIndex::new(0)),
            other => panic!("expected UpdateMismatch, got {other:?}"),
        }
        returned.discard();

        // Ops before the failing one were applied; the rejected edit was not.
        assert_eq!(
            base.leaf_count(),
            LeafCount::new(6),
            "appends before the failure are applied"
        );
        assert_eq!(
            base.leaf_hash(LeafIndex::new(0)).expect("read"),
            Some(h.hash_leaf(&els[0]).expect("hash")),
            "the rejected edit must not land"
        );
    }

    #[test]
    fn unoptimised_commit_replays_every_buffered_operation() {
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..2 {
            base.append(&element(i)).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft.append(&element(2)).expect("draft append");
        draft
            .delete(LeafIndex::new(2), None)
            .expect("buffer delete");
        let composed_root = draft.root();

        let report = match draft.commit(Optimise::Off) {
            Ok(report) => report,
            Err(failure) => panic!("commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(
            report.appended,
            LeafCount::new(1),
            "Optimise::Off keeps every append"
        );
        assert_eq!(report.edits, 1);
        assert_eq!(
            base.leaf_count(),
            LeafCount::new(3),
            "the intermediate append lands even though it is deleted right after"
        );
        assert_eq!(
            base.leaf_hash(LeafIndex::new(2)).expect("read"),
            Some(h.genesis())
        );
        assert_eq!(base.root(), composed_root);
    }
}

// ------------------------------------------------------- optimised commit

mod optimised_commit {
    use super::*;

    #[test]
    fn annihilates_an_ungated_append_delete_pair() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut base = TestMmrEdit::create_editable(h, store.clone(), id(1)).expect("create");
        let els = elements(4);
        for el in &els {
            base.append(el).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft.append(b"ephemeral").expect("draft append");
        draft
            .delete(LeafIndex::new(4), None)
            .expect("buffer delete");
        assert_eq!(
            draft.leaf_count(),
            LeafCount::new(5),
            "the composed view still shows the append"
        );

        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!("folded commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(report.appended, LeafCount::ZERO, "append+delete annihilate");
        assert_eq!(report.edits, 0);
        assert_eq!(
            base.leaf_count(),
            LeafCount::new(4),
            "the element never lands"
        );
        assert_eq!(base.root(), reference_root(h, &slices(&els)));
        assert_eq!(stored_leaf_count(&store, id(1)), 4);
    }

    #[test]
    fn skips_append_nullify_pairs() {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..4 {
            base.append(&element(i)).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft.append(b"ephemeral").expect("draft append");
        draft
            .nullify_shallow(LeafIndex::new(4))
            .expect("buffer nullify");

        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!("folded commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(report.appended, LeafCount::ZERO);
        assert_eq!(
            report.nullifications, 0,
            "both the append and its nullifier record are skipped"
        );
        assert_eq!(base.leaf_count(), LeafCount::new(4));
        let set = base.nullifier_set();
        assert_eq!(
            set.record(LeafIndex::new(4)).expect("read"),
            None,
            "no nullifier record may be written for a leaf that never existed"
        );
    }

    #[test]
    fn collapses_update_chains_to_the_final_value() {
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..4 {
            base.append(&element(i)).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft
            .update(LeafIndex::new(1), b"first", None)
            .expect("buffer");
        draft
            .update(LeafIndex::new(1), b"second", None)
            .expect("buffer");
        draft
            .update(LeafIndex::new(1), b"final", None)
            .expect("buffer");

        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!("folded commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(report.edits, 1, "an update chain collapses to one edit");
        assert_eq!(
            base.leaf_hash(LeafIndex::new(1)).expect("read"),
            Some(h.hash_leaf(b"final").expect("hash")),
            "only the chain's final value may land"
        );
    }

    #[test]
    fn keeps_the_earliest_gate_of_a_chain() {
        let h = hasher();
        // The earliest gate is correct → the folded chain applies once.
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..4 {
            base.append(&element(i)).expect("append must succeed");
        }
        let current = base
            .leaf_hash(LeafIndex::new(1))
            .expect("read")
            .expect("the leaf is occupied");
        let mut draft = base.start_draft();
        draft
            .update(LeafIndex::new(1), b"second", Some(current))
            .expect("buffer");
        draft
            .update(LeafIndex::new(1), b"final", None)
            .expect("buffer");
        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!("folded commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(report.edits, 1);
        assert_eq!(
            base.leaf_hash(LeafIndex::new(1)).expect("read"),
            Some(h.hash_leaf(b"final").expect("hash"))
        );

        // The earliest gate is stale → the whole chain fails closed.
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(2)).expect("create");
        for i in 0..4 {
            base.append(&element(i)).expect("append must succeed");
        }
        let occupied = base
            .leaf_hash(LeafIndex::new(1))
            .expect("read")
            .expect("occupied");
        let mut draft = base.start_draft();
        draft
            .update(LeafIndex::new(1), b"second", Some(Hash::ZERO))
            .expect("buffer");
        draft
            .update(LeafIndex::new(1), b"final", None)
            .expect("buffer");
        match draft.commit(Optimise::On) {
            Err(failure) => match failure.error {
                MmrError::UpdateMismatch { leaf } => assert_eq!(leaf, LeafIndex::new(1)),
                other => panic!("expected UpdateMismatch, got {other:?}"),
            },
            Ok(report) => panic!("a stale earliest gate must fail the commit, got {report:?}"),
        }
        assert_eq!(
            base.leaf_count(),
            LeafCount::new(4),
            "the failed commit must not apply"
        );
        assert_eq!(
            base.leaf_hash(LeafIndex::new(1)).expect("read"),
            Some(occupied),
            "the failed commit must not rewrite the leaf"
        );
    }

    #[test]
    fn folds_gates_on_draft_appended_leaves() {
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..2 {
            base.append(&element(i)).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft.append(b"initial").expect("draft append");
        draft
            .update(LeafIndex::new(2), b"revised", Some(Hash::ZERO))
            .expect("a draft-local gate cannot contend with a concurrent writer");

        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!("folded commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(report.appended, LeafCount::new(1));
        assert_eq!(report.edits, 0, "the gate folds into the append");
        assert_eq!(base.leaf_count(), LeafCount::new(3));
        assert_eq!(
            base.leaf_hash(LeafIndex::new(2)).expect("read"),
            Some(h.hash_leaf(b"revised").expect("hash")),
            "the append carries the chain's final value"
        );
    }

    #[test]
    fn still_applies_preexisting_nullifications() {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..4 {
            base.append(&element(i)).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft
            .nullify_shallow(LeafIndex::new(1))
            .expect("buffer shallow");
        draft.nullify_deep(LeafIndex::new(1)).expect("buffer deep");
        draft.append(b"ephemeral").expect("draft append");
        draft
            .nullify_shallow(LeafIndex::new(4))
            .expect("buffer nullify");

        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!("folded commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(
            report.nullifications, 1,
            "the shallow/deep pair folds to one record; the append+nullify pair vanishes"
        );
        assert_eq!(report.appended, LeafCount::ZERO);
        assert_eq!(base.leaf_count(), LeafCount::new(4));
        expect_nullified(base.proof(LeafIndex::new(1)), LeafIndex::new(1));
        let set = base.nullifier_set();
        assert_eq!(
            set.record(LeafIndex::new(1)).expect("read"),
            Some(NullifierRecord::Deep),
            "deep upgrades shallow when the pair folds"
        );
    }

    #[test]
    fn rejects_out_of_scope_buffers_at_buffer_time() {
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..3 {
            base.append(&element(i)).expect("append must succeed");
        }
        let mut draft = base.start_draft();
        match draft.update(LeafIndex::new(3), b"beyond", None) {
            Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from,
            }) => {
                assert_eq!(leaf, LeafIndex::new(3));
                assert_eq!(provable_from, LeafIndex::FIRST);
            }
            other => panic!("expected UnprovableLeaf at buffer time, got {other:?}"),
        }

        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(2)).expect("create");
        for i in 0..2 {
            base.append(&element(i)).expect("append must succeed");
        }
        let mut draft = base.start_draft();
        match draft.nullify_shallow(LeafIndex::new(2)) {
            Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from,
            }) => {
                assert_eq!(leaf, LeafIndex::new(2));
                assert_eq!(provable_from, LeafIndex::FIRST);
            }
            other => panic!("expected UnprovableLeaf at buffer time, got {other:?}"),
        }
    }
}

// ------------------------------------------------------- commit_as_stacked

mod commit_as_stacked {
    use super::*;

    /// Defect reference: `Mmr::init_stack` (src/mmr/handle.rs) reads the pinned
    /// peaks through `load_nodes` before installing `self.subs`, so the read is
    /// never routed to the sub-MMRs' stores and `Mmr::stack` panics with
    /// `unreachable!()` (MissingRecord(Nodes)) for any non-empty pin. These
    /// tests pin the intended `commit_as_stacked` semantics; un-ignore them
    /// once the routing order is fixed.
    #[test]
    fn builds_a_layer_over_the_untouched_base() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut base = TestMmr::create(h, store.clone(), id(1)).expect("create");
        let els = elements(5);
        for el in &els {
            base.append(el).expect("append must succeed");
        }
        let base_root = base.root();

        let mut draft = base.start_draft();
        draft
            .append_batch(&[element(5), element(6), element(7)])
            .expect("draft append");

        let stacked: TestStacked =
            match draft.commit_as_stacked(h, InMemoryStore::new(), id(2), Optimise::Off) {
                Ok(stacked) => stacked,
                Err(failure) => panic!("stacked commit must succeed, got {:?}", failure.error),
            };
        assert_eq!(stacked.leaf_count(), LeafCount::new(8));
        assert_eq!(
            stacked.root(),
            reference_root(h, &slices(&elements(8))),
            "the stacked root must equal the reference over base + draft elements"
        );
        assert_eq!(
            base.leaf_count(),
            LeafCount::new(5),
            "the base is untouched"
        );
        assert_eq!(base.root(), base_root);
        assert_eq!(stored_leaf_count(&store, id(1)), 5);

        let proof = stacked
            .proof(LeafIndex::new(7))
            .expect("draft leaf through the stack");
        assert!(stacked.verify(&proof, &element(7)).expect("verify"));
    }

    #[test]
    fn folds_with_optimisation() {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        let els = elements(4);
        for el in &els {
            base.append(el).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft.append(b"ephemeral").expect("draft append");
        draft
            .nullify_shallow(LeafIndex::new(4))
            .expect("buffer nullify");

        let stacked: TestStackedNull =
            match draft.commit_as_stacked(h, InMemoryStore::new(), id(2), Optimise::On) {
                Ok(stacked) => stacked,
                Err(failure) => panic!("stacked commit must succeed, got {:?}", failure.error),
            };
        assert_eq!(
            stacked.leaf_count(),
            LeafCount::new(4),
            "the annihilated append+nullify pair never reaches the stack"
        );
        assert_eq!(stacked.root(), reference_root(h, &slices(&els)));
        assert_eq!(
            base.leaf_count(),
            LeafCount::new(4),
            "the base is untouched"
        );
    }

    #[test]
    fn carries_nullifications_onto_the_new_layer() {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..3 {
            base.append(&element(i)).expect("append must succeed");
        }

        let mut draft = base.start_draft();
        draft
            .nullify_shallow(LeafIndex::new(1))
            .expect("buffer nullify");
        draft.append(b"new").expect("draft append");

        let stacked: TestStackedNull =
            match draft.commit_as_stacked(h, InMemoryStore::new(), id(2), Optimise::Off) {
                Ok(stacked) => stacked,
                Err(failure) => panic!("stacked commit must succeed, got {:?}", failure.error),
            };

        // The record lives on the new top layer, not in the base.
        assert_eq!(
            base.nullifier_set()
                .record(LeafIndex::new(1))
                .expect("read"),
            None,
            "the base's store must stay clean"
        );
        assert_eq!(
            stacked
                .nullifier_set()
                .record(LeafIndex::new(1))
                .expect("read"),
            Some(NullifierRecord::Shallow {
                at: size_of(LeafCount::new(3))
            }),
            "the record is written at the pin-time node count"
        );
        expect_nullified(stacked.proof(LeafIndex::new(1)), LeafIndex::new(1));

        // The base still proves leaf 1 — it never saw the record.
        let proof = base
            .proof(LeafIndex::new(1))
            .expect("the base is unchanged");
        assert!(base.verify(&proof, &element(1)).expect("verify"));

        assert_eq!(stacked.leaf_count(), LeafCount::new(4));
        let mut flat = elements(3);
        flat.push(b"new".to_vec());
        assert_eq!(
            stacked.root(),
            reference_root(h, &slices(&flat)),
            "nullifiers are policy records — the stacked root matches the flat reference"
        );
    }
}
