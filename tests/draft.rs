//! Draft-overlay test suite: in-memory appends and proofs, commit (both
//! `Optimise` modes), discard, `commit_as_stacked`, and the lost-update gate
//! semantics.
//!
//! Every root assertion is checked against an independent reference
//! computation built directly on [`Hasher::hash_pair`].

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(feature = "draft_mmr", feature = "memory", feature = "keccak_sol"))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::{Hasher, KeccakSolHasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::LeafCount;
use accumulators::mmr::{
    Editable, Mmr, MmrError, NullifierRecord, Nullifying, Optimise, Plain, Stacked,
};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::Store;
use accumulators::store::keys::{self, Table};
use accumulators::store::memory::InMemoryStore;
use accumulators::utils::mmr::size_of;

use common::{
    FaultyStore, composed_hashes, element, elements, flipped, id, leaf_hashes, node_sizes,
    prefix_roots, reference_peaks, reference_root, root_of_hashes, slices,
};

type TestMmr = Mmr<KeccakSolHasher, InMemoryStore>;
type TestMmrEdit = Mmr<KeccakSolHasher, InMemoryStore, Plain, Editable>;
type TestMmrNull = Mmr<KeccakSolHasher, InMemoryStore, Plain, Nullifying>;
type TestStacked = Mmr<KeccakSolHasher, InMemoryStore, Stacked>;
type TestStackedNull = Mmr<KeccakSolHasher, InMemoryStore, Stacked, Nullifying>;
type TestError = MmrError<InMemoryStore>;

// ---------------------------------------------------------------- helpers

fn hasher() -> KeccakSolHasher {
    KeccakSolHasher
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
            reference_root(&h, &slices(&elements(7))),
            "the draft root must match the flat reference over base + draft elements"
        );
        assert_eq!(
            draft.peaks(),
            reference_peaks(&h, &slices(&elements(7))),
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
            reference_root(&h, &slices(&elements(7))),
            "the committed root must equal the draft's composed root"
        );
        assert_eq!(base.leaf_count(), LeafCount::new(7));
        assert_eq!(base.root(), reference_root(&h, &slices(&elements(7))));
    }

    #[test]
    fn leaf_hash_covers_base_and_draft_leaves() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut base = TestMmr::create(h, store, id(1)).expect("create");
        base.append_batch(elements(4)).expect("append_batch");

        let base_provenance = base.provenance();

        let mut draft = base.start_draft();
        draft
            .append_batch(&[element(4), element(5)])
            .expect("draft append");

        // Delegation surface: id and provenance come from the base.
        assert_eq!(draft.id(), id(1));
        assert_eq!(draft.provenance(), base_provenance);

        // A base leaf resolves through the base's store.
        let base_hash = h.hash_leaf(&element(1)).expect("hash_leaf");
        assert_eq!(
            draft.leaf_hash(LeafIndex::new(1)).expect("leaf_hash"),
            Some(base_hash),
            "a base leaf's hash must resolve through the composed view"
        );

        // A draft-appended leaf resolves through the overlay — and equals
        // the element hash its proof will carry.
        let draft_leaf = LeafIndex::new(4);
        let draft_hash = draft.leaf_hash(draft_leaf).expect("leaf_hash");
        assert_eq!(
            draft_hash,
            Some(h.hash_leaf(&element(4)).expect("hash_leaf")),
            "a draft leaf's hash must resolve through the log"
        );
        assert_eq!(
            draft.proof(draft_leaf).expect("proof").element_hash,
            draft_hash.expect("draft leaf is occupied"),
            "leaf_hash must agree with the proof's element hash"
        );

        // Beyond the composed leaf count: unprovable, not a silent `None`.
        match draft.leaf_hash(LeafIndex::new(6)) {
            Err(MmrError::UnprovableLeaf { leaf, .. }) => {
                assert_eq!(leaf, LeafIndex::new(6));
            }
            other => panic!("expected UnprovableLeaf, got {other:?}"),
        }

        // The base handle is untouched by draft reads: its own leaf is
        // still there, and the draft leaf is out of its range.
        assert_eq!(
            base.leaf_hash(LeafIndex::new(3)).expect("leaf_hash"),
            Some(h.hash_leaf(&element(3)).expect("hash_leaf"))
        );
        assert!(matches!(
            base.leaf_hash(draft_leaf),
            Err(MmrError::UnprovableLeaf { .. })
        ));
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
        assert_eq!(base.root(), reference_root(&h, &slices(&els)));
        assert_eq!(stored_leaf_count(&store, id(1)), 3);
    }

    /// The nullifier query composes the buffered records with the base's:
    /// a buffered nullification resolves immediately with exactly the record
    /// its replay will write, base records resolve through the layers, and
    /// un-nullified leaves read as `None`.
    #[test]
    fn nullifier_query_composes_buffered_and_base_records() {
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..3 {
            base.append(&element(i)).expect("append must succeed");
        }
        base.nullifier_set()
            .nullify_shallow(LeafIndex::new(0), base.size())
            .expect("base record");
        let seed_size = base.size();

        let mut draft = base.start_draft();
        assert_eq!(
            draft.nullifier_record(LeafIndex::new(0)).expect("read"),
            Some(NullifierRecord::Shallow { at: seed_size }),
            "base records resolve through the draft"
        );

        draft
            .nullify_shallow(LeafIndex::new(1))
            .expect("buffer shallow");
        assert_eq!(
            draft.nullifier_record(LeafIndex::new(1)).expect("read"),
            Some(NullifierRecord::Shallow { at: seed_size }),
            "a buffered shallow record carries the composed size at buffer time"
        );
        draft.nullify_deep(LeafIndex::new(1)).expect("buffer deep");
        assert_eq!(
            draft.nullifier_record(LeafIndex::new(1)).expect("read"),
            Some(NullifierRecord::Deep),
            "a buffered deep record upgrades the shallow one"
        );
        assert_eq!(
            draft.nullifier_record(LeafIndex::new(2)).expect("read"),
            None
        );
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
    fn a_store_failure_mid_replay_returns_the_draft_and_keeps_the_applied_prefix() {
        let h = hasher();
        // The seam fails a store write *mid-replay*: the draft's commit
        // streams its ops as several store batches (each append run and each
        // edit is one write), and the fault is armed to hit the second of
        // them — after the first batch already applied.
        let store = FaultyStore::new(InMemoryStore::new());
        let faulted = store.clone();
        let mut base =
            Mmr::<KeccakSolHasher, FaultyStore<InMemoryStore>, Plain, Editable>::create_editable(
                h,
                store,
                id(1),
            )
            .expect("create");
        let els = elements(4);
        for el in &els {
            base.append(el).expect("append must succeed");
        }

        let (error, returned) = {
            let mut draft = base.start_draft();
            draft.append(&element(4)).expect("draft append");
            draft
                .update(LeafIndex::new(0), b"contested", None)
                .expect("buffer update");
            draft.append(&element(5)).expect("draft append");
            // The replay's first write is the buffered append run; the
            // second is this update's store write — it fails.
            faulted.fault().arm_write_failure_after(2);
            match draft.commit(Optimise::Off) {
                Err(failure) => (failure.error, failure.draft),
                Ok(report) => {
                    panic!("a mid-replay store failure must fail the commit, got {report:?}")
                }
            }
        };
        assert!(
            matches!(error, MmrError::Store(common::FaultError::Injected(_))),
            "the injected failure must surface through the store error axis, got {error:?}"
        );
        returned.discard();
        faulted.fault().arm_write_failure_after(0);

        // The applied prefix is kept: the append run before the failure
        // landed; the failing update and the append after it did not.
        assert_eq!(
            base.leaf_count(),
            LeafCount::new(5),
            "the append batch before the failure is applied"
        );
        assert_eq!(
            base.leaf_hash(LeafIndex::new(0)).expect("read"),
            Some(h.hash_leaf(&els[0]).expect("hash")),
            "the update whose store write failed must not land"
        );
        let proof = base.proof(LeafIndex::new(4)).expect("proof");
        assert!(
            base.verify(&proof, &element(4)).expect("verify"),
            "the applied prefix stays a verifiable MMR"
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
        assert_eq!(base.root(), reference_root(&h, &slices(&els)));
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
        // A gate that does not match the draft-local value is a caller bug:
        // rejected at buffer time, fail-closed — never silently dropped.
        match draft.update(LeafIndex::new(2), b"revised", Some(Hash::ZERO)) {
            Err(MmrError::UpdateMismatch { leaf }) => assert_eq!(leaf.get(), 2),
            other => panic!("expected buffer-time UpdateMismatch, got {other:?}"),
        }
        // A gate matching the draft-local value passes and folds into the
        // append (the gate never reaches the fold).
        let expected = h.hash_leaf(b"initial").expect("hash");
        draft
            .update(LeafIndex::new(2), b"revised", Some(expected))
            .expect("a matching draft-local gate passes at buffer time");

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
    fn resurrects_an_annihilated_draft_append_on_a_later_update() {
        // Hand-verified trace: [Append(A), Delete{gate:A}, Update→B] — the
        // buffer-time gate passes, the delete annihilates the append, and
        // the update re-occupies the leaf: the append survives with B.
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        base.append(&element(0)).expect("append must succeed");

        let mut draft = base.start_draft();
        draft.append(b"initial").expect("draft append");
        let gate = h.hash_leaf(b"initial").expect("hash");
        draft
            .delete(LeafIndex::new(1), Some(gate))
            .expect("gate matches the draft-local value");
        draft
            .update(LeafIndex::new(1), b"final", None)
            .expect("buffer update");

        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!("folded commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(
            report.appended,
            LeafCount::new(1),
            "the append survives as B"
        );
        assert_eq!(report.edits, 0, "delete+update fold into the append");
        assert_eq!(base.leaf_count(), LeafCount::new(2));
        assert_eq!(
            base.leaf_hash(LeafIndex::new(1)).expect("read"),
            Some(h.hash_leaf(b"final").expect("hash")),
            "the leaf carries the post-delete update's value"
        );
    }

    #[test]
    fn annihilates_a_gated_delete_then_an_ungated_delete_pair() {
        // Hand-verified trace: [Append(A), Delete{gate:A}, Delete{gate:None}]
        // — both gates pass at buffer time and fold away; the pair
        // annihilates, so the leaf never commits.
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        base.append(&element(0)).expect("append must succeed");

        let mut draft = base.start_draft();
        draft.append(b"initial").expect("draft append");
        let gate = h.hash_leaf(b"initial").expect("hash");
        draft
            .delete(LeafIndex::new(1), Some(gate))
            .expect("first gate passes");
        draft
            .delete(LeafIndex::new(1), None)
            .expect("second delete is gate-free");

        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!("folded commit must succeed, got {:?}", failure.error),
        };
        assert_eq!(
            report.appended,
            LeafCount::ZERO,
            "append + deletes annihilate"
        );
        assert_eq!(report.edits, 0);
        assert_eq!(base.leaf_count(), LeafCount::new(1));
    }

    #[test]
    fn annihilates_duplicate_hash_appends_without_shifting_indexes() {
        // Hand-verified wrong-leaf trace: with duplicate append hashes and
        // an annihilated first append, a later gated delete on the second
        // append must not survive the fold — its buffer-time index would
        // shift down at replay and target the wrong (or nonexistent) leaf.
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        base.append(&element(0)).expect("append must succeed");

        let mut draft = base.start_draft();
        draft.append(b"shared").expect("draft append 1");
        draft
            .append(b"shared")
            .expect("draft append 2 (duplicate hash)");
        draft
            .delete(LeafIndex::new(1), None)
            .expect("delete the first append");
        // The gate is evaluated and stripped at buffer time, so the fold
        // annihilates cleanly instead of replaying a shifted index.
        let gate = h.hash_leaf(b"shared").expect("hash");
        draft
            .delete(LeafIndex::new(2), Some(gate))
            .expect("gate matches the second append");

        let report = match draft.commit(Optimise::On) {
            Ok(report) => report,
            Err(failure) => panic!(
                "annihilated appends must not shift a surviving delete onto the wrong leaf, got {:?}",
                failure.error
            ),
        };
        assert_eq!(report.appended, LeafCount::ZERO, "both appends annihilate");
        assert_eq!(base.leaf_count(), LeafCount::new(1));
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
        // Nullifications are index-keyed records: an out-of-range leaf is a
        // range error, not a provability error.
        match draft.nullify_shallow(LeafIndex::new(2)) {
            Err(MmrError::LeafOutOfRange { leaf, leaf_count }) => {
                assert_eq!(leaf, LeafIndex::new(2));
                assert_eq!(leaf_count, LeafCount::new(2));
            }
            other => panic!("expected LeafOutOfRange at buffer time, got {other:?}"),
        }
    }
}

// ------------------------------------------------------- commit_as_stacked

mod commit_as_stacked {
    use super::*;

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
            reference_root(&h, &slices(&elements(8))),
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
        assert_eq!(stacked.root(), reference_root(&h, &slices(&els)));
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
            reference_root(&h, &slices(&flat)),
            "nullifiers are policy records — the stacked root matches the flat reference"
        );
    }
}

// ---------------------------------------------------------- consistency

mod consistency {
    use super::*;
    use accumulators::mmr::{MmrSize, WithPeaks, verify_consistency_proof};

    type TestDraftEdit<'m> =
        accumulators::mmr::Draft<'m, KeccakSolHasher, InMemoryStore, Plain, Editable>;

    /// Every prefix pair of an append-only draft verifies against the flat
    /// reference — including the degenerate empty and trivial prefixes. A
    /// draft's target size is its current composed size (as with any
    /// handle), so each `m` restarts the draft with `m − BASE` appends.
    #[test]
    fn append_only_draft_every_prefix_pair_verifies() {
        const BASE: usize = 10;
        const TOTAL: usize = 20;
        let h = hasher();
        let mut base = TestMmr::create(h, InMemoryStore::new(), id(30)).expect("create");
        for el in &elements(BASE as u64) {
            base.append(el).expect("append must succeed");
        }

        let hashes = composed_hashes(&h, TOTAL, &[], &[]);
        let roots = prefix_roots(&h, &hashes);
        let sizes = node_sizes(TOTAL);
        for m in BASE..=TOTAL {
            let mut draft = base.start_draft();
            for i in BASE..m {
                draft.append(&element(i as u64)).expect("draft append");
            }
            assert_eq!(draft.leaf_count(), LeafCount::new(m as u64));
            for n in 0..=m {
                let proof = draft
                    .consistency_proof(sizes[n])
                    .unwrap_or_else(|error| panic!("consistency ({n}, {m}) failed: {error}"));
                assert_eq!(proof.prev_size, sizes[n]);
                assert_eq!(proof.size, sizes[m]);
                assert!(
                    matches!(
                        verify_consistency_proof(&h, &proof, roots[n], roots[m]),
                        Ok(true)
                    ),
                    "consistency ({n}, {m}) must verify"
                );
            }
        }
    }

    /// A draft with buffered updates and deletes: every prefix pair
    /// verifies against the *effective* (edited) oracle, and the proofs
    /// commit the buffered values — the unedited flat roots are rejected.
    #[test]
    fn edited_draft_prefixes_carry_the_buffered_values() {
        const BASE: usize = 10;
        const TOTAL: usize = 16;
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(31)).expect("create");
        for el in &elements(BASE as u64) {
            base.append(el).expect("append must succeed");
        }

        // Effective leaf values: update(2), delete(5), then the appends —
        // of which the one landing on leaf 12 is itself rewritten.
        let mut effective: Vec<Hash> = leaf_hashes(&h, &slices(&elements(BASE as u64)))
            .into_iter()
            .collect();
        effective[2] = h.hash_leaf(b"updated-2").expect("valid element");
        effective[5] = h.genesis();
        for i in BASE..TOTAL {
            effective.push(if i == BASE + 2 {
                h.hash_leaf(b"updated-12").expect("valid element")
            } else {
                h.hash_leaf(&element(i as u64)).expect("valid element")
            });
        }
        let roots = prefix_roots(&h, &effective);
        let sizes = node_sizes(TOTAL);

        for m in BASE..=TOTAL {
            let mut draft = base.start_draft();
            draft
                .update(LeafIndex::new(2), b"updated-2", None)
                .expect("buffer update");
            draft
                .delete(LeafIndex::new(5), None)
                .expect("buffer delete");
            for i in BASE..m {
                draft.append(&element(i as u64)).expect("draft append");
            }
            if m > BASE + 2 {
                // A rewrite of a draft-appended leaf, above the base's
                // horizon.
                draft
                    .update(LeafIndex::new((BASE + 2) as u64), b"updated-12", None)
                    .expect("buffer update on a draft leaf");
            }
            for n in 0..=m {
                let proof = draft
                    .consistency_proof(sizes[n])
                    .unwrap_or_else(|error| panic!("consistency ({n}, {m}) failed: {error}"));
                assert!(
                    matches!(
                        verify_consistency_proof(&h, &proof, roots[n], roots[m]),
                        Ok(true)
                    ),
                    "consistency ({n}, {m}) must verify against the edited oracle"
                );
            }
        }

        // The prefix statement is about the composed values *now*: against
        // the unedited flat history the same proof does not verify.
        let unedited: Vec<Hash> = leaf_hashes(&h, &slices(&elements(TOTAL as u64)))
            .into_iter()
            .collect();
        let flat = prefix_roots(&h, &unedited);
        let mut draft = base.start_draft();
        draft
            .update(LeafIndex::new(2), b"updated-2", None)
            .expect("buffer update");
        let proof = draft.consistency_proof(sizes[6]).expect("generate");
        assert!(
            matches!(
                verify_consistency_proof(&h, &proof, flat[6], roots[TOTAL]),
                Ok(false)
            ),
            "the unedited earlier root must not verify"
        );
    }

    /// Nullifications change no node values: the prefix statement is
    /// unaffected, and buffered records are never consulted. The replace
    /// appends one leaf; the oracle is the plain flat history over
    /// base + appends (element(100) included).
    #[test]
    fn nullifications_do_not_disturb_the_prefix_statement() {
        const BASE: usize = 8;
        const TOTAL: usize = 14;
        let h = hasher();
        let mut base =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(32)).expect("create");
        for el in &elements(BASE as u64) {
            base.append(el).expect("append must succeed");
        }

        // Effective leaf values: the nullified leaves keep their node
        // values; the replace appends element(100), then plain appends.
        let mut effective: Vec<Hash> = leaf_hashes(&h, &slices(&elements(BASE as u64)))
            .into_iter()
            .collect();
        effective.push(h.hash_leaf(&element(100)).expect("valid element"));
        for i in BASE..TOTAL - 1 {
            effective.push(h.hash_leaf(&element(i as u64)).expect("valid element"));
        }
        let roots = prefix_roots(&h, &effective);
        let sizes = node_sizes(TOTAL);

        for m in (BASE + 1)..=TOTAL {
            let mut draft = base.start_draft();
            draft
                .nullify_shallow(LeafIndex::new(1))
                .expect("buffer nullify");
            draft
                .replace_shallow(LeafIndex::new(4), &element(100))
                .expect("buffer replace");
            for i in BASE..m - 1 {
                draft.append(&element(i as u64)).expect("draft append");
            }
            for n in 0..=m {
                let proof = draft
                    .consistency_proof(sizes[n])
                    .unwrap_or_else(|error| panic!("consistency ({n}, {m}) failed: {error}"));
                assert!(
                    matches!(
                        verify_consistency_proof(&h, &proof, roots[n], roots[m]),
                        Ok(true)
                    ),
                    "consistency ({n}, {m}) must verify"
                );
            }
        }
    }

    /// `Optimise::On` folds the log at commit, but the composed view is the
    /// buffer-time fold in order: pre-commit proofs commit the composed
    /// shape under either replay strategy, and the committed handles'
    /// proofs match their own shapes.
    #[test]
    fn composed_proofs_are_independent_of_the_replay_strategy() {
        fn base_of_six(h: KeccakSolHasher, store: InMemoryStore, byte: u8) -> TestMmrEdit {
            let mut base = TestMmrEdit::create_editable(h, store, id(byte)).expect("create");
            for el in &elements(6) {
                base.append(el).expect("append must succeed");
            }
            base
        }

        // append(6), delete(6), append(7): the fold annihilates the first
        // append, the composed view keeps it (as genesis).
        fn buffer_annihilating_log(draft: &mut TestDraftEdit<'_>) {
            draft.append(&element(6)).expect("draft append");
            draft
                .delete(LeafIndex::new(6), None)
                .expect("buffer delete");
            draft.append(&element(7)).expect("draft append");
        }

        let h = hasher();
        // The composed view: 8 leaves — leaf 6 is genesis (deleted),
        // leaf 7 is element(7).
        let mut composed: Vec<Hash> = leaf_hashes(&h, &slices(&elements(6))).into_iter().collect();
        composed.push(h.genesis());
        composed.push(h.hash_leaf(&element(7)).expect("valid element"));
        let composed_roots = prefix_roots(&h, &composed);
        let composed_sizes = node_sizes(8);

        // Off: the committed handle reproduces the composed shape
        // byte-for-byte, for every prefix pair.
        let mut base_off = base_of_six(h, InMemoryStore::new(), 33);
        let mut draft = base_off.start_draft();
        buffer_annihilating_log(&mut draft);
        assert_eq!(draft.leaf_count(), LeafCount::new(8));
        let off_proofs: Vec<_> = (0..=8)
            .map(|n| {
                draft
                    .consistency_proof(composed_sizes[n])
                    .expect("generate")
            })
            .collect();
        draft.commit(Optimise::Off).expect("commit");
        for (n, proof) in off_proofs.iter().enumerate() {
            assert_eq!(
                &base_off
                    .consistency_proof(composed_sizes[n])
                    .expect("generate"),
                proof,
                "the committed handle serves the same proof as the draft ({n}, 8)"
            );
            assert!(matches!(
                verify_consistency_proof(&h, proof, composed_roots[n], composed_roots[8]),
                Ok(true)
            ));
        }

        // On: the fold erases the annihilated append — the committed shape
        // is 7 leaves with element(7) at leaf 6, so the composed proofs no
        // longer match the handle's, and the handle's verify against the
        // folded oracle.
        let folded_roots = prefix_roots(&h, &composed_hashes(&h, 6, &[], &[element(7)]));
        let mut base_on = base_of_six(h, InMemoryStore::new(), 34);
        let mut draft = base_on.start_draft();
        buffer_annihilating_log(&mut draft);
        let composed_proof = draft
            .consistency_proof(composed_sizes[4])
            .expect("generate");
        draft.commit(Optimise::On).expect("commit");
        assert_eq!(
            base_on.leaf_count(),
            LeafCount::new(7),
            "the fold erased one leaf"
        );
        let committed_proof = base_on
            .consistency_proof(size_of(LeafCount::new(4)))
            .expect("generate");
        assert_ne!(
            committed_proof, composed_proof,
            "the folded shape differs from the composed shape"
        );
        assert!(matches!(
            verify_consistency_proof(&h, &committed_proof, folded_roots[4], folded_roots[7]),
            Ok(true)
        ));
    }

    /// Degenerate anchors, the draft-level verifier, and the typed
    /// rejections: tampered anchors are `Ok(false)`, fabricated structure
    /// is a typed error, out-of-range and malformed sizes are
    /// `InvalidPrevSize`.
    #[test]
    fn degenerate_verify_and_rejections() {
        let h = hasher();
        let mut base =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(35)).expect("create");
        for el in &elements(10) {
            base.append(el).expect("append must succeed");
        }
        let mut draft = base.start_draft();
        draft
            .update(LeafIndex::new(3), b"updated-3", None)
            .expect("buffer update");
        for i in 10..14_u64 {
            draft.append(&element(i)).expect("draft append");
        }

        let hashes = composed_hashes(
            &h,
            10,
            &[(3, Some(b"updated-3".to_vec()))],
            &[element(10), element(11), element(12), element(13)],
        );
        let roots = prefix_roots(&h, &hashes);
        let sizes = node_sizes(14);

        // Empty prefix and trivial prefix, from the composed peaks alone.
        let empty_root = root_of_hashes(&h, &[]);
        let proof = draft.consistency_proof(MmrSize::ZERO).expect("generate");
        assert_eq!(proof.prev_peaks, [] as [Hash; 0]);
        assert!(matches!(
            verify_consistency_proof(&h, &proof, empty_root, roots[14]),
            Ok(true)
        ));
        let trivial = draft.consistency_proof(sizes[14]).expect("generate");
        assert_eq!(trivial.path, [] as [Hash; 0]);
        assert!(matches!(
            verify_consistency_proof(&h, &trivial, roots[14], roots[14]),
            Ok(true)
        ));

        // The draft-level verifier: positive, then tampered anchors.
        let proof = draft.consistency_proof(sizes[5]).expect("generate");
        assert!(draft.verify_consistency(&proof, roots[5]).expect("verify"));
        assert!(matches!(
            draft.verify_consistency(&proof, flipped(roots[5])),
            Ok(false)
        ));
        // A proof generated for a different target size does not verify
        // against the current composed root: the base handle's own root is
        // the pre-draft state, so a proof committed to it misses the
        // composed target.
        let stale = base.consistency_proof(sizes[5]).expect("generate");
        let draft = base.start_draft();
        assert!(matches!(
            draft.verify_consistency(&stale, roots[5]),
            Ok(false)
        ));

        // Structural fabrication: truncated path is a typed error.
        let mut truncated = proof;
        truncated.path.pop();
        assert!(matches!(
            verify_consistency_proof(&h, &truncated, roots[5], roots[14]),
            Err(accumulators::mmr::VerifyError::Inconsistent(_))
        ));

        // Out of range, and a malformed (non-well-formed) size.
        assert!(matches!(
            draft.consistency_proof(size_of(LeafCount::new(15))),
            Err(MmrError::InvalidPrevSize { .. })
        ));
        assert!(matches!(
            draft.consistency_proof(MmrSize::new_unchecked(5)),
            Err(MmrError::InvalidPrevSize { .. })
        ));
    }

    /// A `WithPeaks` base keeps its seed floor under a draft: below the
    /// floor is a typed rejection, the empty prefix and the floor itself
    /// are servable, and everything at or above verifies against the flat
    /// reference.
    #[test]
    fn withpeaks_floor_survives_the_draft() {
        let h = hasher();
        let mut seed_base = TestMmr::create(h, InMemoryStore::new(), id(36)).expect("create");
        for el in &elements(6) {
            seed_base.append(el).expect("append must succeed");
        }
        let seed = seed_base.size();
        let mut peaks_mmr: Mmr<KeccakSolHasher, InMemoryStore, WithPeaks> =
            Mmr::from_peaks(h, InMemoryStore::new(), id(36), seed, seed_base.peaks())
                .expect("seed succeeds");
        for i in 6..10_usize {
            peaks_mmr.append(&element(i as u64)).expect("append");
        }

        let mut draft = peaks_mmr.start_draft();
        for i in 10..12_u64 {
            draft.append(&element(i)).expect("draft append");
        }

        let hashes = composed_hashes(&h, 12, &[], &[]);
        let roots = prefix_roots(&h, &hashes);
        let sizes = node_sizes(12);
        // At the floor and above (including draft-only sizes), plus the
        // always-servable empty prefix.
        for n in [0_usize, 6, 7, 9, 11, 12] {
            let proof = draft
                .consistency_proof(sizes[n])
                .unwrap_or_else(|error| panic!("consistency from {n} failed: {error}"));
            let prev_root = if n == 0 {
                root_of_hashes(&h, &[])
            } else {
                roots[n]
            };
            assert!(
                matches!(
                    verify_consistency_proof(&h, &proof, prev_root, roots[12]),
                    Ok(true)
                ),
                "consistency ({n}, 12) must verify"
            );
        }
        // Below the floor: typed rejection.
        assert!(matches!(
            draft.consistency_proof(sizes[3]),
            Err(MmrError::InvalidPrevSize { .. })
        ));
    }
}
