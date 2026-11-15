//! Plain-MMR test suite: create/open round trips, appends, roots against a
//! brute-force reference, proofs and multiproofs, peaks-only seeds, editable
//! and nullifying modes, and the `open` corruption contract.
//!
//! Every root assertion is checked against an independent reference
//! computation built directly on [`Hasher::hash_pair`] — never against the
//! crate's own state core.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "mmr",
    feature = "memory",
    feature = "keccak_sol",
    feature = "blake2s_stark"
))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::{Blake2sStarkHasher, Hasher, KeccakSolHasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::proof::verify_proof;
use accumulators::mmr::{
    AppendOnly, Corrupted, Editable, Mmr, MmrError, NullifierError, NullifierRecord, Nullifying,
    Plain, PlainAppendMmr, PlainEditableMmr, PlainNullifyingMmr, Proof, Provenance, UpdateOutcome,
    WithPeaks, WithPeaksAppendMmr, WithPeaksEditableMmr, WithPeaksNullifyingMmr,
};
use accumulators::mmr::{LeafCount, MmrSize, bag_peaks, peaks_of, root_from, size_of};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::keys::{self, Table};
use accumulators::store::memory::InMemoryStore;
use accumulators::store::{Batch, Store};

use common::{element, elements, id, reference_peaks, reference_root, slices};

type TestMmr = Mmr<KeccakSolHasher, InMemoryStore>;
type BlakeMmr = Mmr<Blake2sStarkHasher, InMemoryStore>;
type TestMmrEdit = Mmr<KeccakSolHasher, InMemoryStore, Plain, Editable>;
type TestMmrNull = Mmr<KeccakSolHasher, InMemoryStore, Plain, Nullifying>;
type TestError = MmrError<InMemoryStore>;

// ---------------------------------------------------------------- helpers

fn hasher() -> KeccakSolHasher {
    KeccakSolHasher
}

/// Overwrites the single-subkey record of `table` with arbitrary bytes.
fn poke(store: &InMemoryStore, id: AccumulatorId, table: Table, value: Vec<u8>) {
    let mut batch = Batch::new();
    batch.put_owned(keys::encode(&id, table, 0), value);
    store.write(batch).expect("in-memory writes are infallible");
}

fn expect_nullified(proof: Result<Proof<Hash>, TestError>, leaf: LeafIndex) {
    match proof {
        Err(MmrError::LeafNullified { leaf: refused }) => {
            assert_eq!(refused, leaf, "the error must name the requested leaf");
        }
        other => panic!("expected LeafNullified for leaf {leaf}, got {other:?}"),
    }
}

fn expect_unprovable(
    proof: Result<Proof<Hash>, TestError>,
    leaf: LeafIndex,
    provable_from: LeafIndex,
) {
    match proof {
        Err(MmrError::UnprovableLeaf {
            leaf: refused,
            provable_from: floor,
        }) => {
            assert_eq!(refused, leaf, "the error must name the requested leaf");
            assert_eq!(
                floor, provable_from,
                "the provenance floor must be reported"
            );
        }
        other => panic!("expected UnprovableLeaf for leaf {leaf}, got {other:?}"),
    }
}

fn expect_update_mismatch(result: Result<UpdateOutcome<Hash>, TestError>, leaf: LeafIndex) {
    match result {
        Err(MmrError::UpdateMismatch { leaf: rejected }) => {
            assert_eq!(rejected, leaf, "the error must name the rejected leaf");
        }
        other => panic!("expected UpdateMismatch for leaf {leaf}, got {other:?}"),
    }
}

fn assert_malformed(result: Result<TestMmr, TestError>, table: Table) {
    match result {
        Err(MmrError::Corrupted(Corrupted::MalformedRecord { table: found })) => {
            assert_eq!(found, table, "the error must name the malformed table");
        }
        Err(other) => panic!("expected MalformedRecord({table:?}), got {other:?}"),
        Ok(_) => panic!("expected MalformedRecord({table:?}), but the MMR opened"),
    }
}

// -------------------------------------------------------------- lifecycle

mod lifecycle {
    use super::*;

    #[test]
    fn create_then_open_round_trips_metadata_and_state() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut mmr = TestMmr::create(h, store.clone(), id(1)).expect("create must succeed");
        let els = elements(7);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }

        let mut reopened = TestMmr::open(h, store, id(1)).expect("open must succeed");
        assert_eq!(reopened.id(), id(1), "the id survives the round trip");
        assert_eq!(reopened.leaf_count(), LeafCount::new(7));
        assert_eq!(reopened.size(), size_of(LeafCount::new(7)));
        assert_eq!(
            reopened.peaks(),
            reference_peaks(&h, &slices(&els)),
            "persisted peaks must match the brute-force reference"
        );
        assert_eq!(reopened.root(), mmr.root(), "the cached root must survive");
        assert_eq!(reopened.provenance(), Provenance::Full);

        for i in 7..9 {
            reopened
                .append(&element(i))
                .expect("reopened MMR keeps appending");
        }
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(9))),
            "growth after reopen must track the reference"
        );
    }

    #[test]
    fn empty_mmr_bags_the_genesis() {
        let h = hasher();
        let mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        assert_eq!(
            mmr.root(),
            root_from(&h, bag_peaks(&h, &[]), MmrSize::ZERO),
            "the empty root is the bagged genesis at size 0"
        );
        assert_eq!(mmr.leaf_count(), LeafCount::ZERO);
        assert_eq!(mmr.size(), MmrSize::ZERO);
        assert!(mmr.peaks().is_empty(), "an empty MMR has no peaks");
        assert_eq!(mmr.provenance(), Provenance::Full);
        expect_unprovable(
            mmr.proof(LeafIndex::FIRST),
            LeafIndex::FIRST,
            LeafIndex::FIRST,
        );
    }

    #[test]
    fn open_rejects_an_empty_store() {
        match TestMmr::open(hasher(), InMemoryStore::new(), id(1)) {
            Err(MmrError::Corrupted(Corrupted::MissingRecord { table })) => {
                assert_eq!(table, Table::HasherInfo, "the hasher record is read first");
            }
            Err(other) => panic!("expected MissingRecord(HasherInfo), got {other:?}"),
            Ok(_) => panic!("expected MissingRecord(HasherInfo), but the MMR opened"),
        }
    }

    #[test]
    fn open_rejects_a_hasher_id_mismatch() {
        let h = hasher();
        let store = InMemoryStore::new();
        TestMmr::create(h, store.clone(), id(1)).expect("create must succeed");
        match BlakeMmr::open(Blake2sStarkHasher { truncate: true }, store, id(1)) {
            Err(MmrError::Corrupted(Corrupted::HasherMismatch { stored, .. })) => {
                assert!(
                    stored.contains("keccak_sol"),
                    "the stored identity must name the creating hasher, got {stored}"
                );
            }
            Err(other) => panic!("expected HasherMismatch, got {other:?}"),
            Ok(_) => panic!("expected HasherMismatch, but the MMR opened"),
        }
    }

    #[test]
    fn open_rejects_a_hasher_config_mismatch() {
        let store = InMemoryStore::new();
        BlakeMmr::create(Blake2sStarkHasher { truncate: false }, store.clone(), id(1))
            .expect("create must succeed");
        match BlakeMmr::open(Blake2sStarkHasher { truncate: true }, store, id(1)) {
            Err(MmrError::Corrupted(Corrupted::HasherMismatch { stored, .. })) => {
                assert!(
                    stored.contains("truncate=false"),
                    "the persisted config must be validated, got {stored}"
                );
            }
            Err(other) => panic!("expected HasherMismatch, got {other:?}"),
            Ok(_) => panic!("expected HasherMismatch, but the MMR opened"),
        }
    }

    #[test]
    fn open_rejects_a_mode_mismatch() {
        let h = hasher();
        let store = InMemoryStore::new();
        TestMmrEdit::create_editable(h, store.clone(), id(1)).expect("create must succeed");
        match Mmr::<KeccakSolHasher, InMemoryStore, Plain, AppendOnly>::open(h, store, id(1)) {
            Err(MmrError::Corrupted(Corrupted::ModeMismatch { stored, declared })) => {
                assert_eq!(stored, "editable", "the persisted mode must be reported");
                assert_eq!(
                    declared, "append_only",
                    "the declared mode must be reported"
                );
            }
            Err(other) => panic!("expected ModeMismatch, got {other:?}"),
            Ok(_) => panic!("expected ModeMismatch, but the MMR opened"),
        }
    }

    #[test]
    fn open_rejects_malformed_metadata_records() {
        let h = hasher();
        // Garbage under the mode record.
        {
            let store = InMemoryStore::new();
            TestMmr::create(h, store.clone(), id(1)).expect("create must succeed");
            poke(&store, id(1), Table::Mode, vec![0xff, 0xff, 0x00]);
            assert_malformed(TestMmr::open(h, store, id(1)), Table::Mode);
        }
        // A counter shorter than the 8-byte wire format.
        {
            let store = InMemoryStore::new();
            TestMmr::create(h, store.clone(), id(1)).expect("create must succeed");
            poke(&store, id(1), Table::LeafCount, vec![1, 2, 3]);
            assert_malformed(TestMmr::open(h, store, id(1)), Table::LeafCount);
        }
        // An unknown hasher wire tag.
        {
            let store = InMemoryStore::new();
            TestMmr::create(h, store.clone(), id(1)).expect("create must succeed");
            poke(&store, id(1), Table::HasherInfo, vec![0xfe]);
            assert_malformed(TestMmr::open(h, store, id(1)), Table::HasherInfo);
        }
    }

    #[test]
    fn open_rejects_a_tampered_root() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut mmr = TestMmr::create(h, store.clone(), id(1)).expect("create must succeed");
        mmr.append(b"payload").expect("append must succeed");
        poke(&store, id(1), Table::Root, vec![0x5a; 32]);
        match TestMmr::open(h, store, id(1)) {
            Err(MmrError::Corrupted(Corrupted::RootMismatch)) => {}
            Err(other) => panic!("expected RootMismatch, got {other:?}"),
            Ok(_) => panic!("expected RootMismatch, but the MMR opened"),
        }
    }

    #[test]
    fn open_rejects_inconsistent_counters() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut mmr = TestMmr::create(h, store.clone(), id(1)).expect("create must succeed");
        for i in 0..10 {
            mmr.append(&element(i)).expect("append must succeed");
        }
        // Ten leaves imply node_count 18; a leaf_count of 8 contradicts it.
        poke(
            &store,
            id(1),
            Table::LeafCount,
            8_u64.to_be_bytes().to_vec(),
        );
        match TestMmr::open(h, store, id(1)) {
            Err(MmrError::Corrupted(Corrupted::PeaksMismatch { expected, found })) => {
                let node_count = size_of(LeafCount::new(10));
                assert_eq!(
                    expected,
                    node_count.get().count_ones() as usize,
                    "expected reports the peak count implied by the node count"
                );
                assert_eq!(
                    found,
                    8_u64.count_ones() as usize,
                    "found reports the peak count implied by the stored counter"
                );
            }
            Err(other) => panic!("expected PeaksMismatch, got {other:?}"),
            Ok(_) => panic!("expected PeaksMismatch, but the MMR opened"),
        }
    }

    #[test]
    fn open_rejects_a_missing_peak_node() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut mmr = TestMmr::create(h, store.clone(), id(1)).expect("create must succeed");
        for i in 0..5 {
            mmr.append(&element(i)).expect("append must succeed");
        }
        let first_peak = peaks_of(size_of(LeafCount::new(5)))[0];
        let mut batch = Batch::new();
        batch.delete(keys::encode(&id(1), Table::Nodes, first_peak.get()));
        store.write(batch).expect("in-memory writes are infallible");
        match TestMmr::open(h, store, id(1)) {
            Err(MmrError::Corrupted(Corrupted::MissingRecord { table })) => {
                assert_eq!(table, Table::Nodes);
            }
            Err(other) => panic!("expected MissingRecord(Nodes), got {other:?}"),
            Ok(_) => panic!("expected MissingRecord(Nodes), but the MMR opened"),
        }
    }
}

// ---------------------------------------------------------------- appends

mod appends {
    use super::*;

    #[test]
    fn roots_track_the_brute_force_reference_for_every_size() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let mut all: Vec<Vec<u8>> = Vec::new();
        for i in 0..=40_u64 {
            assert_eq!(
                mmr.root(),
                reference_root(&h, &slices(&all)),
                "root must equal the brute-force reference at {i} leaves"
            );
            assert_eq!(
                mmr.size(),
                size_of(LeafCount::new(i)),
                "node count must be 2L − popcount(L) at {i} leaves"
            );
            assert_eq!(
                mmr.peaks().len(),
                i.count_ones() as usize,
                "peak count must be popcount(L) at {i} leaves"
            );
            if i < 40 {
                let el = element(i);
                mmr.append(&el).expect("append must succeed");
                all.push(el);
            }
        }
    }

    #[test]
    fn append_reports_the_leaf_node_and_new_root() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");

        let first = mmr.append(b"first").expect("append must succeed");
        assert_eq!(first.leaf, LeafIndex::FIRST);
        assert_eq!(first.node.get(), 1, "the first leaf sits at node 1");
        assert_eq!(first.root, reference_root(&h, &[b"first".as_slice()]));
        assert_eq!(
            first.root,
            mmr.root(),
            "the outcome root is the cached root"
        );

        let second = mmr.append(b"second").expect("append must succeed");
        assert_eq!(second.leaf, LeafIndex::new(1));
        assert_eq!(
            second.node.get(),
            2,
            "leaf i sits at node 2i + 1 − popcount(i)"
        );
        assert_eq!(
            second.root,
            reference_root(&h, &[b"first".as_slice(), b"second".as_slice()])
        );
    }

    #[test]
    fn append_batch_matches_sequential_appends() {
        let h = hasher();
        let els = elements(10);
        let els_slices = slices(&els);

        let mut batched = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create");
        let outcome = batched.append_batch(&els_slices).expect("batch append");
        assert_eq!(outcome.first_leaf, LeafIndex::FIRST);
        assert_eq!(outcome.appended, LeafCount::new(10));
        assert_eq!(outcome.root, batched.root());
        assert_eq!(outcome.root, reference_root(&h, &els_slices));

        let mut sequential = TestMmr::create(h, InMemoryStore::new(), id(2)).expect("create");
        for el in &els_slices {
            sequential.append(el).expect("append must succeed");
        }
        assert_eq!(
            batched.root(),
            sequential.root(),
            "batch and loop must land on the same root"
        );
        assert_eq!(batched.peaks(), sequential.peaks());

        let more = [element(10), element(11)];
        let outcome = batched
            .append_batch([&more[0], &more[1]])
            .expect("batch append");
        assert_eq!(outcome.first_leaf, LeafIndex::new(10));
        assert_eq!(outcome.appended, LeafCount::new(2));
        let mut all = els.clone();
        all.extend(more);
        assert_eq!(batched.root(), reference_root(&h, &slices(&all)));

        let before = batched.root();
        let outcome = batched
            .append_batch(Vec::<&[u8]>::new())
            .expect("empty batch");
        assert_eq!(
            outcome.appended,
            LeafCount::ZERO,
            "an empty batch appends nothing"
        );
        assert_eq!(outcome.first_leaf, LeafIndex::new(12));
        assert_eq!(
            outcome.root, before,
            "an empty batch must not move the root"
        );
    }

    #[test]
    fn leaf_hash_reads_the_stored_element_hash() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(4);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }
        for (index, el) in els.iter().enumerate() {
            assert_eq!(
                mmr.leaf_hash(LeafIndex::new(index as u64)).expect("read"),
                Some(h.hash_leaf(el).expect("hash")),
                "leaf {index} must hold its own element hash"
            );
        }
        match mmr.leaf_hash(LeafIndex::new(4)) {
            Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from,
            }) => {
                assert_eq!(leaf, LeafIndex::new(4));
                assert_eq!(provable_from, LeafIndex::FIRST);
            }
            other => panic!(
                "leaf_hash is range-checked: beyond the leaf count must be UnprovableLeaf, got {other:?}"
            ),
        }
    }
}

// ----------------------------------------------------------------- proofs

mod proofs {
    use super::*;

    #[test]
    fn every_leaf_proof_verifies_for_its_own_element_only() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(31);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }

        for (index, el) in els.iter().enumerate() {
            let leaf = LeafIndex::new(index as u64);
            let proof = mmr.proof(leaf).expect("every appended leaf is provable");
            assert_eq!(proof.leaf, leaf);
            assert_eq!(proof.element_hash, h.hash_leaf(el).expect("hash"));
            assert_eq!(
                proof.root,
                mmr.root(),
                "the proof commits to the current root"
            );
            assert_eq!(proof.size, mmr.size());
            assert!(
                mmr.verify(&proof, el).expect("verify"),
                "leaf {index} must verify"
            );
            assert!(
                !mmr.verify(&proof, b"not-the-element").expect("verify"),
                "a foreign element must not verify for leaf {index}"
            );
        }
    }

    #[test]
    fn multiproof_over_all_leaves_verifies() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(24);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }

        let leaves: Vec<LeafIndex> = (0..24).map(LeafIndex::new).collect();
        let proof = mmr.multiproof(leaves.clone()).expect("multiproof");
        assert_eq!(proof.leaves, leaves, "leaves stay in canonical order");
        assert!(mmr.verify_multi(&proof, &slices(&els)).expect("verify"));

        let mut wrong = els.clone();
        wrong[7] = b"swapped".to_vec();
        assert!(
            !mmr.verify_multi(&proof, &slices(&wrong)).expect("verify"),
            "a swapped element must not verify"
        );
    }

    #[test]
    fn truncated_multiproof_is_structurally_rejected() {
        use accumulators::mmr::VerifyError;
        use accumulators::mmr::proof::{ProofInconsistency, verify_multi_proof};

        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(8);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }

        let leaves = [LeafIndex::new(0), LeafIndex::new(3), LeafIndex::new(5)];
        let proof = mmr.multiproof(leaves).expect("multiproof");
        let proof_els = [&els[0], &els[3], &els[5]];
        assert!(
            verify_multi_proof(&h, &proof, &proof_els).expect("verify"),
            "the honest multiproof verifies"
        );

        // An attacker drops one element-hash commitment: the commitments no
        // longer align with the leaves. A shortened ref list must never
        // "verify" against fewer commitments — the alignment check must
        // reject it as a structural error, never a false Ok.
        let mut truncated = Clone::clone(&proof);
        truncated.element_hashes.truncate(2);
        match verify_multi_proof(&h, &truncated, &proof_els) {
            Err(VerifyError::Inconsistent(ProofInconsistency::ElementCountMismatch {
                leaves: 3,
                elements: 2,
            })) => {}
            other => panic!("expected ElementCountMismatch, got {other:?}"),
        }

        // The full attack: shrink the commitments *and* the sibling refs.
        let mut shrunk = Clone::clone(&proof);
        shrunk.element_hashes.truncate(2);
        shrunk.sibling_refs.truncate(2);
        assert!(
            verify_multi_proof(&h, &shrunk, &proof_els).is_err(),
            "a truncated multiproof must be a structural error"
        );

        // Refs alone may not run short either — the reference budget is
        // validated structurally *before* the replay (an early Ok(false)
        // must never mask a malformed ref count), so this is a typed
        // PathLengthMismatch, not a mid-replay RefOutOfBounds.
        let mut short_refs = Clone::clone(&proof);
        short_refs.sibling_refs.truncate(1);
        match verify_multi_proof(&h, &short_refs, &proof_els) {
            Err(VerifyError::Inconsistent(ProofInconsistency::PathLengthMismatch {
                siblings: 1,
                ..
            })) => {}
            other => panic!("expected PathLengthMismatch, got {other:?}"),
        }
    }

    #[test]
    fn a_corrupt_node_value_is_malformed_not_missing() {
        // A present-but-unparsable node value is corruption; it must be
        // diagnosed as such, never conflated with an absent record.
        let h = hasher();
        let store = InMemoryStore::new();
        let mut mmr = TestMmr::create(h, store.clone(), id(1)).expect("create");
        mmr.append(&element(0)).expect("append");
        mmr.append(&element(1)).expect("append");

        // Leaf 0 lives at node index 1; poison it.
        let mut batch = Batch::new();
        batch.put_owned(keys::encode(&id(1), Table::Nodes, 1), vec![0xff; 3]);
        store.write(batch).expect("in-memory writes are infallible");

        match mmr.proof(LeafIndex::new(0)) {
            Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::Nodes,
            })) => {}
            other => panic!("expected MalformedRecord(Nodes), got {other:?}"),
        }
    }

    #[test]
    fn multiproof_subset_shares_a_deduped_sibling_pool() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(32);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }

        let subset = [
            LeafIndex::new(0),
            LeafIndex::new(1),
            LeafIndex::new(6),
            LeafIndex::new(17),
        ];
        let proof = mmr.multiproof(subset).expect("multiproof");
        let subset_els = [
            els[0].as_slice(),
            els[1].as_slice(),
            els[6].as_slice(),
            els[17].as_slice(),
        ];
        assert!(mmr.verify_multi(&proof, subset_els).expect("verify"));
        assert!(
            !mmr.verify_multi(
                &proof,
                [
                    b"wrong".as_slice(),
                    b"w".as_slice(),
                    b"a".as_slice(),
                    b"t".as_slice()
                ]
            )
            .expect("verify")
        );

        // Leaves 0 and 1 share every sibling above height 0.
        let pair = mmr
            .multiproof([LeafIndex::new(0), LeafIndex::new(1)])
            .expect("multiproof");
        assert!(
            pair.sibling_pool.len() < pair.sibling_refs.len(),
            "leaves sharing a subtree must share pooled siblings"
        );
    }

    #[test]
    fn multiproof_normalizes_leaf_order_and_dedups() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(8);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }

        let proof = mmr
            .multiproof([
                LeafIndex::new(5),
                LeafIndex::new(2),
                LeafIndex::new(5),
                LeafIndex::new(0),
            ])
            .expect("multiproof");
        assert_eq!(
            proof.leaves,
            vec![LeafIndex::new(0), LeafIndex::new(2), LeafIndex::new(5)],
            "leaves must be sorted and deduplicated"
        );
        let aligned = [els[0].as_slice(), els[2].as_slice(), els[5].as_slice()];
        assert!(mmr.verify_multi(&proof, aligned).expect("verify"));
        let misaligned = [els[5].as_slice(), els[2].as_slice(), els[0].as_slice()];
        assert!(
            !mmr.verify_multi(&proof, misaligned).expect("verify"),
            "misaligned elements must fail the hash commitment, not panic"
        );
    }

    #[test]
    fn tampered_proofs_verify_false_without_erroring() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(31);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }
        let proof = mmr.proof(LeafIndex::new(9)).expect("proof");

        let mut bad_sibling = proof.clone();
        let mut raw = *bad_sibling.siblings[0].as_bytes();
        raw[0] ^= 0xff;
        bad_sibling.siblings[0] = Hash::from_bytes(raw);
        assert!(!mmr.verify(&bad_sibling, &els[9]).expect("verify"));

        let mut bad_element = proof.clone();
        let mut raw = *bad_element.element_hash.as_bytes();
        raw[31] ^= 0x01;
        bad_element.element_hash = Hash::from_bytes(raw);
        assert!(!mmr.verify(&bad_element, &els[9]).expect("verify"));

        let mut bad_root = proof.clone();
        let mut raw = *bad_root.root.as_bytes();
        raw[0] ^= 0x80;
        bad_root.root = Hash::from_bytes(raw);
        assert!(!mmr.verify(&bad_root, &els[9]).expect("verify"));

        let mut bad_peak = proof;
        let mut raw = *bad_peak.peaks[0].as_bytes();
        raw[1] ^= 0xff;
        bad_peak.peaks[0] = Hash::from_bytes(raw);
        assert!(!mmr.verify(&bad_peak, &els[9]).expect("verify"));
    }

    #[test]
    fn a_truncated_single_proof_is_structurally_rejected() {
        use accumulators::mmr::VerifyError;
        use accumulators::mmr::proof::ProofInconsistency;

        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(31);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }
        let proof = mmr.proof(LeafIndex::new(9)).expect("proof");
        let honest_siblings = proof.siblings.len();
        assert!(honest_siblings > 1, "leaf 9's path has several steps");

        // An attacker drops siblings from the path: the honest element can
        // then no longer be folded to the committed peak. Like the
        // multiproof case above, the shortened proof must be rejected as a
        // typed structural error — never a false `Ok(true)`, never a panic,
        // and never a silent `Ok(false)` that would mask the malformation.
        let mut truncated = proof.clone();
        truncated.siblings.truncate(honest_siblings - 1);
        match mmr.verify(&truncated, &els[9]) {
            Err(MmrError::Verify(VerifyError::Inconsistent(
                ProofInconsistency::PathLengthMismatch {
                    siblings,
                    expected: _,
                },
            ))) => {
                assert_eq!(
                    siblings,
                    honest_siblings - 1,
                    "the error names the attacker's shortened path"
                );
            }
            other => panic!("expected PathLengthMismatch, got {other:?}"),
        }

        // The standalone verifier (no store) enforces the same structure.
        match verify_proof(&h, &truncated, &els[9]) {
            Err(VerifyError::Inconsistent(ProofInconsistency::PathLengthMismatch { .. })) => {}
            other => panic!("expected PathLengthMismatch, got {other:?}"),
        }

        // The fully-emptied path is rejected the same way.
        let mut empty = proof;
        empty.siblings.clear();
        assert!(verify_proof(&h, &empty, &els[9]).is_err());
    }

    #[test]
    fn a_proof_from_an_older_root_stops_verifying_after_growth() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        let els = elements(10);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }
        let old_proof = mmr.proof(LeafIndex::new(3)).expect("proof");

        for i in 10..30 {
            mmr.append(&element(i)).expect("append must succeed");
        }
        assert!(
            !mmr.verify(&old_proof, &els[3]).expect("verify"),
            "a proof taken before later appends must not verify against the grown root"
        );
        assert!(
            verify_proof(&h, &old_proof, &els[3]).expect("standalone verify"),
            "the standalone verifier needs no store and honours the proof's own commitment"
        );
    }

    #[test]
    fn a_proof_beyond_the_leaf_count_is_unprovable() {
        let h = hasher();
        let mut mmr = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create must succeed");
        mmr.append(b"only").expect("append must succeed");
        expect_unprovable(
            mmr.proof(LeafIndex::new(1)),
            LeafIndex::new(1),
            LeafIndex::FIRST,
        );
    }
}

// ------------------------------------------------------------- from_peaks

mod from_peaks {
    use super::*;

    #[test]
    fn peaks_only_seed_shares_the_root_and_proves_above_the_floor() {
        let h = hasher();
        let mut full = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create");
        let els = elements(5);
        for el in &els {
            full.append(el).expect("append must succeed");
        }
        let seed_size = full.size();
        let seed_peaks = full.peaks().to_vec();
        assert_eq!(
            seed_peaks,
            reference_peaks(&h, &slices(&els)),
            "the built MMR's peaks must match the brute-force reference"
        );

        let peaks_mmr = Mmr::<KeccakSolHasher, InMemoryStore, WithPeaks>::from_peaks(
            h,
            InMemoryStore::new(),
            id(2),
            seed_size,
            &seed_peaks,
        )
        .expect("from_peaks must succeed");
        assert_eq!(
            peaks_mmr.root(),
            full.root(),
            "a peaks-only MMR has the same root as its source"
        );
        assert_eq!(peaks_mmr.leaf_count(), full.leaf_count());
        assert_eq!(peaks_mmr.size(), seed_size);
        assert_eq!(
            peaks_mmr.provenance(),
            Provenance::FromPeaks {
                size_at_creation: seed_size
            }
        );

        expect_unprovable(
            peaks_mmr.proof(LeafIndex::new(2)),
            LeafIndex::new(2),
            LeafIndex::new(5),
        );
        match peaks_mmr.leaf_hash(LeafIndex::new(0)) {
            Err(MmrError::UnprovableLeaf { .. }) => {}
            other => panic!("leaves below the floor cannot be read, got {other:?}"),
        }

        let mut grown = peaks_mmr;
        for i in 5..8 {
            grown
                .append(&element(i))
                .expect("append on top of the seed");
        }
        assert_eq!(
            grown.root(),
            reference_root(&h, &slices(&elements(8))),
            "appends on the seed must track the reference"
        );
        for leaf in [5_u64, 6, 7] {
            let proof = grown.proof(LeafIndex::new(leaf)).expect("above the floor");
            assert!(
                grown.verify(&proof, &element(leaf)).expect("verify"),
                "leaf {leaf} must verify above the floor"
            );
        }
    }

    #[test]
    fn from_peaks_rejects_inconsistent_seeds() {
        let h = hasher();
        let size_five = size_of(LeafCount::new(5));
        match Mmr::<KeccakSolHasher, InMemoryStore, WithPeaks>::from_peaks(
            h,
            InMemoryStore::new(),
            id(1),
            size_five,
            &[Hash::ZERO],
        ) {
            Err(MmrError::InvalidPeaks { size, peaks }) => {
                assert_eq!(size, size_five);
                assert_eq!(peaks, 1, "five leaves need two peaks, not one");
            }
            Err(other) => panic!("expected InvalidPeaks, got {other:?}"),
            Ok(_) => panic!("expected InvalidPeaks, but the seed was accepted"),
        }
    }

    #[test]
    fn from_peaks_rejects_a_malformed_size() {
        let h = hasher();
        match Mmr::<KeccakSolHasher, InMemoryStore, WithPeaks>::from_peaks(
            h,
            InMemoryStore::new(),
            id(1),
            MmrSize::new_unchecked(2),
            &[],
        ) {
            Err(MmrError::InvalidPeaks { size, peaks }) => {
                assert_eq!(size.get(), 2, "2 is not a well-formed MMR node count");
                assert_eq!(peaks, 0);
            }
            Err(other) => panic!("expected InvalidPeaks, got {other:?}"),
            Ok(_) => panic!("expected InvalidPeaks, but the seed was accepted"),
        }
    }

    /// Provenance is persisted (`Table::Provenance`): a peaks-only MMR
    /// re-opens as peaks-only with its seed floor intact, a Plain open of a
    /// peaks-only store (and a `WithPeaks` open of a full-history store) is
    /// rejected, and a store missing the provenance record fails closed.
    #[test]
    fn from_peaks_provenance_survives_reopen_and_keeps_the_floor() {
        let h = hasher();
        let mut full = TestMmr::create(h, InMemoryStore::new(), id(1)).expect("create");
        for el in &elements(5) {
            full.append(el).expect("append must succeed");
        }
        let seed_size = full.size();
        let seed_peaks = full.peaks().to_vec();

        let store = InMemoryStore::new();
        drop(
            Mmr::<KeccakSolHasher, InMemoryStore, WithPeaks>::from_peaks(
                h,
                store.clone(),
                id(2),
                seed_size,
                &seed_peaks,
            )
            .expect("from_peaks must succeed"),
        );

        // WithPeaks open parity: the reconstructed handle keeps the floor.
        let reopened =
            Mmr::<KeccakSolHasher, InMemoryStore, WithPeaks>::open(h, store.clone(), id(2))
                .expect("a peaks-only store re-opens as WithPeaks");
        assert_eq!(
            reopened.provenance(),
            Provenance::FromPeaks {
                size_at_creation: seed_size
            },
            "the seed provenance must survive the reopen"
        );
        expect_unprovable(
            reopened.proof(LeafIndex::new(2)),
            LeafIndex::new(2),
            LeafIndex::new(5),
        );
        let mut grown = reopened;
        grown.append(&element(5)).expect("append after reopen");
        assert_eq!(
            grown.root(),
            reference_root(&h, &slices(&elements(6))),
            "a reopened peaks-only MMR keeps growing identically"
        );

        // A Plain open of a peaks-only store would silently lose the floor.
        match TestMmr::open(h, store.clone(), id(2)) {
            Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::Provenance,
            })) => {}
            Err(other) => panic!("expected MalformedRecord(Provenance), got {other:?}"),
            Ok(_) => panic!("expected MalformedRecord(Provenance), but the MMR opened"),
        }

        // The mirror: a WithPeaks open of a full-history store.
        let plain_store = InMemoryStore::new();
        drop(TestMmr::create(h, plain_store.clone(), id(3)).expect("create"));
        match Mmr::<KeccakSolHasher, InMemoryStore, WithPeaks>::open(h, plain_store, id(3)) {
            Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::Provenance,
            })) => {}
            Err(other) => panic!("expected MalformedRecord(Provenance), got {other:?}"),
            Ok(_) => panic!("expected MalformedRecord(Provenance), but the MMR opened"),
        }

        // An absent provenance record fails closed: a missing record is
        // corruption, never an "assume Full" default.
        let mut batch = Batch::new();
        batch.delete(keys::encode(&id(2), Table::Provenance, 0));
        store.write(batch).expect("in-memory writes are infallible");
        match TestMmr::open(h, store.clone(), id(2)) {
            Err(MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Provenance,
            })) => {}
            Err(other) => panic!("expected MissingRecord(Provenance), got {other:?}"),
            Ok(_) => panic!("expected MissingRecord(Provenance), but the MMR opened"),
        }
        match Mmr::<KeccakSolHasher, InMemoryStore, WithPeaks>::open(h, store, id(2)) {
            Err(MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Provenance,
            })) => {}
            Err(other) => panic!("expected MissingRecord(Provenance), got {other:?}"),
            Ok(_) => panic!("expected MissingRecord(Provenance), but the MMR opened"),
        }
    }
}

// --------------------------------------------------------------- editable

mod editable {
    use super::*;

    #[test]
    fn update_rewrites_a_leaf_and_recomputes_the_root() {
        let h = hasher();
        let mut mmr = TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        let els = elements(6);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }
        let root_before = mmr.root();
        let previous = mmr
            .leaf_hash(LeafIndex::new(2))
            .expect("read")
            .expect("the leaf is occupied");

        let outcome = mmr
            .update(LeafIndex::new(2), b"edited", None)
            .expect("update");
        assert_eq!(outcome.leaf, LeafIndex::new(2));
        assert_eq!(
            outcome.previous,
            Some(previous),
            "the outcome reports the old hash"
        );
        assert_ne!(outcome.root, root_before, "an edit must move the root");
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(2)).expect("read"),
            Some(h.hash_leaf(b"edited").expect("hash"))
        );

        let proof = mmr.proof(LeafIndex::new(5)).expect("proof");
        assert!(
            mmr.verify(&proof, &els[5]).expect("verify"),
            "siblings keep verifying"
        );
        let edited = mmr.proof(LeafIndex::new(2)).expect("proof");
        assert!(
            mmr.verify(&edited, b"edited").expect("verify"),
            "the edit verifies"
        );
    }

    #[test]
    fn delete_clears_a_leaf_to_genesis() {
        let h = hasher();
        let mut mmr = TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        let els = elements(5);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }

        let outcome = mmr.delete(LeafIndex::new(3), None).expect("delete");
        assert_eq!(outcome.previous, Some(h.hash_leaf(&els[3]).expect("hash")));
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(3)).expect("read"),
            Some(h.genesis()),
            "delete writes the genesis value"
        );
        let proof = mmr
            .proof(LeafIndex::new(3))
            .expect("the leaf stays provable");
        assert_eq!(
            proof.element_hash,
            h.genesis(),
            "the proof commits to the cleared value"
        );
    }

    #[test]
    fn the_expected_current_gate_rejects_stale_values() {
        let h = hasher();
        let mut mmr = TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..4 {
            mmr.append(&element(i)).expect("append must succeed");
        }

        expect_update_mismatch(
            mmr.update(LeafIndex::new(1), b"contested", Some(Hash::ZERO)),
            LeafIndex::new(1),
        );
        let current = mmr
            .leaf_hash(LeafIndex::new(1))
            .expect("read")
            .expect("the leaf is occupied");
        mmr.update(LeafIndex::new(1), b"contested", Some(current))
            .expect("the correct gate must pass");

        let current = mmr
            .leaf_hash(LeafIndex::new(1))
            .expect("read")
            .expect("the leaf is occupied");
        mmr.delete(LeafIndex::new(1), Some(current))
            .expect("delete with a fresh gate");
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(1)).expect("read"),
            Some(h.genesis())
        );
    }

    #[test]
    fn an_edit_onto_a_missing_leaf_node_is_corruption_not_a_gate_mismatch() {
        // The structure is dense: a leaf whose node record is absent is
        // store corruption. The edit must fail as MissingRecord even with
        // the gate skipped (no gate means unconditional — never "repair by
        // overwriting nothing").
        let h = hasher();
        let store = InMemoryStore::new();
        let mut mmr = TestMmrEdit::create_editable(h, store.clone(), id(1)).expect("create");
        mmr.append(b"only").expect("append must succeed");

        let mut batch = Batch::new();
        batch.delete(keys::encode(
            &id(1),
            Table::Nodes,
            LeafIndex::FIRST.node().get(),
        ));
        store.write(batch).expect("in-memory writes are infallible");

        match mmr.update(LeafIndex::FIRST, b"edited", None) {
            Err(MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Nodes,
            })) => {}
            other => panic!("expected MissingRecord(Nodes), got {other:?}"),
        }
        match mmr.delete(LeafIndex::FIRST, None) {
            Err(MmrError::Corrupted(Corrupted::MissingRecord {
                table: Table::Nodes,
            })) => {}
            other => panic!("expected MissingRecord(Nodes), got {other:?}"),
        }
    }

    #[test]
    fn editable_with_peaks_refuses_edits_below_the_floor() {
        let h = hasher();
        let mut full =
            TestMmrEdit::create_editable(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..5 {
            full.append(&element(i)).expect("append must succeed");
        }
        let mut peaks_mmr = Mmr::<KeccakSolHasher, InMemoryStore, WithPeaks, Editable>::from_peaks(
            h,
            InMemoryStore::new(),
            id(2),
            full.size(),
            full.peaks(),
        )
        .expect("from_peaks must succeed");

        match peaks_mmr.update(LeafIndex::new(0), b"below", None) {
            Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from,
            }) => {
                assert_eq!(leaf, LeafIndex::new(0));
                assert_eq!(provable_from, LeafIndex::new(5));
            }
            other => panic!("expected UnprovableLeaf below the floor, got {other:?}"),
        }

        peaks_mmr
            .append(&element(5))
            .expect("append on top of the seed");
        peaks_mmr
            .update(LeafIndex::new(5), b"above", None)
            .expect("leaves above the floor are editable");
    }
}

// ------------------------------------------------------------- nullifying

mod nullifying {
    use super::*;

    #[test]
    fn shallow_nullification_refuses_proofs_and_records_the_size() {
        let h = hasher();
        let mut mmr =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        let els = elements(6);
        for el in &els {
            mmr.append(el).expect("append must succeed");
        }
        let at = mmr.size();

        let outcome = mmr.nullify_shallow(LeafIndex::new(2)).expect("nullify");
        assert_eq!(outcome.leaf, LeafIndex::new(2));
        assert_eq!(outcome.record, NullifierRecord::Shallow { at });

        expect_nullified(mmr.proof(LeafIndex::new(2)), LeafIndex::new(2));
        let proof = mmr
            .proof(LeafIndex::new(4))
            .expect("untouched leaves still prove");
        assert!(mmr.verify(&proof, &els[4]).expect("verify"));
        assert_eq!(
            mmr.root(),
            reference_root(&h, &slices(&els)),
            "nullifiers are policy records — the data and root are untouched"
        );

        let set = mmr.nullifier_set();
        assert_eq!(
            set.record(LeafIndex::new(2)).expect("read"),
            Some(NullifierRecord::Shallow { at })
        );
        assert_eq!(set.record(LeafIndex::new(4)).expect("read"), None);
        let batch = set
            .records([LeafIndex::new(1), LeafIndex::new(2), LeafIndex::new(3)])
            .expect("batch read");
        assert_eq!(
            batch,
            vec![None, Some(NullifierRecord::Shallow { at }), None],
            "batch reads stay positionally aligned"
        );
    }

    #[test]
    fn replace_shallow_nullifies_the_old_leaf_and_appends_a_new_one() {
        let h = hasher();
        let els = elements(5);
        let mut replaced =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        let mut manual =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(2)).expect("create");
        for el in &els {
            replaced.append(el).expect("append must succeed");
            manual.append(el).expect("append must succeed");
        }

        let outcome = replaced
            .replace_shallow(LeafIndex::new(3), b"replacement")
            .expect("replace");
        assert_eq!(outcome.nullified, LeafIndex::new(3));
        assert_eq!(
            outcome.record,
            NullifierRecord::Shallow {
                at: size_of(LeafCount::new(5))
            }
        );
        assert_eq!(outcome.appended.leaf, LeafIndex::new(5));
        assert_eq!(outcome.root, replaced.root());

        manual
            .nullify_shallow(LeafIndex::new(3))
            .expect("nullify must succeed");
        manual.append(b"replacement").expect("append must succeed");

        assert_eq!(
            replaced.root(),
            manual.root(),
            "replace is exactly nullify + append"
        );
        assert_eq!(replaced.leaf_count(), manual.leaf_count());
        expect_nullified(replaced.proof(LeafIndex::new(3)), LeafIndex::new(3));
        let proof = replaced
            .proof(LeafIndex::new(5))
            .expect("the new leaf proves");
        assert!(replaced.verify(&proof, b"replacement").expect("verify"));
    }

    #[test]
    fn deep_nullification_is_recorded_and_blocks_proofs() {
        let h = hasher();
        let mut mmr =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        for i in 0..6 {
            mmr.append(&element(i)).expect("append must succeed");
        }

        let outcome = mmr.nullify_deep(LeafIndex::new(1)).expect("nullify");
        assert_eq!(outcome.leaf, LeafIndex::new(1));
        assert_eq!(outcome.record, NullifierRecord::Deep);
        expect_nullified(mmr.proof(LeafIndex::new(1)), LeafIndex::new(1));
        assert_eq!(
            mmr.nullifier_set().record(LeafIndex::new(1)).expect("read"),
            Some(NullifierRecord::Deep)
        );
    }

    #[test]
    fn nullify_beyond_the_leaf_count_is_out_of_range() {
        let h = hasher();
        let mut mmr =
            TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        mmr.append(b"only").expect("append must succeed");
        // Nullifier records are index-keyed — an out-of-range leaf is a
        // range error with the leaf count, not a fabricated provability
        // payload.
        match mmr.nullify_shallow(LeafIndex::new(9)) {
            Err(MmrError::LeafOutOfRange { leaf, leaf_count }) => {
                assert_eq!(leaf, LeafIndex::new(9));
                assert_eq!(leaf_count, LeafCount::new(1));
            }
            other => panic!("expected LeafOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn nullifier_records_only_strengthen() {
        let h = hasher();
        let mmr = TestMmrNull::create_nullifying(h, InMemoryStore::new(), id(1)).expect("create");
        let set = mmr.nullifier_set();

        assert!(
            set.nullify_shallow(LeafIndex::new(1), MmrSize::new_unchecked(50))
                .expect("write"),
            "the first write lands"
        );
        assert!(
            !set.nullify_shallow(LeafIndex::new(1), MmrSize::new_unchecked(100))
                .expect("write"),
            "a larger size never replaces a smaller record"
        );
        assert_eq!(
            set.record(LeafIndex::new(1)).expect("read"),
            Some(NullifierRecord::Shallow {
                at: MmrSize::new_unchecked(50)
            })
        );
        assert!(
            set.nullify_deep(LeafIndex::new(1)).expect("write"),
            "deep upgrades shallow"
        );
        assert_eq!(
            set.record(LeafIndex::new(1)).expect("read"),
            Some(NullifierRecord::Deep)
        );
        assert!(
            !set.nullify_deep(LeafIndex::new(1)).expect("write"),
            "deep over deep keeps the existing record"
        );

        match set.nullify_shallow(LeafIndex::new(2), MmrSize::ZERO) {
            Err(NullifierError::ZeroShallowSize) => {}
            other => panic!("size 0 is the deep marker, got {other:?}"),
        }
    }

    #[test]
    fn a_corrupt_nullifier_record_fails_closed() {
        let h = hasher();
        let store = InMemoryStore::new();
        let mut mmr = TestMmrNull::create_nullifying(h, store.clone(), id(1)).expect("create");
        mmr.append(&element(0)).expect("append");
        mmr.nullify_shallow(LeafIndex::new(0)).expect("nullify");

        // Corrupt the record: present, but not a parseable size.
        let mut batch = Batch::new();
        batch.put_owned(keys::encode(&id(1), Table::Nullifiers, 0), vec![0xff; 3]);
        store.write(batch).expect("in-memory writes are infallible");

        match mmr.nullifier_set().record(LeafIndex::new(0)) {
            Err(NullifierError::MalformedRecord) => {}
            other => panic!("expected MalformedRecord, got {other:?}"),
        }
        // The proof path fails closed too — a corrupt record must never
        // read as "not nullified" (the leaf silently provable).
        match mmr.proof(LeafIndex::new(0)) {
            Err(MmrError::Nullifier(NullifierError::MalformedRecord)) => {}
            other => panic!("expected Nullifier(MalformedRecord), got {other:?}"),
        }
    }
}

// ---------------------------------------------------- hasher-info bounds

mod hasher_info_bounds {
    use super::*;
    use accumulators::hashers::{Hasher, HasherError, HasherId};
    use std::borrow::Cow;

    /// A custom hasher with controllable identity/config; hashing delegates
    /// to Keccak so behavior is real.
    #[derive(Clone, Copy, Debug, Default)]
    struct BoundedHasher {
        name: &'static str,
        config: &'static str,
    }

    impl Hasher for BoundedHasher {
        type Output = Hash;

        fn id(&self) -> HasherId {
            HasherId::Custom(self.name)
        }

        fn config(&self) -> Cow<'static, str> {
            Cow::Borrowed(self.config)
        }

        fn hash_pair(&self, left: Hash, right: Hash) -> Hash {
            KeccakSolHasher.hash_pair(left, right)
        }

        fn hash_leaf(&self, element: &[u8]) -> Result<Hash, HasherError> {
            KeccakSolHasher.hash_leaf(element)
        }

        fn genesis(&self) -> Hash {
            KeccakSolHasher.genesis()
        }
    }

    type BoundedMmr = Mmr<BoundedHasher, InMemoryStore>;

    #[test]
    fn create_rejects_an_over_long_custom_hasher_name() {
        // 256 bytes cannot fit the record's u8 name prefix; create must
        // reject, not truncate (truncation would alias hashers on later open).
        let name: &'static str = Box::leak("x".repeat(256).into_boxed_str());
        let hasher = BoundedHasher { name, config: "" };
        match BoundedMmr::create(hasher, InMemoryStore::new(), id(1)) {
            Err(MmrError::UnrepresentableHasher) => {}
            Err(other) => panic!("expected UnrepresentableHasher, got {other:?}"),
            Ok(_) => panic!("expected UnrepresentableHasher, but the MMR was created"),
        }
    }

    #[test]
    fn create_rejects_an_over_long_hasher_config() {
        // 65536 bytes cannot fit the record's u16 config prefix.
        let config: &'static str = Box::leak("c".repeat(65_536).into_boxed_str());
        let hasher = BoundedHasher { name: "ok", config };
        match BoundedMmr::create(hasher, InMemoryStore::new(), id(1)) {
            Err(MmrError::UnrepresentableHasher) => {}
            Err(other) => panic!("expected UnrepresentableHasher, got {other:?}"),
            Ok(_) => panic!("expected UnrepresentableHasher, but the MMR was created"),
        }
    }
}

// ------------------------------------------------------------ type aliases

#[test]
fn kind_mode_aliases_resolve_to_the_plain_generics() {
    // The alias's `Id` default must resolve identically to the struct's own:
    // `PlainAppendMmr<H, S>` is exactly `Mmr<H, S>`, and each alias carries
    // the named constructors of its pinned kind × mode combination.
    fn takes_default(
        mmr: Mmr<KeccakSolHasher, InMemoryStore>,
    ) -> Mmr<KeccakSolHasher, InMemoryStore> {
        mmr
    }

    let append: PlainAppendMmr<KeccakSolHasher, InMemoryStore> =
        Mmr::create(hasher(), InMemoryStore::new(), id(1)).expect("create");
    let _ = takes_default(append);

    let _: PlainEditableMmr<KeccakSolHasher, InMemoryStore> =
        PlainEditableMmr::create_editable(hasher(), InMemoryStore::new(), id(2)).expect("create");
    let _: PlainNullifyingMmr<KeccakSolHasher, InMemoryStore> =
        PlainNullifyingMmr::create_nullifying(hasher(), InMemoryStore::new(), id(3))
            .expect("create");
    let _: WithPeaksAppendMmr<KeccakSolHasher, InMemoryStore> =
        WithPeaksAppendMmr::from_peaks(hasher(), InMemoryStore::new(), id(4), MmrSize::ZERO, &[])
            .expect("from peaks");
    let _: WithPeaksEditableMmr<KeccakSolHasher, InMemoryStore> =
        WithPeaksEditableMmr::from_peaks(hasher(), InMemoryStore::new(), id(5), MmrSize::ZERO, &[])
            .expect("from peaks");
    let _: WithPeaksNullifyingMmr<KeccakSolHasher, InMemoryStore> =
        WithPeaksNullifyingMmr::from_peaks(
            hasher(),
            InMemoryStore::new(),
            id(6),
            MmrSize::ZERO,
            &[],
        )
        .expect("from peaks");
}
