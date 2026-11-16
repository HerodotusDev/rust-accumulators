//! Async-MMR parity tests over the SQLite store: create/open round trips,
//! appends and batch appends, roots against the brute-force reference, proofs
//! and multiproofs, editable/nullifying modes, peaks-only seeds, and the
//! `open` metadata validation — mirroring the sync [`Mmr`] contract.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "mmr",
    feature = "sqlite",
    feature = "keccak_sol",
    feature = "blake2s_stark",
    not(target_family = "wasm")
))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::{Blake2sStarkHasher, Hasher, KeccakSolHasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::LeafCount;
use accumulators::mmr::{
    AsyncMmr, Corrupted, Editable, MmrError, MmrSize, NullifierRecord, Nullifying, Plain, WithPeaks,
};
use accumulators::mmr::{
    AsyncPlainAppendMmr, AsyncPlainEditableMmr, AsyncPlainNullifyingMmr, AsyncWithPeaksAppendMmr,
    AsyncWithPeaksEditableMmr, AsyncWithPeaksNullifyingMmr,
};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::keys::{self, Table};
use accumulators::store::sqlite::SqliteStore;
use accumulators::store::{AsyncStore as _, Batch};

use common::{
    TempDb, element, elements, id, reference_peaks, reference_root, root_of_hashes, slices,
};

type TestMmr = AsyncMmr<KeccakSolHasher, SqliteStore>;
type BlakeMmr = AsyncMmr<Blake2sStarkHasher, SqliteStore>;
type TestMmrEdit = AsyncMmr<KeccakSolHasher, SqliteStore, Plain, Editable>;
type TestMmrNull = AsyncMmr<KeccakSolHasher, SqliteStore, Plain, Nullifying>;

// ---------------------------------------------------------------- helpers

fn hasher() -> KeccakSolHasher {
    KeccakSolHasher
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
    async fn roots_track_the_reference_at_every_size() {
        let h = hasher();
        let db = TempDb::new("roots");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");

        for i in 1..=12_u64 {
            mmr.append(&element(i - 1))
                .await
                .expect("append must succeed");
            assert_eq!(
                mmr.root(),
                reference_root(&h, &slices(&elements(i))),
                "root must equal the brute-force reference at {i} leaves"
            );
        }
        drop(mmr);
    }

    #[tokio::test]
    async fn create_open_round_trip_and_growth_match_the_reference() {
        let h = hasher();
        let db = TempDb::new("round-trip");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");

        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");
        let els = elements(8);
        mmr.append_batch(&slices(&els)).await.expect("batch append");
        assert_eq!(mmr.root(), reference_root(&h, &slices(&els)));
        drop(mmr);

        // Re-open from the same database file.
        let reopened_store = SqliteStore::connect(&path).await.expect("reconnect");
        let mut reopened = TestMmr::open(h, reopened_store, id(1)).await.expect("open");
        assert_eq!(reopened.leaf_count(), LeafCount::new(8));
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&els)),
            "the persisted root must match the reference after reopen"
        );
        assert_eq!(
            reopened.peaks(),
            reference_peaks(&h, &slices(&els)),
            "persisted peaks must match the brute-force reference"
        );

        for i in 8..10 {
            reopened
                .append(&element(i))
                .await
                .expect("append must succeed");
        }
        assert_eq!(
            reopened.root(),
            reference_root(&h, &slices(&elements(10))),
            "growth after reopen must track the reference"
        );
        drop(reopened);
    }

    #[tokio::test]
    async fn append_batch_lands_on_the_reference_root() {
        let h = hasher();
        let db = TempDb::new("batch");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");

        let els = elements(12);
        let outcome = mmr.append_batch(&slices(&els)).await.expect("batch append");
        assert_eq!(outcome.first_leaf, LeafIndex::FIRST);
        assert_eq!(outcome.appended, LeafCount::new(12));
        assert_eq!(outcome.root, mmr.root());
        assert_eq!(outcome.root, reference_root(&h, &slices(&els)));

        let outcome = mmr
            .append_batch(Vec::<&[u8]>::new())
            .await
            .expect("empty batch");
        assert_eq!(
            outcome.appended,
            LeafCount::ZERO,
            "an empty batch appends nothing"
        );
        assert_eq!(outcome.first_leaf, LeafIndex::new(12));
        drop(mmr);
    }

    #[tokio::test]
    async fn open_validates_the_persisted_hasher() {
        let h = hasher();
        let db = TempDb::new("hasher-mismatch");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");

        match BlakeMmr::open(Blake2sStarkHasher { truncate: true }, store, id(1)).await {
            Err(MmrError::Corrupted(Corrupted::HasherMismatch { .. })) => {}
            Err(other) => panic!("expected HasherMismatch, got {other:?}"),
            Ok(_) => panic!("expected HasherMismatch, but the MMR opened"),
        }
    }

    #[tokio::test]
    async fn open_validates_the_persisted_mode() {
        let h = hasher();
        let db = TempDb::new("mode-mismatch");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        TestMmrEdit::create_editable(h, store.clone(), id(1))
            .await
            .expect("create editable");

        match TestMmr::open(h, store, id(1)).await {
            Err(MmrError::Corrupted(Corrupted::ModeMismatch { stored, declared })) => {
                assert_eq!(stored, "editable");
                assert_eq!(declared, "append_only");
            }
            Err(other) => panic!("expected ModeMismatch, got {other:?}"),
            Ok(_) => panic!("expected ModeMismatch, but the MMR opened"),
        }
    }
}

// ----------------------------------------------------------------- proofs

mod proofs {
    use super::*;

    #[tokio::test]
    async fn every_leaf_proof_verifies_for_its_own_element_only() {
        let h = hasher();
        let db = TempDb::new("proofs");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");
        let els = elements(16);
        mmr.append_batch(&slices(&els)).await.expect("batch append");

        for (index, el) in els.iter().enumerate() {
            let proof = mmr
                .proof(LeafIndex::new(index as u64))
                .await
                .expect("proof");
            assert!(
                mmr.verify(&proof, el).expect("verify"),
                "leaf {index} must verify"
            );
            assert!(
                !mmr.verify(&proof, b"not-the-element").expect("verify"),
                "a foreign element must not verify for leaf {index}"
            );
        }
        drop(mmr);
    }

    #[tokio::test]
    async fn multiproofs_verify_over_the_whole_tree_and_subsets() {
        let h = hasher();
        let db = TempDb::new("multiproofs");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");
        let els = elements(16);
        mmr.append_batch(&slices(&els)).await.expect("batch append");

        let all: Vec<LeafIndex> = (0..16).map(LeafIndex::new).collect();
        let multi = mmr.multiproof(all).await.expect("multiproof");
        assert!(mmr.verify_multi(&multi, &slices(&els)).expect("verify"));

        let subset = [LeafIndex::new(1), LeafIndex::new(4), LeafIndex::new(15)];
        let multi = mmr.multiproof(subset).await.expect("multiproof");
        let aligned = [els[1].as_slice(), els[4].as_slice(), els[15].as_slice()];
        assert!(mmr.verify_multi(&multi, aligned).expect("verify"));
        let misaligned = [els[15].as_slice(), els[4].as_slice(), els[1].as_slice()];
        assert!(
            !mmr.verify_multi(&multi, misaligned).expect("verify"),
            "misaligned elements must fail the commitment"
        );
        drop(mmr);
    }

    #[tokio::test]
    async fn a_proof_from_an_old_root_stops_verifying_after_growth() {
        let h = hasher();
        let db = TempDb::new("old-proof");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");
        let els = elements(10);
        mmr.append_batch(&slices(&els)).await.expect("batch append");
        let old_proof = mmr.proof(LeafIndex::new(3)).await.expect("proof");

        for i in 10..25 {
            mmr.append(&element(i)).await.expect("append must succeed");
        }
        assert!(
            !mmr.verify(&old_proof, &els[3]).expect("verify"),
            "a proof from an older root must not verify against the grown MMR"
        );
        drop(mmr);
    }
}

// ------------------------------------------------------------------- modes

mod modes {
    use super::*;

    #[tokio::test]
    async fn editable_update_delete_and_gate_reject_stale_values() {
        let h = hasher();
        let db = TempDb::new("editable");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmrEdit::create_editable(h, store, id(1))
            .await
            .expect("create");
        let els = elements(5);
        mmr.append_batch(&slices(&els)).await.expect("batch append");

        match mmr
            .update(LeafIndex::new(2), b"contested", Some(Hash::ZERO))
            .await
        {
            Err(MmrError::UpdateMismatch { leaf }) => assert_eq!(leaf, LeafIndex::new(2)),
            other => panic!("expected UpdateMismatch, got {other:?}"),
        }
        let current = mmr
            .leaf_hash(LeafIndex::new(2))
            .await
            .expect("read")
            .expect("the leaf is occupied");
        mmr.update(LeafIndex::new(2), b"rewritten", Some(current))
            .await
            .expect("the correct gate must pass");
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(2)).await.expect("read"),
            Some(h.hash_leaf(b"rewritten").expect("hash"))
        );

        let previous = mmr
            .leaf_hash(LeafIndex::new(3))
            .await
            .expect("read")
            .expect("the leaf is occupied");
        let outcome = mmr.delete(LeafIndex::new(3), None).await.expect("delete");
        assert_eq!(outcome.previous, Some(previous));
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(3)).await.expect("read"),
            Some(h.genesis()),
            "delete writes the genesis value"
        );
        drop(mmr);
    }

    #[tokio::test]
    async fn nullifying_refuses_nullified_proofs_and_replaces_append() {
        let h = hasher();
        let db = TempDb::new("nullifying");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmrNull::create_nullifying(h, store, id(1))
            .await
            .expect("create");
        let els = elements(6);
        mmr.append_batch(&slices(&els)).await.expect("batch append");

        let outcome = mmr
            .nullify_shallow(LeafIndex::new(2))
            .await
            .expect("nullify");
        assert_eq!(outcome.record, NullifierRecord::Shallow { at: mmr.size() });
        match mmr.proof(LeafIndex::new(2)).await {
            Err(MmrError::LeafNullified { leaf }) => assert_eq!(leaf, LeafIndex::new(2)),
            other => panic!("expected LeafNullified, got {other:?}"),
        }

        let replace = mmr
            .replace_shallow(LeafIndex::new(3), b"replacement")
            .await
            .expect("replace");
        assert_eq!(replace.nullified, LeafIndex::new(3));
        assert_eq!(replace.appended.leaf, LeafIndex::new(6));
        match mmr.proof(LeafIndex::new(3)).await {
            Err(MmrError::LeafNullified { .. }) => {}
            other => panic!("the replaced leaf must be nullified, got {other:?}"),
        }
        let proof = mmr
            .proof(LeafIndex::new(6))
            .await
            .expect("the new leaf proves");
        assert!(mmr.verify(&proof, b"replacement").expect("verify"));

        let deep = mmr
            .nullify_deep(LeafIndex::new(1))
            .await
            .expect("deep nullify");
        assert_eq!(deep.record, NullifierRecord::Deep);
        match mmr.proof(LeafIndex::new(1)).await {
            Err(MmrError::LeafNullified { .. }) => {}
            other => panic!("expected LeafNullified, got {other:?}"),
        }
        drop(mmr);
    }

    #[tokio::test]
    async fn from_peaks_proves_only_above_the_seed_floor() {
        let h = hasher();
        let db = TempDb::new("from-peaks");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut full = TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");
        let els = elements(5);
        full.append_batch(&slices(&els))
            .await
            .expect("batch append");
        let seed_size = full.size();
        let seed_peaks = full.peaks().to_vec();
        drop(full);

        let mut peaks_mmr = AsyncMmr::<KeccakSolHasher, SqliteStore, WithPeaks>::from_peaks(
            h,
            store,
            id(2),
            seed_size,
            &seed_peaks,
        )
        .await
        .expect("from_peaks must succeed");
        match peaks_mmr.proof(LeafIndex::new(2)).await {
            Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from,
            }) => {
                assert_eq!(leaf, LeafIndex::new(2));
                assert_eq!(provable_from, LeafIndex::new(5));
            }
            other => panic!("expected UnprovableLeaf below the floor, got {other:?}"),
        }

        peaks_mmr
            .append(&element(5))
            .await
            .expect("append on the seed");
        let proof = peaks_mmr
            .proof(LeafIndex::new(5))
            .await
            .expect("above the floor");
        assert!(peaks_mmr.verify(&proof, &element(5)).expect("verify"));
        assert_eq!(
            peaks_mmr.root(),
            reference_root(&h, &slices(&elements(6))),
            "appends on the seed must track the reference"
        );
        drop(peaks_mmr);
    }
}

// ----------------------------------------------------- provenance reopen

mod provenance {
    use super::*;

    /// Provenance is persisted (`Table::Provenance`): a peaks-only async MMR
    /// re-opens as peaks-only with its seed floor intact, and a Plain open
    /// of a peaks-only store is rejected (the floor would be lost).
    #[tokio::test]
    async fn from_peaks_provenance_survives_reopen() {
        let h = hasher();
        let db = TempDb::new("provenance-reopen");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut full = TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");
        let els = elements(5);
        full.append_batch(&slices(&els))
            .await
            .expect("batch append");
        let seed_size = full.size();
        let seed_peaks = full.peaks().to_vec();
        drop(full);

        drop(
            AsyncMmr::<KeccakSolHasher, SqliteStore, WithPeaks>::from_peaks(
                h,
                store.clone(),
                id(2),
                seed_size,
                &seed_peaks,
            )
            .await
            .expect("from_peaks must succeed"),
        );

        // The WithPeaks open reconstructs the floor.
        let reopened =
            AsyncMmr::<KeccakSolHasher, SqliteStore, WithPeaks>::open(h, store.clone(), id(2))
                .await
                .expect("a peaks-only store re-opens as WithPeaks");
        match reopened.proof(LeafIndex::new(2)).await {
            Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from,
            }) => {
                assert_eq!(leaf, LeafIndex::new(2));
                assert_eq!(provable_from, LeafIndex::new(5));
            }
            other => panic!("expected UnprovableLeaf below the floor, got {other:?}"),
        }
        drop(reopened);

        // A Plain open of a peaks-only store would silently lose the floor.
        match TestMmr::open(h, store, id(2)).await {
            Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: accumulators::store::keys::Table::Provenance,
            })) => {}
            Err(other) => panic!("expected MalformedRecord(Provenance), got {other:?}"),
            Ok(_) => panic!("expected MalformedRecord(Provenance), but the MMR opened"),
        }
    }
}

// ---------------------------------------------------------- editable gates

/// Async twins of the sync suites' editable-gate cases (the sync draft gate
/// suite's semantics, expressed through the async shell's direct
/// `update`/`delete` ops; the full async draft overlay lives in
/// `tests/async_draft.rs`).
mod editable_gates {
    use super::*;

    #[tokio::test]
    async fn a_stale_gate_rejects_the_update_and_changes_nothing() {
        let h = hasher();
        let db = TempDb::new("gate-stale");
        let store = SqliteStore::connect(db.path()).await.expect("connect");
        let mut mmr = TestMmrEdit::create_editable(h, store, id(1))
            .await
            .expect("create");
        let els = elements(4);
        mmr.append_batch(&slices(&els)).await.expect("batch append");
        let root_before = mmr.root();

        match mmr
            .update(LeafIndex::new(1), b"contested", Some(Hash::ZERO))
            .await
        {
            Err(MmrError::UpdateMismatch { leaf }) => assert_eq!(leaf, LeafIndex::new(1)),
            other => panic!("expected UpdateMismatch, got {other:?}"),
        }
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(1)).await.expect("read"),
            Some(h.hash_leaf(&els[1]).expect("hash")),
            "the stale gate must not rewrite the leaf"
        );
        assert_eq!(mmr.leaf_count(), LeafCount::new(4));
        assert_eq!(
            mmr.root(),
            root_before,
            "a rejected update changes no state"
        );
    }

    #[tokio::test]
    async fn the_correct_gate_passes_and_the_root_tracks_the_reference() {
        let h = hasher();
        let db = TempDb::new("gate-pass");
        let store = SqliteStore::connect(db.path()).await.expect("connect");
        let mut mmr = TestMmrEdit::create_editable(h, store, id(1))
            .await
            .expect("create");
        let els = elements(4);
        mmr.append_batch(&slices(&els)).await.expect("batch append");
        let current = mmr
            .leaf_hash(LeafIndex::new(2))
            .await
            .expect("read")
            .expect("the leaf is occupied");

        let outcome = mmr
            .update(LeafIndex::new(2), b"rewritten", Some(current))
            .await
            .expect("the correct gate must pass");
        assert_eq!(outcome.previous, Some(current));
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(2)).await.expect("read"),
            Some(h.hash_leaf(b"rewritten").expect("hash"))
        );

        // The committed root must equal the independent reference over the
        // post-edit leaf hashes.
        let mut leaf_hashes: Vec<Hash> = els
            .iter()
            .map(|el| h.hash_leaf(el).expect("hash"))
            .collect();
        leaf_hashes[2] = h.hash_leaf(b"rewritten").expect("hash");
        assert_eq!(mmr.root(), root_of_hashes(&h, &leaf_hashes));

        // The rewritten leaf proves and verifies; the old proof is dead.
        let proof = mmr.proof(LeafIndex::new(2)).await.expect("proof");
        assert!(mmr.verify(&proof, b"rewritten").expect("verify"));
        assert!(
            !mmr.verify(&proof, &els[2]).expect("verify"),
            "the pre-edit element must not verify under the rewritten leaf"
        );
    }

    #[tokio::test]
    async fn a_gated_delete_writes_genesis_and_a_genesis_gate_resurrects() {
        let h = hasher();
        let db = TempDb::new("gate-delete");
        let store = SqliteStore::connect(db.path()).await.expect("connect");
        let mut mmr = TestMmrEdit::create_editable(h, store, id(1))
            .await
            .expect("create");
        let els = elements(3);
        mmr.append_batch(&slices(&els)).await.expect("batch append");

        // Gated delete: the gate must match the live value.
        match mmr.delete(LeafIndex::new(1), Some(Hash::ZERO)).await {
            Err(MmrError::UpdateMismatch { leaf }) => assert_eq!(leaf, LeafIndex::new(1)),
            other => panic!("expected UpdateMismatch, got {other:?}"),
        }
        let current = mmr
            .leaf_hash(LeafIndex::new(1))
            .await
            .expect("read")
            .expect("the leaf is occupied");
        let outcome = mmr
            .delete(LeafIndex::new(1), Some(current))
            .await
            .expect("the matching gate passes");
        assert_eq!(outcome.previous, Some(current));
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(1)).await.expect("read"),
            Some(h.genesis()),
            "delete writes the genesis value"
        );

        // Resurrection: the genesis value is itself a valid gate, so a
        // later update re-occupies the cleared leaf.
        let resurrected = mmr
            .update(LeafIndex::new(1), b"resurrected", Some(h.genesis()))
            .await
            .expect("the genesis gate passes");
        assert_eq!(
            resurrected.previous,
            Some(h.genesis()),
            "the delete's genesis value is the edit's previous"
        );
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(1)).await.expect("read"),
            Some(h.hash_leaf(b"resurrected").expect("hash"))
        );
        let proof = mmr.proof(LeafIndex::new(1)).await.expect("proof");
        assert!(mmr.verify(&proof, b"resurrected").expect("verify"));
    }

    #[tokio::test]
    async fn an_update_beyond_the_leaf_count_is_unprovable() {
        let h = hasher();
        let db = TempDb::new("gate-beyond");
        let store = SqliteStore::connect(db.path()).await.expect("connect");
        let mut mmr = TestMmrEdit::create_editable(h, store, id(1))
            .await
            .expect("create");
        mmr.append_batch(&slices(&elements(2)))
            .await
            .expect("batch append");

        match mmr.update(LeafIndex::new(2), b"beyond", None).await {
            Err(MmrError::UnprovableLeaf {
                leaf,
                provable_from,
            }) => {
                assert_eq!(leaf, LeafIndex::new(2));
                assert_eq!(provable_from, LeafIndex::FIRST);
            }
            other => panic!("expected UnprovableLeaf, got {other:?}"),
        }
    }
}

// ------------------------------------------------------------ send bounds

mod send_bounds {
    use super::*;

    /// Compile-time Send assertions for the documented bounds (see the
    /// `async_mmr` module docs): `S: AsyncStore + Send + Sync + 'static`,
    /// `H: Hasher + Send + Sync` with `H::Output: Send + Sync`,
    /// `Id: TreeId + Send + Sync`. Every `assert_send` call is the
    /// assertion; awaiting keeps the futures real.
    #[tokio::test]
    async fn the_public_futures_are_send_under_the_documented_bounds() {
        fn assert_send<T: Send>(future: T) -> T {
            future
        }

        let h = hasher();
        let db = TempDb::new("send-bounds");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");
        mmr.append(&element(0)).await.expect("append");

        // The `&self` methods (proof reads, verification inputs).
        let proof = assert_send(mmr.proof(LeafIndex::new(0)))
            .await
            .expect("proof");
        assert!(mmr.verify(&proof, &element(0)).expect("verify"));
        assert_send(mmr.multiproof([LeafIndex::new(0)]))
            .await
            .expect("multiproof");
        assert_send(mmr.leaf_hash(LeafIndex::new(0)))
            .await
            .expect("leaf hash");

        // The `&mut self` methods (writes).
        let outcome = assert_send(mmr.append(&element(1))).await.expect("append");
        assert_eq!(outcome.leaf, LeafIndex::new(1));

        // An associated async constructor's future.
        drop(mmr);
        let store = SqliteStore::connect(&path).await.expect("reconnect");
        let reopened = assert_send(TestMmr::open(h, store, id(1)))
            .await
            .expect("open");
        assert_eq!(reopened.leaf_count(), LeafCount::new(2));
    }
}

// ------------------------------------------------------------- corruption

mod corruption {
    use super::*;

    /// The async loader's corruption contract: a present-but-unparsable node
    /// value is diagnosed as `MalformedRecord`, not silently read as an
    /// absent record — mirroring the sync suite's twin.
    #[tokio::test]
    async fn a_tampered_node_value_is_malformed_not_missing() {
        let h = hasher();
        let db = TempDb::new("corrupt-node");
        let store = SqliteStore::connect(db.path()).await.expect("connect");
        let mut mmr = TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");
        mmr.append(&element(0)).await.expect("append");
        mmr.append(&element(1)).await.expect("append");

        // Leaf 0 lives at node index 1; poison it.
        let mut batch = Batch::new();
        batch.put_owned(keys::encode(&id(1), Table::Nodes, 1), vec![0xff; 3]);
        store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");

        match mmr.proof(LeafIndex::FIRST).await {
            Err(MmrError::Corrupted(Corrupted::MalformedRecord {
                table: Table::Nodes,
            })) => {}
            other => panic!("expected MalformedRecord(Nodes), got {other:?}"),
        }
    }

    /// A tampered cached root is rejected at open — the async loader checks
    /// the persisted root against the recomputed peaks exactly like the sync
    /// one.
    #[tokio::test]
    async fn a_tampered_root_is_rejected_on_open() {
        let h = hasher();
        let db = TempDb::new("corrupt-root");
        let store = SqliteStore::connect(db.path()).await.expect("connect");
        let mut mmr = TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");
        mmr.append(b"payload").await.expect("append");

        poke(&store, id(1), Table::Root, &[0x5a; 32]).await;
        match TestMmr::open(h, store, id(1)).await {
            Err(MmrError::Corrupted(Corrupted::RootMismatch)) => {}
            other => panic!("expected RootMismatch, got {other:?}"),
        }
    }

    /// Inconsistent persisted counters (a leaf count contradicting the node
    /// count) are rejected on open with the counter disagreement finding.
    #[tokio::test]
    async fn inconsistent_counters_are_rejected_on_open() {
        let h = hasher();
        let db = TempDb::new("corrupt-counters");
        let store = SqliteStore::connect(db.path()).await.expect("connect");
        let mut mmr = TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");
        for i in 0..10_u64 {
            mmr.append(&element(i)).await.expect("append");
        }

        // Ten leaves imply node_count 18; a leaf_count of 8 contradicts it.
        poke(&store, id(1), Table::LeafCount, &8_u64.to_be_bytes()).await;
        match TestMmr::open(h, store, id(1)).await {
            Err(MmrError::Corrupted(Corrupted::PeaksMismatch { expected, found })) => {
                assert_eq!(expected, 2, "ten leaves carry two peaks");
                assert_eq!(found, 1, "eight leaves would carry one");
            }
            other => panic!("expected PeaksMismatch, got {other:?}"),
        }
    }
}

// ------------------------------------------------------------ type aliases

#[tokio::test]
async fn kind_mode_aliases_resolve_to_the_plain_generics() {
    // The alias's `Id` default must resolve identically to the struct's own:
    // `AsyncPlainAppendMmr<H, S>` is exactly `AsyncMmr<H, S>`, and each alias
    // carries the named constructors of its kind × mode combination.
    let h = hasher();
    let db = TempDb::new("aliases");
    let store = SqliteStore::connect(db.path()).await.expect("connect");

    let append: AsyncPlainAppendMmr<KeccakSolHasher, SqliteStore> =
        TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");
    assert_eq!(append.leaf_count(), LeafCount::ZERO);

    let _: AsyncPlainEditableMmr<KeccakSolHasher, SqliteStore> =
        AsyncPlainEditableMmr::create_editable(h, store.clone(), id(2))
            .await
            .expect("create");
    let _: AsyncPlainNullifyingMmr<KeccakSolHasher, SqliteStore> =
        AsyncPlainNullifyingMmr::create_nullifying(h, store.clone(), id(3))
            .await
            .expect("create");
    let _: AsyncWithPeaksAppendMmr<KeccakSolHasher, SqliteStore> =
        AsyncWithPeaksAppendMmr::from_peaks(h, store.clone(), id(4), MmrSize::ZERO, &[])
            .await
            .expect("from peaks");
    let _: AsyncWithPeaksEditableMmr<KeccakSolHasher, SqliteStore> =
        AsyncWithPeaksEditableMmr::from_peaks(h, store.clone(), id(5), MmrSize::ZERO, &[])
            .await
            .expect("from peaks");
    let _: AsyncWithPeaksNullifyingMmr<KeccakSolHasher, SqliteStore> =
        AsyncWithPeaksNullifyingMmr::from_peaks(h, store, id(6), MmrSize::ZERO, &[])
            .await
            .expect("from peaks");
}
