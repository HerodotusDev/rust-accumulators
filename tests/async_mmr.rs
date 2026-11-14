//! Async-MMR parity tests over the SQLite store: create/open round trips,
//! appends and batch appends, roots against the brute-force reference, proofs
//! and multiproofs, editable/nullifying modes, peaks-only seeds, and the
//! `open` metadata validation — mirroring the sync [`Mmr`] contract.

#![cfg(all(
    feature = "mmr",
    feature = "sqlite",
    feature = "keccak",
    feature = "blake",
    not(target_family = "wasm")
))]

use accumulators::hashers::{Blake2sHasher, Hasher, Keccak256Hasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::LeafCount;
use accumulators::mmr::{
    AsyncMmr, Corrupted, Editable, MmrError, NullifierRecord, Nullifying, Plain,
};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::sqlite::SqliteStore;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

type TestMmr = AsyncMmr<Keccak256Hasher, SqliteStore>;
type BlakeMmr = AsyncMmr<Blake2sHasher, SqliteStore>;
type TestMmrEdit = AsyncMmr<Keccak256Hasher, SqliteStore, Plain, Editable>;
type TestMmrNull = AsyncMmr<Keccak256Hasher, SqliteStore, Plain, Nullifying>;

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

fn db_path(tag: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "accumulators-async-{tag}-{}-{nanos}.sqlite3",
        std::process::id()
    ))
}

fn remove_db(path: &Path) {
    let name = path.to_string_lossy();
    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{name}{suffix}"));
    }
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

// ------------------------------------------------------- lifecycle + roots

mod lifecycle {
    use super::*;

    #[tokio::test]
    async fn roots_track_the_reference_at_every_size() {
        let h = hasher();
        let path = db_path("roots");
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");

        for i in 1..=12_u64 {
            mmr.append(&element(i - 1))
                .await
                .expect("append must succeed");
            assert_eq!(
                mmr.root(),
                reference_root(h, &slices(&elements(i))),
                "root must equal the brute-force reference at {i} leaves"
            );
        }
        drop(mmr);
        remove_db(&path);
    }

    #[tokio::test]
    async fn create_open_round_trip_and_growth_match_the_reference() {
        let h = hasher();
        let path = db_path("round-trip");
        let store = SqliteStore::connect(&path).await.expect("connect");

        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");
        let els = elements(8);
        mmr.append_batch(&slices(&els)).await.expect("batch append");
        assert_eq!(mmr.root(), reference_root(h, &slices(&els)));
        drop(mmr);

        // Re-open from the same database file.
        let reopened_store = SqliteStore::connect(&path).await.expect("reconnect");
        let mut reopened = TestMmr::open(h, reopened_store, id(1)).await.expect("open");
        assert_eq!(reopened.leaf_count(), LeafCount::new(8));
        assert_eq!(
            reopened.root(),
            reference_root(h, &slices(&els)),
            "the persisted root must match the reference after reopen"
        );
        assert_eq!(
            reopened.peaks(),
            reference_peaks(h, &slices(&els)),
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
            reference_root(h, &slices(&elements(10))),
            "growth after reopen must track the reference"
        );
        drop(reopened);
        remove_db(&path);
    }

    #[tokio::test]
    async fn append_batch_lands_on_the_reference_root() {
        let h = hasher();
        let path = db_path("batch");
        let store = SqliteStore::connect(&path).await.expect("connect");
        let mut mmr = TestMmr::create(h, store, id(1)).await.expect("create");

        let els = elements(12);
        let outcome = mmr.append_batch(&slices(&els)).await.expect("batch append");
        assert_eq!(outcome.first_leaf, LeafIndex::FIRST);
        assert_eq!(outcome.appended, LeafCount::new(12));
        assert_eq!(outcome.root, mmr.root());
        assert_eq!(outcome.root, reference_root(h, &slices(&els)));

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
        remove_db(&path);
    }

    #[tokio::test]
    async fn open_validates_the_persisted_hasher() {
        let h = hasher();
        let path = db_path("hasher-mismatch");
        let store = SqliteStore::connect(&path).await.expect("connect");
        TestMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");

        match BlakeMmr::open(Blake2sHasher { truncate: true }, store, id(1)).await {
            Err(MmrError::Corrupted(Corrupted::HasherMismatch { .. })) => {}
            Err(other) => panic!("expected HasherMismatch, got {other:?}"),
            Ok(_) => panic!("expected HasherMismatch, but the MMR opened"),
        }
        remove_db(&path);
    }

    #[tokio::test]
    async fn open_validates_the_persisted_mode() {
        let h = hasher();
        let path = db_path("mode-mismatch");
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
        remove_db(&path);
    }
}

// ----------------------------------------------------------------- proofs

mod proofs {
    use super::*;

    #[tokio::test]
    async fn every_leaf_proof_verifies_for_its_own_element_only() {
        let h = hasher();
        let path = db_path("proofs");
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
        remove_db(&path);
    }

    #[tokio::test]
    async fn multiproofs_verify_over_the_whole_tree_and_subsets() {
        let h = hasher();
        let path = db_path("multiproofs");
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
        remove_db(&path);
    }

    #[tokio::test]
    async fn a_proof_from_an_old_root_stops_verifying_after_growth() {
        let h = hasher();
        let path = db_path("old-proof");
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
        remove_db(&path);
    }
}

// ------------------------------------------------------------------- modes

mod modes {
    use super::*;

    #[tokio::test]
    async fn editable_update_delete_and_gate_reject_stale_values() {
        let h = hasher();
        let path = db_path("editable");
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
        remove_db(&path);
    }

    #[tokio::test]
    async fn nullifying_refuses_nullified_proofs_and_replaces_append() {
        let h = hasher();
        let path = db_path("nullifying");
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
        remove_db(&path);
    }

    #[tokio::test]
    async fn from_peaks_proves_only_above_the_seed_floor() {
        let h = hasher();
        let path = db_path("from-peaks");
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

        let mut peaks_mmr = TestMmr::from_peaks(h, store, id(2), seed_size, &seed_peaks)
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
            reference_root(h, &slices(&elements(6))),
            "appends on the seed must track the reference"
        );
        drop(peaks_mmr);
        remove_db(&path);
    }
}
