//! `ErasedAsyncStore` coverage: the type-erased async store (see
//! `accumulators::store::ErasedAsyncStore`) passes the full async conformance
//! suite, and an async MMR over erased stores round-trips the editable
//! gate contract through the erased write path.
//!
//! The erased pin/stack session-local flow over the async shell lives in
//! `tests/async_stacked.rs` (`an_erased_pin_builds_a_session_local_mixed_stack`,
//! `SubView::erased_async` over `ErasedAsyncStore`); here the erased async
//! store is exercised where the async surface actually writes — editable
//! updates through `DynAsyncStore`.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "mmr",
    feature = "sqlite",
    feature = "keccak_sol",
    not(target_family = "wasm")
))]

#[path = "common/mod.rs"]
mod common;

#[path = "store/conformance.rs"]
mod conformance;

use accumulators::hashers::{Hasher, KeccakSolHasher};
use accumulators::mmr::{AsyncMmr, Editable, LeafCount, MmrError};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::sqlite::SqliteStore;
use accumulators::store::{AsyncStore as _, ErasedAsyncStore};

use common::{TempDb, elements, id, reference_root, slices};

type ErasedMmrEdit =
    AsyncMmr<KeccakSolHasher, ErasedAsyncStore, accumulators::mmr::Plain, Editable>;

fn hasher() -> KeccakSolHasher {
    KeccakSolHasher
}

// ---------------------------------------------------------------- conformance

#[tokio::test]
async fn the_erased_async_store_satisfies_the_conformance_suite() {
    let db = TempDb::new("erased-async-conformance");
    let store = ErasedAsyncStore::new(
        SqliteStore::connect(db.path())
            .await
            .expect("file sqlite opens"),
    );
    conformance::positional_reads_async(&store).await;
    conformance::empty_key_list_async(&store).await;
    conformance::put_delete_batch_async(&store).await;
    conformance::last_op_wins_async(&store).await;
    conformance::empty_batch_async(&store).await;
    conformance::duplicate_keys_alignment_async(&store).await;
    conformance::owned_ops_async(&store).await;
    conformance::binary_keys_async(&store).await;

    // The wrapper-level fault seam over the erased store: the wrapper's
    // typed error axis composes with the erased store's boxed `DynError`.
    let fault_db = TempDb::new("erased-async-fault");
    conformance::error_preservation_before_backend_async(&common::FaultyStore::new(
        ErasedAsyncStore::new(
            SqliteStore::connect(fault_db.path())
                .await
                .expect("file sqlite opens"),
        ),
    ))
    .await;
}

// ------------------------------------------------------------------- the mmr

#[tokio::test]
async fn an_async_mmr_over_erased_stores_round_trips_and_gates_edits() {
    let h = hasher();
    let db = TempDb::new("erased-async-mmr");
    let store = ErasedAsyncStore::new(
        SqliteStore::connect(db.path())
            .await
            .expect("file sqlite opens"),
    );
    let mut mmr = ErasedMmrEdit::create_editable(h, store, id(1))
        .await
        .expect("create");
    let els = elements(5);
    mmr.append_batch(&slices(&els)).await.expect("batch append");
    assert_eq!(
        mmr.root(),
        reference_root(&h, &slices(&els)),
        "the erased store carries the same node records as a concrete one"
    );

    // The erased write path gates edits exactly like the concrete one.
    let current = mmr
        .leaf_hash(LeafIndex::new(2))
        .await
        .expect("read")
        .expect("the leaf is occupied");
    match mmr
        .update(LeafIndex::new(2), b"contested", Some(Hash::ZERO))
        .await
    {
        Err(MmrError::UpdateMismatch { leaf }) => assert_eq!(leaf, LeafIndex::new(2)),
        other => panic!("expected UpdateMismatch, got {other:?}"),
    }
    mmr.update(LeafIndex::new(2), b"rewritten", Some(current))
        .await
        .expect("the correct gate must pass");
    assert_eq!(
        mmr.leaf_hash(LeafIndex::new(2)).await.expect("read"),
        Some(h.hash_leaf(b"rewritten").expect("hash"))
    );

    let proof = mmr.proof(LeafIndex::new(2)).await.expect("proof");
    assert!(mmr.verify(&proof, b"rewritten").expect("verify"));
    assert_eq!(
        mmr.leaf_count(),
        LeafCount::new(5),
        "edits never change the leaf count"
    );
}

#[tokio::test]
async fn erased_handles_over_one_store_report_same_store() {
    let db = TempDb::new("erased-async-identity");
    let store = SqliteStore::connect(db.path()).await.expect("connect");
    let erased_a = ErasedAsyncStore::new(store.clone());
    let erased_b = ErasedAsyncStore::new(store);
    assert!(
        erased_a.same_store(&erased_b),
        "erasure preserves the wrapped store's identity"
    );

    let other = ErasedAsyncStore::new(
        SqliteStore::connect(TempDb::new("erased-async-other").path())
            .await
            .expect("connect"),
    );
    assert!(!erased_a.same_store(&other));
}

// --------------------------------------------------- erased wrapping per backend

/// The async conformance suite over `ErasedAsyncStore` wrapping each new
/// async backend: erasure must preserve every backend's read/write/atomicity
/// contract through the boxed `DynAsyncStore` path. Identity checks run where
/// clones are free (in-RAM backends); file backends already prove clone
/// identity per-backend.
#[cfg(all(feature = "memory", not(target_family = "wasm")))]
#[tokio::test]
async fn the_erased_async_store_wraps_the_memory_backend() {
    use accumulators::store::memory::InMemoryStore;

    let store = ErasedAsyncStore::new(InMemoryStore::new());
    conformance::positional_reads_async(&store).await;
    conformance::empty_key_list_async(&store).await;
    conformance::put_delete_batch_async(&store).await;
    conformance::last_op_wins_async(&store).await;
    conformance::empty_batch_async(&store).await;
    conformance::duplicate_keys_alignment_async(&store).await;
    conformance::owned_ops_async(&store).await;

    // Clones of one store erase to one storage.
    let shared = InMemoryStore::shared("erased-async-memory");
    assert!(ErasedAsyncStore::new(shared.clone()).same_store(&ErasedAsyncStore::new(shared)));
}

#[cfg(all(feature = "heapless", not(target_family = "wasm")))]
#[tokio::test]
async fn the_erased_async_store_wraps_the_heapless_backend() {
    use accumulators::store::heapless::HeaplessStore;

    let store = ErasedAsyncStore::new(HeaplessStore::<64>::new());
    conformance::positional_reads_async(&store).await;
    conformance::empty_key_list_async(&store).await;
    conformance::put_delete_batch_async(&store).await;
    conformance::last_op_wins_async(&store).await;
    conformance::empty_batch_async(&store).await;
    conformance::duplicate_keys_alignment_async(&store).await;
    conformance::owned_ops_async(&store).await;
}

#[cfg(all(feature = "sled", not(target_family = "wasm")))]
#[tokio::test]
async fn the_erased_async_store_wraps_the_sled_backend() {
    use accumulators::store::sled::SledStore;

    let dir = common::TempDir::new("erased-async-sled");
    let store = ErasedAsyncStore::new(SledStore::open_path(dir.path()).expect("sled store opens"));
    conformance::positional_reads_async(&store).await;
    conformance::empty_key_list_async(&store).await;
    conformance::put_delete_batch_async(&store).await;
    conformance::last_op_wins_async(&store).await;
    conformance::empty_batch_async(&store).await;
    conformance::duplicate_keys_alignment_async(&store).await;
    conformance::owned_ops_async(&store).await;
    conformance::error_preservation_before_backend_async(&common::FaultyStore::new(
        ErasedAsyncStore::new(
            SledStore::open_path(common::TempDir::new("erased-async-sled-fault").path())
                .expect("opens"),
        ),
    ))
    .await;
}

#[cfg(all(feature = "fjall", not(target_family = "wasm")))]
#[tokio::test]
async fn the_erased_async_store_wraps_the_fjall_backend() {
    use accumulators::store::fjall::{FjallConfig, FjallStore};

    let dir = common::TempDir::new("erased-async-fjall");
    let store =
        ErasedAsyncStore::new(FjallStore::open(FjallConfig::new(dir.path())).expect("opens"));
    conformance::positional_reads_async(&store).await;
    conformance::empty_key_list_async(&store).await;
    conformance::put_delete_batch_async(&store).await;
    conformance::last_op_wins_async(&store).await;
    conformance::empty_batch_async(&store).await;
    conformance::duplicate_keys_alignment_async(&store).await;
    conformance::owned_ops_async(&store).await;
    // fjall holds an exclusive lock file per folder: the fault seam wraps
    // the same (erased) handle, no second open.
    conformance::error_preservation_before_backend_async(&common::FaultyStore::new(store)).await;
}

#[cfg(all(feature = "redb", not(target_family = "wasm")))]
#[tokio::test]
async fn the_erased_async_store_wraps_the_redb_backend() {
    use accumulators::store::redb::RedbStore;

    let db = TempDb::new("erased-async-redb");
    let store = ErasedAsyncStore::new(RedbStore::open_path(db.path()).expect("opens"));
    conformance::positional_reads_async(&store).await;
    conformance::empty_key_list_async(&store).await;
    conformance::put_delete_batch_async(&store).await;
    conformance::last_op_wins_async(&store).await;
    conformance::empty_batch_async(&store).await;
    conformance::duplicate_keys_alignment_async(&store).await;
    conformance::owned_ops_async(&store).await;

    // redb's exclusive file lock: the first handle is dropped before the
    // fault handle opens the same file.
    drop(store);
    let faulted = ErasedAsyncStore::new(RedbStore::open_path(db.path()).expect("opens"));
    conformance::error_preservation_before_backend_async(&common::FaultyStore::new(faulted)).await;
}

#[cfg(all(feature = "rocksdb", not(target_family = "wasm")))]
#[tokio::test]
async fn the_erased_async_store_wraps_the_rocksdb_backend() {
    use accumulators::store::rocksdb::{RocksdbConfig, RocksdbStore};

    let dir = common::TempDir::new("erased-async-rocksdb");
    let store =
        ErasedAsyncStore::new(RocksdbStore::open(RocksdbConfig::new(dir.path())).expect("opens"));
    conformance::positional_reads_async(&store).await;
    conformance::empty_key_list_async(&store).await;
    conformance::put_delete_batch_async(&store).await;
    conformance::last_op_wins_async(&store).await;
    conformance::empty_batch_async(&store).await;
    conformance::duplicate_keys_alignment_async(&store).await;
    conformance::owned_ops_async(&store).await;
    conformance::error_preservation_before_backend_async(&common::FaultyStore::new(
        ErasedAsyncStore::new(
            RocksdbStore::open(RocksdbConfig::new(
                common::TempDir::new("erased-async-rocksdb-fault").path(),
            ))
            .expect("opens"),
        ),
    ))
    .await;
}
