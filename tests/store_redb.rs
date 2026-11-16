//! Behavior tests for the redb store backend: the backend-agnostic
//! conformance suite plus redb-specific semantics — re-opening from a
//! locator, clone identity, durability configuration, and reader/writer
//! concurrency.

#![cfg(all(feature = "redb", not(target_family = "wasm")))]
#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#[path = "common/mod.rs"]
mod common;

#[path = "store/conformance.rs"]
mod conformance;

use std::sync::Arc;
use std::thread;

use accumulators::store::redb::{RedbConfig, RedbError, RedbStore};
use accumulators::store::{Batch, Retrievable, Store};

use common::TempDb;

mod conformance_runner {
    use super::*;

    #[test]
    fn the_redb_store_satisfies_the_conformance_suite() {
        let db = TempDb::new("redb-conformance");
        let store = RedbStore::open_path(db.path()).expect("file redb opens");
        conformance::positional_reads(&store);
        conformance::empty_key_list(&store);
        conformance::put_delete_batch(&store);
        conformance::last_op_wins(&store);
        conformance::empty_batch(&store);
        conformance::duplicate_keys_alignment(&store);
        conformance::owned_ops(&store);
        drop(store);

        // The fault seam is external to the store; a fresh handle on the
        // same file is enough (the first handle is dropped: redb holds an
        // exclusive file lock, so the two cannot coexist).
        let faulted = RedbStore::open_path(db.path()).expect("file redb opens");
        conformance::error_preservation_before_backend(&common::FaultyStore::new(faulted));
    }

    #[tokio::test]
    async fn the_redb_store_satisfies_the_async_conformance_suite() {
        let db = TempDb::new("redb-conformance-async");
        let store = RedbStore::open_path(db.path()).expect("file redb opens");
        conformance::positional_reads_async(&store).await;
        conformance::empty_key_list_async(&store).await;
        conformance::put_delete_batch_async(&store).await;
        conformance::last_op_wins_async(&store).await;
        conformance::empty_batch_async(&store).await;
        conformance::duplicate_keys_alignment_async(&store).await;
        conformance::owned_ops_async(&store).await;
        drop(store);

        let faulted = RedbStore::open_path(db.path()).expect("file redb opens");
        conformance::error_preservation_before_backend_async(&common::FaultyStore::new(faulted))
            .await;
    }
}

/// The async surface (scoped module, see `store_sled.rs`): the async locator
/// round trip and the async twin of the in-backend mid-batch fault seam.
mod async_surface {
    use accumulators::store::redb::{RedbError, RedbStore};
    use accumulators::store::{AsyncRetrievable, AsyncStore, Batch};

    use crate::common::TempDb;

    /// The async locator round trip: [`AsyncRetrievable::open`] offloads the
    /// file open to the blocking pool and reattaches to the persisted data.
    #[tokio::test]
    async fn async_reopen_from_locator_round_trips_the_data() {
        let db = TempDb::new("redb-async-reopen");
        let locator = {
            let store = RedbStore::open_path(db.path()).expect("file redb opens");
            let mut batch = Batch::new();
            batch.put(b"key", b"value");
            AsyncStore::write(&store, batch).await.expect("redb write");
            <RedbStore as AsyncRetrievable>::canonical_locator(&store)
        };

        let reopened = <RedbStore as AsyncRetrievable>::open(&locator)
            .await
            .expect("open re-opens the path");
        let results = AsyncStore::read(&reopened, &[b"key"])
            .await
            .expect("redb read");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "open reattaches to the persisted data"
        );
    }

    /// The async twin of
    /// [`a_backend_internal_failure_mid_batch_aborts_the_write_transaction`]: the
    /// same seam through the [`AsyncStore`] path, which runs the write inside
    /// redb's transaction on the blocking pool — the transaction boundary (and
    /// its rollback) is the engine's, unchanged by the offload.
    #[tokio::test]
    async fn an_async_backend_internal_failure_mid_batch_aborts_the_write_transaction() {
        const OVERSIZED: usize = 3 * 1024 * 1024 * 1024 + 1;

        let db = TempDb::new("redb-mid-batch-async");
        let store = RedbStore::open_path(db.path()).expect("file redb opens");

        let (setup, prior, poisoned) = (b"redb-mid/setup", b"redb-mid/prior", b"redb-mid/poisoned");
        let mut setup_batch = Batch::new();
        setup_batch.put(setup, b"old");
        AsyncStore::write(&store, setup_batch)
            .await
            .expect("the setup write succeeds");

        let mut batch = Batch::new();
        batch.put(prior, b"must-not-land");
        batch.delete(setup);
        batch.put_owned(poisoned, vec![0u8; OVERSIZED]);
        match AsyncStore::write(&store, batch).await {
            Err(RedbError::Storage(redb::StorageError::ValueTooLarge(len))) => {
                assert_eq!(len, OVERSIZED, "the backend names the rejected op's size");
            }
            Err(other) => panic!("expected ValueTooLarge, got {other:?}"),
            Ok(()) => panic!("the oversized write must fail inside the transaction"),
        }

        let results = AsyncStore::read(&store, &[prior, setup, poisoned])
            .await
            .expect("read succeeds");
        assert_eq!(
            results,
            [None, Some(b"old".to_vec()), None],
            "the failed batch must not partially apply — all-or-nothing"
        );

        let mut batch = Batch::new();
        batch.put(prior, b"lands-now");
        batch.delete(setup);
        batch.put(poisoned, b"lands-now");
        AsyncStore::write(&store, batch)
            .await
            .expect("the retry succeeds");
        let results = AsyncStore::read(&store, &[prior, setup, poisoned])
            .await
            .expect("read succeeds");
        assert_eq!(
            results,
            [
                Some(b"lands-now".to_vec()),
                None,
                Some(b"lands-now".to_vec())
            ],
            "after the fault clears the batch applies whole"
        );
    }
}

/// The **in-backend** fault seam for redb: redb's own value-size limit
/// (`MAX_VALUE_LENGTH`, 3 GiB) rejects one op of the batch *mid-transaction*
/// — after the preceding put and delete have already been staged inside the
/// write transaction. The failing write must surface redb's typed
/// `ValueTooLarge` error, and redb's own transaction abort (the dropped
/// `WriteTransaction`) must discard the staged work: none of the batch
/// applies and the pre-batch state survives verbatim. The wrapper-level
/// [`conformance::error_preservation_before_backend`] seam cannot reach this
/// boundary.
///
/// The oversized value is one lazily-zeroed allocation (`vec![0u8; …]`):
/// redb checks the length before touching the bytes, so the test never
/// faults in the 3 GiB.
#[test]
fn a_backend_internal_failure_mid_batch_aborts_the_write_transaction() {
    const OVERSIZED: usize = 3 * 1024 * 1024 * 1024 + 1;

    let db = TempDb::new("redb-mid-batch");
    let store = RedbStore::open_path(db.path()).expect("file redb opens");

    let (setup, prior, poisoned) = (b"redb-mid/setup", b"redb-mid/prior", b"redb-mid/poisoned");
    let mut setup_batch = Batch::new();
    setup_batch.put(setup, b"old");
    store.write(setup_batch).expect("the setup write succeeds");

    let mut batch = Batch::new();
    batch.put(prior, b"must-not-land");
    batch.delete(setup);
    batch.put_owned(poisoned, vec![0u8; OVERSIZED]);
    match store.write(batch) {
        Err(RedbError::Storage(redb::StorageError::ValueTooLarge(len))) => {
            assert_eq!(len, OVERSIZED, "the backend names the rejected op's size");
        }
        Err(other) => panic!("expected ValueTooLarge, got {other:?}"),
        Ok(()) => panic!("the oversized write must fail inside the transaction"),
    }

    // redb aborted its own transaction: nothing from the batch applied, and
    // the staged delete of the setup key was discarded with it.
    let results = store
        .read(&[prior, setup, poisoned])
        .expect("read succeeds");
    assert_eq!(
        results,
        [None, Some(b"old".to_vec()), None],
        "the failed batch must not partially apply — all-or-nothing"
    );

    // A well-formed retry of the same batch shape applies whole.
    let mut batch = Batch::new();
    batch.put(prior, b"lands-now");
    batch.delete(setup);
    batch.put(poisoned, b"lands-now");
    store.write(batch).expect("the retry succeeds");
    let results = store
        .read(&[prior, setup, poisoned])
        .expect("read succeeds");
    assert_eq!(
        results,
        [
            Some(b"lands-now".to_vec()),
            None,
            Some(b"lands-now".to_vec())
        ],
        "after the fault clears the batch applies whole"
    );
}

#[test]
fn clones_share_data_and_identity() {
    let db = TempDb::new("redb-clone");
    let store = RedbStore::open_path(db.path()).expect("file redb opens");
    let clone = store.clone();

    let mut batch = Batch::new();
    batch.put(b"shared", b"value");
    clone.write(batch).expect("redb writes only fail on I/O");

    let results = store
        .read(&[b"shared"])
        .expect("redb reads only fail on I/O");
    assert_eq!(
        results[0].as_deref(),
        Some(b"value".as_slice()),
        "clones share the database"
    );
    assert!(store.same_store(&clone), "clones report the same storage");
    assert!(clone.same_store(&store), "same_store is symmetric");
    assert_eq!(store.identity(), clone.identity(), "clones share identity");

    let other = RedbStore::open_path(TempDb::new("redb-clone-other").path())
        .expect("a second database opens");
    assert!(
        !store.same_store(&other),
        "distinct databases are distinct storage"
    );
}

#[test]
fn persistence_across_reopen() {
    let db = TempDb::new("redb-persist");
    {
        let store = RedbStore::open_path(db.path()).expect("file redb opens");
        let mut batch = Batch::new();
        batch.put(b"durable", b"value");
        store.write(batch).expect("redb writes only fail on I/O");
    }

    let reopened = RedbStore::open_path(db.path()).expect("file redb re-opens");
    let results = reopened
        .read(&[b"durable", b"absent"])
        .expect("redb reads only fail on I/O");
    assert_eq!(
        results[0].as_deref(),
        Some(b"value".as_slice()),
        "data survives dropping the handle"
    );
    assert_eq!(results[1], None, "a fresh key was never written");
}

#[test]
fn reopen_from_locator_and_raw_path_round_trip() {
    let db = TempDb::new("redb-locator");
    let original = RedbStore::open_path(db.path()).expect("file redb opens");

    // The locator is the raw OS path — never a lossy string.
    let locator = Store::locator(&original).expect("file databases have locators");
    assert_eq!(
        locator.as_bytes(),
        db.path().as_os_str().as_encoded_bytes(),
        "the locator is the raw OS path"
    );
    assert_eq!(
        Retrievable::canonical_locator(&original),
        locator,
        "Store::locator and canonical_locator agree"
    );

    let mut batch = Batch::new();
    batch.put(b"key", b"value");
    original.write(batch).expect("redb writes only fail on I/O");
    drop(original);

    let reopened =
        <RedbStore as Retrievable>::open(&locator).expect("the locator re-opens the database");
    let results = reopened
        .read(&[b"key"])
        .expect("redb reads only fail on I/O");
    assert_eq!(
        results[0].as_deref(),
        Some(b"value".as_slice()),
        "Retrievable::open reattaches to the persisted data"
    );
}

/// redb locks the database file while a handle is open: a second open of
/// the same path fails with `DatabaseAlreadyOpen` rather than aliasing the
/// storage. (This is why `same_store` can key on handle identity alone.)
#[test]
fn a_second_open_of_a_live_database_is_refused() {
    let db = TempDb::new("redb-lock");
    let store = RedbStore::open_path(db.path()).expect("file redb opens");

    match RedbStore::open_path(db.path()) {
        Err(RedbError::Database(redb::DatabaseError::DatabaseAlreadyOpen)) => {}
        other => panic!("a live database must refuse a second open, got {other:?}"),
    }
    drop(store);

    RedbStore::open_path(db.path()).expect("after the handle drops, the file re-opens");
}

#[test]
fn durability_configuration_is_applied() {
    // Default posture: every commit is fsynced before `write` returns.
    let defaults = RedbConfig::new("unused.redb");
    assert!(
        matches!(defaults.durability(), redb::Durability::None),
        "the default durability is None (process-crash safe, no per-commit fsync)"
    );

    // Relaxed posture: a None commit is visible in-process (read-your-
    // writes) and batch semantics are unchanged; persistence across a
    // process boundary is deliberately not asserted — that is the trade
    // the caller opted into.
    let db = TempDb::new("redb-durability");
    let relaxed =
        RedbStore::open(RedbConfig::new(db.path()).with_durability(redb::Durability::None))
            .expect("file redb opens");

    let mut first = Batch::new();
    first.put(b"relaxed", b"one");
    relaxed
        .write(first)
        .expect("a None-durability commit succeeds");

    let mut second = Batch::new();
    second.put(b"relaxed", b"two");
    second.delete(b"relaxed");
    relaxed
        .write(second)
        .expect("a second None-durability commit succeeds");

    let results = relaxed
        .read(&[b"relaxed"])
        .expect("redb reads only fail on I/O");
    assert_eq!(
        results[0], None,
        "batch semantics hold under None durability"
    );
}

/// MVCC: a reader observing commits from a concurrent writer never errors
/// and never observes a torn state — each read returns the value of some
/// committed batch, and observed values are monotonically non-decreasing.
#[test]
fn readers_run_concurrently_with_the_writer() {
    const COMMITS: u64 = 64;

    let db = TempDb::new("redb-concurrent");
    let store = Arc::new(RedbStore::open_path(db.path()).expect("file redb opens"));

    let mut seed = Batch::new();
    seed.put_owned(b"crw", 0u64.to_be_bytes().to_vec());
    store.write(seed).expect("the seed write succeeds");

    let writer_store = Arc::clone(&store);
    let writer = thread::spawn(move || {
        for i in 1..=COMMITS {
            let mut batch = Batch::new();
            batch.put_owned(b"crw", i.to_be_bytes().to_vec());
            writer_store.write(batch).expect("each commit succeeds");
        }
    });

    let reader_store = Arc::clone(&store);
    let reader = thread::spawn(move || {
        let mut last = 0u64;
        loop {
            let results = reader_store.read(&[b"crw"]).expect("reads never error");
            let observed = u64::from_be_bytes(
                results[0]
                    .as_deref()
                    .expect("seeded")
                    .try_into()
                    .expect("u64 value"),
            );
            assert!(
                observed >= last,
                "observed values must never regress: {observed} < {last}"
            );
            last = observed;
            if observed == COMMITS {
                break;
            }
        }
    });

    writer.join().expect("the writer thread survives");
    reader.join().expect("the reader thread survives");

    let results = store.read(&[b"crw"]).expect("the final read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(COMMITS.to_be_bytes().as_slice()),
        "the final commit is visible"
    );
}

/// The panic-safe temp guard removes the database file on drop.
#[test]
fn temp_database_files_are_cleaned_up_on_drop() {
    let db = TempDb::new("redb-cleanup");
    let store = RedbStore::open_path(db.path()).expect("file redb opens");
    let path = db.path().to_path_buf();
    assert!(path.exists(), "the database file exists while open");

    drop(store);
    drop(db);
    assert!(!path.exists(), "the guard removes the file on drop");
}

/// A persisted locator reconstructs the store with its data.
#[test]
fn locator_round_trips_through_retrievable_open() {
    let db = TempDb::new("redb-retrievable");
    let store = RedbStore::open_path(db.path()).expect("file redb opens");

    let mut batch = Batch::new();
    batch.put(b"meta", b"layer");
    store.write(batch).expect("redb writes only fail on I/O");

    let locator = Retrievable::canonical_locator(&store);
    drop(store);

    let reopened = <RedbStore as Retrievable>::open(&locator).expect("re-open succeeds");
    let results = reopened
        .read(&[b"meta"])
        .expect("redb reads only fail on I/O");
    assert_eq!(results[0].as_deref(), Some(b"layer".as_slice()));
    assert_eq!(
        Retrievable::canonical_locator(&reopened),
        locator,
        "the re-opened store reports the same locator"
    );
}

/// A failed open surfaces as a typed [`RedbError`], never a panic.
#[test]
fn opening_a_missing_database_directory_fails_cleanly() {
    let missing = std::env::temp_dir()
        .join("accumulators-redb-missing")
        .join("nested")
        .join("no-parent.redb");
    let outcome: Result<RedbStore, RedbError> = RedbStore::open_path(&missing);
    assert!(
        outcome.is_err(),
        "an uncreatable path must error, not panic"
    );
}
