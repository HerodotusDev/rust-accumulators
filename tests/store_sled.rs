//! Behavior tests for the sled store backend: the full backend-agnostic
//! conformance suite plus sled-specific semantics — locator round trips,
//! clone identity, persistence across close/reopen, the exclusive directory
//! lock, config knobs, and temp-dir cleanup.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]

#[path = "common/mod.rs"]
mod common;

#[path = "store/conformance.rs"]
mod conformance;

use std::path::PathBuf;

use accumulators::store::sled::{SledConfig, SledError, SledStore};
use accumulators::store::{Batch, Retrievable, Store};

use common::{FaultyStore, TempDir};

// ------------------------------------------------------------------ fixtures

/// Opens a store in a guarded temp directory; the returned guard must be kept
/// alive as long as the store (dropping it while a handle is alive would race
/// the directory lock, so the pair is always bound together in tests).
fn guarded_store(label: &str) -> (TempDir, SledStore) {
    let dir = TempDir::new(label);
    let store = SledStore::open_path(dir.path()).expect("sled store opens");
    (dir, store)
}

// ---------------------------------------------------------------- conformance

#[test]
fn the_sled_store_satisfies_the_conformance_suite() {
    let dir = TempDir::new("conformance");
    let store = SledStore::open_path(dir.path()).expect("sled store opens");
    conformance::positional_reads(&store);
    conformance::empty_key_list(&store);
    conformance::put_delete_batch(&store);
    conformance::last_op_wins(&store);
    conformance::empty_batch(&store);
    conformance::duplicate_keys_alignment(&store);
    conformance::owned_ops(&store);
    let fault_dir = TempDir::new("conformance-fault");
    conformance::error_preservation_before_backend(&FaultyStore::new(
        SledStore::open_path(fault_dir.path()).expect("opens"),
    ));
}

/// The async surface: the full async conformance suite plus the async
/// locator round trip. Kept in its own module so `AsyncStore` (and its
/// identically-named methods) stays out of the sync tests' scope.
mod async_surface {
    use accumulators::store::sled::SledStore;
    use accumulators::store::{AsyncRetrievable, AsyncStore, Batch};

    use crate::common::{FaultyStore, TempDir};
    use crate::conformance;

    #[tokio::test]
    async fn the_sled_store_satisfies_the_async_conformance_suite() {
        let dir = TempDir::new("conformance-async");
        let store = SledStore::open_path(dir.path()).expect("sled store opens");
        conformance::positional_reads_async(&store).await;
        conformance::empty_key_list_async(&store).await;
        conformance::put_delete_batch_async(&store).await;
        conformance::last_op_wins_async(&store).await;
        conformance::empty_batch_async(&store).await;
        conformance::duplicate_keys_alignment_async(&store).await;
        conformance::owned_ops_async(&store).await;
        let fault_dir = TempDir::new("conformance-async-fault");
        conformance::error_preservation_before_backend_async(&FaultyStore::new(
            SledStore::open_path(fault_dir.path()).expect("opens"),
        ))
        .await;
    }

    /// The async locator round trip: [`AsyncRetrievable::open`] offloads the
    /// directory open to the blocking pool and reattaches to the persisted
    /// data.
    #[tokio::test]
    async fn async_reopen_from_locator_round_trips_the_data() {
        let dir = TempDir::new("async-reopen");
        let locator = {
            let store = SledStore::open_path(dir.path()).expect("sled store opens");
            let mut batch = Batch::new();
            batch.put(b"key", b"value");
            AsyncStore::write(&store, batch).await.expect("sled write");

            // Dropping the last handle flushes; the locator survives the store.
            <SledStore as AsyncRetrievable>::canonical_locator(&store)
        };

        let reopened = <SledStore as AsyncRetrievable>::open(&locator)
            .await
            .expect("open re-opens the path");
        let results = AsyncStore::read(&reopened, &[b"key"])
            .await
            .expect("sled read");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "open reattaches to the persisted data"
        );
    }
}

// ------------------------------------------------------- sled-specific behavior

#[test]
fn clones_share_database_and_identity() {
    let dir = TempDir::new("clone");
    let store = SledStore::open_path(dir.path()).expect("sled store opens");
    let clone = store.clone();

    let mut batch = Batch::new();
    batch.put(b"shared", b"value");
    clone.write(batch).expect("sled write");

    let results = store.read(&[b"shared"]).expect("sled read");
    assert_eq!(
        results[0].as_deref(),
        Some(b"value".as_slice()),
        "clones share the database"
    );
    assert!(store.same_store(&clone), "clones report the same storage");
    assert!(clone.same_store(&store), "same_store is symmetric");
    assert_eq!(store.identity(), clone.identity(), "clones share identity");

    let (_other_dir, other) = guarded_store("clone-other");
    assert!(
        !store.same_store(&other),
        "distinct databases are distinct storage"
    );
    assert_ne!(
        store.identity(),
        other.identity(),
        "distinct databases have distinct identities"
    );
}

#[test]
fn locator_is_the_raw_os_path() {
    let dir = TempDir::new("locator");
    let store = SledStore::open_path(dir.path()).expect("sled store opens");

    let locator = Store::locator(&store).expect("sled stores carry a locator");
    assert_eq!(
        locator.as_bytes(),
        dir.path().as_os_str().as_encoded_bytes(),
        "the locator is the raw OS path of the database directory"
    );
    assert_eq!(
        Retrievable::canonical_locator(&store),
        locator,
        "the canonical locator matches the reported locator"
    );
}

#[test]
fn reopen_from_locator_round_trips_the_data() {
    let dir = TempDir::new("reopen");
    let locator = {
        let store = SledStore::open_path(dir.path()).expect("sled store opens");
        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        store.write(batch).expect("sled write");

        // Dropping the last handle flushes; the locator survives the store.
        Retrievable::canonical_locator(&store)
    };

    let reopened = <SledStore as Retrievable>::open(&locator).expect("open re-opens the path");
    let results = reopened.read(&[b"key"]).expect("sled read");
    assert_eq!(
        results[0].as_deref(),
        Some(b"value".as_slice()),
        "open reattaches to the persisted data"
    );
}

#[test]
fn data_persists_across_close_and_reopen() {
    let dir = TempDir::new("persist");
    {
        let store = SledStore::open_path(dir.path()).expect("sled store opens");
        let mut batch = Batch::new();
        batch.put(b"durable", b"value");
        store.write(batch).expect("sled write");
        store.flush().expect("explicit flush succeeds");
    }

    let reopened = SledStore::open_path(dir.path()).expect("sled store re-opens");
    let results = reopened.read(&[b"durable"]).expect("sled read");
    assert_eq!(
        results[0].as_deref(),
        Some(b"value".as_slice()),
        "data survives dropping the handle"
    );
}

#[test]
fn a_second_live_handle_on_one_path_is_rejected() {
    let dir = TempDir::new("lock");
    let _store = SledStore::open_path(dir.path()).expect("sled store opens");

    match SledStore::open_path(dir.path()) {
        // sled holds an exclusive directory lock while a handle is alive.
        Err(SledError::Io(error)) => assert_eq!(
            error.kind(),
            std::io::ErrorKind::WouldBlock,
            "the directory lock surfaces as WouldBlock, got: {error}"
        ),
        Err(error) => panic!("unexpected error kind: {error}"),
        Ok(_) => panic!("a second live handle on one path must fail"),
    }
}

#[test]
fn binary_keys_round_trip_verbatim() {
    let dir = TempDir::new("binary-keys");
    let store = SledStore::open_path(dir.path()).expect("sled store opens");

    let mut binary_key = vec![0u8, 255, 0, 1];
    binary_key.extend_from_slice(&u64::MAX.to_be_bytes());
    let mut batch = Batch::new();
    batch.put_owned(binary_key.clone(), vec![0, 0, 255, 255]);
    store.write(batch).expect("sled write");

    let results = store.read(&[binary_key.as_slice()]).expect("sled read");
    assert_eq!(
        results[0].as_deref(),
        Some([0, 0, 255, 255].as_slice()),
        "keys are opaque bytes end-to-end"
    );
}

#[test]
fn config_knobs_are_accepted_and_the_store_functions() {
    // The knobs are pass-throughs to sled's config builder; observable
    // behavior here is that a fully-tuned config opens and round-trips.
    let store = SledStore::open(
        SledConfig::in_temp("knobs")
            .with_cache_capacity_bytes(16 * 1024 * 1024)
            .with_flush_every_ms(None)
            .with_zstd_compression_level(1),
    )
    .expect("tuned config opens");

    let mut batch = Batch::new();
    batch.put(b"key", b"value");
    store.write(batch).expect("sled write");
    store.flush().expect("explicit flush succeeds");
    let results = store.read(&[b"key"]).expect("sled read");
    assert_eq!(results[0].as_deref(), Some(b"value".as_slice()));
}

#[test]
fn in_temp_stores_are_unique_and_isolated() {
    let first = SledStore::open(SledConfig::in_temp("unique")).expect("in_temp config opens");
    let second = SledStore::open(SledConfig::in_temp("unique")).expect("in_temp config opens");

    // Both handles are alive simultaneously — only possible on distinct
    // directories, since sled's exclusive directory lock rejects a second
    // open of one path. That makes this isolation check also prove that
    // `in_temp` hands out fresh locations every call.
    let mut batch = Batch::new();
    batch.put(b"key", b"first");
    first.write(batch).expect("sled write");
    let results = second.read(&[b"key"]).expect("sled read");
    assert_eq!(results[0], None, "distinct in_temp stores are isolated");
    assert!(!first.same_store(&second));

    // `in_temp` directories are documented as not auto-removed; clean up
    // through the locator (raw OS path bytes, ASCII for temp-dir names).
    let paths = [&first, &second].map(|store| {
        PathBuf::from(
            String::from_utf8_lossy(Retrievable::canonical_locator(store).as_bytes()).into_owned(),
        )
    });
    drop(first);
    drop(second);
    for path in paths {
        let _ = std::fs::remove_dir_all(path);
    }
}
