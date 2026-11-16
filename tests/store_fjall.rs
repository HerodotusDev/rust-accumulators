//! Fjall store backend tests: the full backend-agnostic conformance suite
//! plus the fjall-specific contract — re-opening from the locator,
//! clone-shared keyspaces, config-driven keyspaces, and temp-folder cleanup.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(feature = "fjall", feature = "keccak_sol", not(target_family = "wasm")))]

#[path = "common/mod.rs"]
mod common;

#[path = "store/conformance.rs"]
mod conformance;

use accumulators::store::fjall::{FjallConfig, FjallStore};
use accumulators::store::{Batch, Retrievable, Store};

use common::{FaultyStore, TempDir};

#[test]
fn the_fjall_store_satisfies_the_conformance_suite() {
    let dir = TempDir::new("conformance");
    let store = FjallStore::open(FjallConfig::new(dir.path())).expect("fjall store opens");
    conformance::positional_reads(&store);
    conformance::empty_key_list(&store);
    conformance::put_delete_batch(&store);
    conformance::last_op_wins(&store);
    conformance::empty_batch(&store);
    conformance::duplicate_keys_alignment(&store);
    conformance::owned_ops(&store);
    conformance::binary_keys(&store);
    // The fault seam wraps the same handle — fjall holds an exclusive lock
    // file per database folder, so no second database open may happen here.
    conformance::error_preservation_before_backend(&FaultyStore::new(store));
}

/// The async surface (scoped module, see `store_sled.rs`): the full async
/// conformance suite plus the async locator round trip —
/// [`AsyncRetrievable::open`] decodes the (path, keyspace) locator off the
/// async path and offloads the database open to the blocking pool.
mod async_surface {
    use accumulators::store::fjall::{FjallConfig, FjallStore};
    use accumulators::store::{AsyncRetrievable, AsyncStore, Batch};

    use crate::common::{FaultyStore, TempDir};
    use crate::conformance;

    #[tokio::test]
    async fn the_fjall_store_satisfies_the_async_conformance_suite() {
        let dir = TempDir::new("conformance-async");
        let store = FjallStore::open(FjallConfig::new(dir.path())).expect("fjall store opens");
        conformance::positional_reads_async(&store).await;
        conformance::empty_key_list_async(&store).await;
        conformance::put_delete_batch_async(&store).await;
        conformance::last_op_wins_async(&store).await;
        conformance::empty_batch_async(&store).await;
        conformance::duplicate_keys_alignment_async(&store).await;
        conformance::owned_ops_async(&store).await;
        conformance::binary_keys_async(&store).await;
        // Same-handle fault seam (see the sync suite's lock-file note).
        conformance::error_preservation_before_backend_async(&FaultyStore::new(store)).await;
    }

    #[tokio::test]
    async fn async_reopen_from_locator_round_trips_data() {
        let dir = TempDir::new("async-reopen");
        let locator = {
            let store = FjallStore::open(FjallConfig::new(dir.path())).expect("fjall store opens");
            let mut batch = Batch::new();
            batch.put(b"async/key", b"value");
            AsyncStore::write(&store, batch)
                .await
                .expect("write succeeds");
            <FjallStore as AsyncRetrievable>::canonical_locator(&store)
        };

        let reopened = <FjallStore as AsyncRetrievable>::open(&locator)
            .await
            .expect("re-open from locator");
        let results = AsyncStore::read(&reopened, &[b"async/key"])
            .await
            .expect("read succeeds");
        assert_eq!(results[0].as_deref(), Some(b"value".as_slice()));
    }
}

#[test]
fn reopen_from_locator_round_trips_data() {
    let dir = TempDir::new("reopen");
    let store = FjallStore::open(FjallConfig::new(dir.path())).expect("fjall store opens");

    let mut batch = Batch::new();
    let counter: [u8; 8] = 42_u64.to_be_bytes();
    batch.put(b"persist/counter", counter.as_slice());
    batch.put_owned(b"persist/node", vec![1, 2, 3, 4]);
    store.write(batch).expect("batch write succeeds");

    // The locator is the persistence story: Store::locator (the pin hint)
    // and canonical_locator (the persisted answer) must agree.
    let locator = store.locator().expect("fjall stores are re-openable");
    assert_eq!(locator, store.canonical_locator());

    drop(store);
    let reopened: FjallStore = Retrievable::open(&locator).expect("re-open from locator");
    let results = reopened
        .read(&[b"persist/counter", b"persist/node", b"persist/absent"])
        .expect("read succeeds");
    assert_eq!(results[0].as_deref(), Some(42_u64.to_be_bytes().as_slice()));
    assert_eq!(results[1].as_deref(), Some([1, 2, 3, 4].as_slice()));
    assert_eq!(results[2], None);
}

#[test]
fn clones_share_the_keyspace_and_report_same_store() {
    let dir = TempDir::new("clone");
    let store = FjallStore::open(FjallConfig::new(dir.path())).expect("fjall store opens");
    let clone = store.clone();

    let mut batch = Batch::new();
    batch.put(b"clone/visible", b"through-both-handles");
    clone.write(batch).expect("write through the clone");

    let results = store.read(&[b"clone/visible"]).expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"through-both-handles".as_slice()),
        "clone and original share one keyspace"
    );

    assert!(store.same_store(&clone), "clones are one storage");
    assert!(clone.same_store(&store));
    assert_eq!(store.identity(), clone.identity(), "one identity");
    assert_eq!(store.locator(), clone.locator());
}

#[test]
fn config_selects_the_keyspace_and_tuning() {
    let dir = TempDir::new("config");

    // Two stores over one database, pinned to different keyspaces — opened
    // sequentially (fjall's lock file forbids two live handles per path).
    let alpha = FjallStore::open(
        FjallConfig::new(dir.path())
            .with_keyspace("alpha")
            // Tuning knobs are accepted and do not affect semantics.
            .with_durability(None),
    )
    .expect("alpha opens");
    assert_eq!(&**alpha.keyspace().name(), "alpha");

    let mut batch = Batch::new();
    batch.put(b"config/who", b"alpha");
    alpha.write(batch).expect("write succeeds");
    let locator = alpha.locator().expect("alpha is re-openable");
    drop(alpha);

    let beta =
        FjallStore::open(FjallConfig::new(dir.path()).with_keyspace("beta")).expect("beta opens");
    assert_eq!(&**beta.keyspace().name(), "beta");
    let results = beta.read(&[b"config/who"]).expect("read succeeds");
    assert_eq!(
        results[0], None,
        "a different keyspace never sees alpha's keys"
    );
    assert_ne!(
        beta.locator(),
        Some(locator),
        "keyspaces differ in identity"
    );
    drop(beta);

    let alpha_again = FjallStore::open(FjallConfig::new(dir.path()).with_keyspace("alpha"))
        .expect("alpha re-opens");
    let results = alpha_again.read(&[b"config/who"]).expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"alpha".as_slice()),
        "alpha's data survives in its own keyspace"
    );
}

#[test]
fn invalid_keyspace_names_are_rejected_not_panics() {
    let dir = TempDir::new("names");
    // Fjall panics on invalid names; the store must reject them first.
    assert!(matches!(
        FjallStore::open(FjallConfig::new(dir.path()).with_keyspace("")),
        Err(accumulators::store::fjall::FjallError::InvalidKeyspaceName)
    ));
    assert!(matches!(
        FjallStore::open(FjallConfig::new(dir.path()).with_keyspace("x".repeat(256))),
        Err(accumulators::store::fjall::FjallError::InvalidKeyspaceName)
    ));
}

#[test]
fn temporary_config_removes_the_database_folder_on_drop() {
    let dir = TempDir::new("temporary");
    let config = FjallConfig::new(dir.path()).with_temporary(true);
    let store = FjallStore::open(config).expect("temporary store opens");

    let mut batch = Batch::new();
    batch.put(b"temp/key", b"value");
    store.write(batch).expect("write succeeds");

    let db_path = dir.path().to_path_buf();
    assert!(db_path.try_exists().expect("fs works"), "database exists");
    drop(store);
    assert!(
        !db_path.try_exists().expect("fs works"),
        "temporary config deletes the folder on drop"
    );
}

#[test]
fn atomic_batch_lands_whole_across_reopen() {
    let dir = TempDir::new("atomic");
    let store = FjallStore::open(FjallConfig::new(dir.path())).expect("fjall store opens");

    let mut setup = Batch::new();
    setup.put(b"atomic/existing", b"old");
    store.write(setup).expect("setup write succeeds");

    // One atomic unit: a put, an overwrite, and a delete of prior state.
    let mut batch = Batch::new();
    batch.put(b"atomic/new", b"created");
    batch.put(b"atomic/existing", b"overwritten");
    batch.delete(b"atomic/existing");
    store.write(batch).expect("batch write succeeds");
    let locator = store.locator().expect("fjall stores are re-openable");
    drop(store);

    let reopened: FjallStore = Retrievable::open(&locator).expect("re-opens");
    let results = reopened
        .read(&[b"atomic/new", b"atomic/existing"])
        .expect("read succeeds");
    assert_eq!(results[0].as_deref(), Some(b"created".as_slice()));
    assert_eq!(results[1], None, "delete inside the batch applied");
}
