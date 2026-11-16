//! Behavior tests for the `RocksDB` store backend: the backend-agnostic
//! conformance suite plus `RocksDB`-specific behavior — re-opening from
//! locators, handle identity, config semantics, concurrency, persistence
//! and cleanup.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]

#[path = "common/mod.rs"]
mod common;

#[path = "store/conformance.rs"]
mod conformance;

mod rocksdb {
    use accumulators::store::rocksdb::{RocksdbConfig, RocksdbError, RocksdbStore};
    use accumulators::store::{Batch, Retrievable, Store, StoreLocator};

    use crate::common::{FaultyStore, TempDir};
    use crate::conformance;

    fn open_at(label: &str) -> (RocksdbStore, TempDir) {
        let dir = TempDir::new(label);
        let store = RocksdbStore::open(RocksdbConfig::new(dir.path()))
            .expect("a fresh database always opens");
        (store, dir)
    }

    #[test]
    fn the_rocksdb_store_satisfies_the_conformance_suite() {
        let (store, _dir) = open_at("conformance");
        conformance::positional_reads(&store);
        conformance::empty_key_list(&store);
        conformance::put_delete_batch(&store);
        conformance::last_op_wins(&store);
        conformance::empty_batch(&store);
        conformance::duplicate_keys_alignment(&store);
        conformance::owned_ops(&store);
        conformance::binary_keys(&store);

        let faulty =
            RocksdbStore::open(RocksdbConfig::new(TempDir::new("conformance-fault").path()))
                .expect("a fresh database always opens");
        conformance::error_preservation_before_backend(&FaultyStore::new(faulty));
    }

    #[test]
    fn clones_share_data_and_identity() {
        let (store, _dir) = open_at("clone");
        let clone = store.clone();

        let mut batch = Batch::new();
        batch.put(b"shared", b"value");
        clone.write(batch).expect("rocksdb writes only fail on I/O");

        let results = store
            .read(&[b"shared"])
            .expect("rocksdb reads only fail on I/O");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "clones front the same database"
        );
        assert!(store.same_store(&clone), "clones report the same storage");
        assert!(clone.same_store(&store), "same_store is symmetric");
        assert_eq!(
            store.identity(),
            clone.identity(),
            "identity matches clones"
        );

        let (other, _other_dir) = open_at("clone-other");
        assert!(
            !store.same_store(&other),
            "independently opened databases are distinct storage"
        );
    }

    #[test]
    fn the_locator_is_the_raw_database_path_and_reopens_the_data() {
        let (store, dir) = open_at("locator");

        let mut batch = Batch::new();
        batch.put(b"durable", b"value");
        store.write(batch).expect("rocksdb writes only fail on I/O");

        let locator = Store::locator(&store).expect("rocksdb stores are re-openable");
        assert_eq!(
            locator.as_bytes(),
            dir.path().as_os_str().as_encoded_bytes(),
            "the locator is the raw OS path, never a lossy string"
        );
        assert_eq!(
            Retrievable::canonical_locator(&store),
            locator,
            "canonical_locator matches locator()"
        );

        drop(store);
        let reopened =
            <RocksdbStore as Retrievable>::open(&locator).expect("open re-opens the path");
        let results = reopened
            .read(&[b"durable"])
            .expect("rocksdb reads only fail on I/O");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "data persists across a close/reopen cycle"
        );
    }

    #[test]
    fn open_on_a_missing_database_fails_instead_of_creating() {
        let dir = TempDir::new("missing");
        let locator = StoreLocator::from_bytes(dir.path().as_os_str().as_encoded_bytes().to_vec());
        // Retrievable::open never creates (see its docs): a locator names an
        // existing store, and a missing one must fail closed.
        assert!(
            matches!(
                <RocksdbStore as Retrievable>::open(&locator),
                Err(RocksdbError::Db(_))
            ),
            "a missing database must not be fabricated under a locator"
        );

        // The explicit-config counterpart: create_if_missing(false) fails on
        // a nonexistent path, create_if_missing(true) succeeds.
        assert!(
            RocksdbStore::open(RocksdbConfig::new(dir.path()).with_create_if_missing(false))
                .is_err()
        );
        RocksdbStore::open(RocksdbConfig::new(dir.path()))
            .expect("create_if_missing defaults to true");
    }

    #[test]
    fn non_default_config_options_open_and_function() {
        use rocksdb::DBCompressionType;

        let dir = TempDir::new("tuned");
        let config = RocksdbConfig::new(dir.path())
            .with_compression(DBCompressionType::Lz4)
            .with_write_buffer_size(1 << 20)
            .with_max_open_files(64)
            .with_base_options(rocksdb::Options::default());
        assert_eq!(config.path(), dir.path(), "the config keeps its path");
        let store = RocksdbStore::open(config).expect("tuned options open");

        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        store.write(batch).expect("rocksdb writes only fail on I/O");
        let results = store
            .read(&[b"key"])
            .expect("rocksdb reads only fail on I/O");
        assert_eq!(results[0].as_deref(), Some(b"value".as_slice()));
    }

    #[test]
    fn concurrent_readers_and_writers_share_one_handle() {
        let (store, _dir) = open_at("concurrent");
        // Both threads front the exact same engine — clones are the
        // documented concurrency model, no external lock involved.
        let writer = store.clone();
        let reader = store.clone();

        let handle = std::thread::spawn(move || {
            for i in 0..64u64 {
                let mut batch = Batch::new();
                batch.put_owned(format!("key-{i}").into_bytes(), i.to_be_bytes().to_vec());
                writer
                    .write(batch)
                    .expect("concurrent writes only fail on I/O");
            }
        });

        let mut seen = 0;
        while seen < 64 {
            let keys: Vec<Vec<u8>> = (0..64u64)
                .map(|i| format!("key-{i}").into_bytes())
                .collect();
            let key_refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
            let results = reader
                .read(&key_refs)
                .expect("concurrent reads only fail on I/O");
            seen = results.iter().filter(|slot| slot.is_some()).count();
            std::thread::yield_now();
        }

        handle.join().expect("the writer thread never panics");
        let keys: Vec<Vec<u8>> = (0..64u64)
            .map(|i| format!("key-{i}").into_bytes())
            .collect();
        let key_refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        let results = store
            .read(&key_refs)
            .expect("rocksdb reads only fail on I/O");
        assert_eq!(results.iter().filter(|slot| slot.is_some()).count(), 64);
    }

    #[test]
    fn destroy_removes_the_database_directory() {
        let (store, dir) = open_at("destroy");
        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        store.write(batch).expect("rocksdb writes only fail on I/O");
        drop(store);

        RocksdbStore::destroy(&RocksdbConfig::new(dir.path()))
            .expect("destroy succeeds once every handle is dropped");
        assert!(
            !dir.path().exists(),
            "destroy removes the database directory"
        );
    }
}

/// The async surface (scoped module, see `store_sled.rs`): the full async
/// conformance suite plus the async locator round trip.
mod async_surface {
    use accumulators::store::rocksdb::{RocksdbConfig, RocksdbStore};
    use accumulators::store::{AsyncRetrievable, AsyncStore, Batch};

    use crate::common::{FaultyStore, TempDir};
    use crate::conformance;

    fn open_at(label: &str) -> (RocksdbStore, TempDir) {
        let dir = TempDir::new(label);
        let store = RocksdbStore::open(RocksdbConfig::new(dir.path()))
            .expect("a fresh database always opens");
        (store, dir)
    }

    #[tokio::test]
    async fn the_rocksdb_store_satisfies_the_async_conformance_suite() {
        let (store, _dir) = open_at("conformance-async");
        conformance::positional_reads_async(&store).await;
        conformance::empty_key_list_async(&store).await;
        conformance::put_delete_batch_async(&store).await;
        conformance::last_op_wins_async(&store).await;
        conformance::empty_batch_async(&store).await;
        conformance::duplicate_keys_alignment_async(&store).await;
        conformance::owned_ops_async(&store).await;
        conformance::binary_keys_async(&store).await;

        let faulty = RocksdbStore::open(RocksdbConfig::new(
            TempDir::new("conformance-async-fault").path(),
        ))
        .expect("a fresh database always opens");
        conformance::error_preservation_before_backend_async(&FaultyStore::new(faulty)).await;
    }

    /// The async locator round trip: [`AsyncRetrievable::open`] offloads the
    /// directory open to the blocking pool and never creates (the sync
    /// locator contract).
    #[tokio::test]
    async fn async_reopen_from_locator_round_trips_the_data() {
        let (store, _dir) = open_at("async-reopen");
        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        AsyncStore::write(&store, batch)
            .await
            .expect("rocksdb write");
        let locator = <RocksdbStore as AsyncRetrievable>::canonical_locator(&store);
        drop(store);

        let reopened = <RocksdbStore as AsyncRetrievable>::open(&locator)
            .await
            .expect("open re-opens the path");
        let results = AsyncStore::read(&reopened, &[b"key"])
            .await
            .expect("rocksdb read");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "data persists across a close/reopen cycle"
        );
    }
}
