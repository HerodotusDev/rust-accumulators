//! Behavior tests for the storage layer: the in-memory reference backend,
//! the SQLite backend on native targets, the binary key layout, and `AccumulatorId`.

mod key_layout {
    use accumulators::ids::{AccumulatorId, TreeId};
    use accumulators::store::keys::{self, Table};

    /// A 3-byte id proving the key layout is id-length agnostic.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    struct ThreeByteId([u8; 3]);

    impl TreeId for ThreeByteId {
        fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.0);
        }

        fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let bytes: [u8; 3] = bytes.try_into().ok()?;
            Some(Self(bytes))
        }
    }

    /// A 32-byte id proving the layout carries wide ids too.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    struct WideId([u8; 32]);

    impl TreeId for WideId {
        fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&self.0);
        }

        fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let bytes: [u8; 32] = bytes.try_into().ok()?;
            Some(Self(bytes))
        }
    }

    #[test]
    fn encoded_keys_follow_the_wire_layout() {
        let id = AccumulatorId::from_bytes([0xab; 16]);
        let key = keys::encode(&id, Table::Nodes, 5);
        assert_eq!(
            key.len(),
            1 + 16 + 1 + 8,
            "length prefix, id, table tag, subkey"
        );
        assert_eq!(key[0], 16, "the length prefix is the id's byte length");
        assert_eq!(
            &key[1..17],
            [0xab; 16].as_slice(),
            "the id bytes follow the prefix"
        );
        assert_eq!(
            key[17],
            Table::Nodes as u8,
            "the table tag is the discriminant"
        );
        assert_eq!(&key[18..], &5u64.to_be_bytes(), "the subkey is big-endian");
    }

    #[test]
    fn encode_decode_round_trips_every_table_and_subkey() {
        let id = AccumulatorId::from_bytes([0x42; 16]);
        let id_bytes = id.as_bytes().to_vec();
        let tables = [
            Table::Nodes,
            Table::LeafCount,
            Table::NodeCount,
            Table::Root,
            Table::HasherInfo,
            Table::Mode,
            Table::Nullifiers,
            Table::Subviews,
            Table::TreeNode,
            Table::TreeMeta,
        ];
        for table in tables {
            for subkey in [0, 1, 0xdead_beef, u64::MAX] {
                let key = keys::encode(&id, table, subkey);
                let (decoded_id, decoded_table, decoded_subkey) =
                    keys::decode(&key).expect("encoded keys must decode");
                assert_eq!(decoded_id, id_bytes, "the id bytes round-trip");
                assert_eq!(decoded_table, table, "the table round-trips");
                assert_eq!(decoded_subkey, subkey, "the subkey round-trips");
            }
        }
    }

    #[test]
    fn table_from_repr_round_trips_the_wire_tags() {
        for tag in 0..=9u8 {
            let table = Table::from_repr(tag).expect("tags 0..=9 are assigned");
            assert_eq!(table as u8, tag, "wire tags are the discriminants");
        }
        for tag in [10u8, 64, 200, 255] {
            assert!(Table::from_repr(tag).is_none(), "tag {tag} is unassigned");
        }
    }

    #[test]
    fn decoding_foreign_bytes_fails_cleanly() {
        assert!(keys::decode(b"").is_none(), "empty keys are foreign");
        assert!(keys::decode(b"not even close").is_none(), "text is foreign");

        let mut unknown_table = vec![16];
        unknown_table.extend_from_slice(&[0; 16]);
        unknown_table.push(200);
        unknown_table.extend_from_slice(&0u64.to_be_bytes());
        assert!(
            keys::decode(&unknown_table).is_none(),
            "well-formed framing with an unknown table tag is foreign"
        );

        let mut overrun = vec![255];
        overrun.extend_from_slice(&[1; 10]);
        assert!(
            keys::decode(&overrun).is_none(),
            "a length prefix overrunning the key is foreign"
        );

        let truncated = [1, 0xaa, Table::Root as u8, 0, 0, 0];
        assert!(
            keys::decode(&truncated).is_none(),
            "a truncated subkey is foreign"
        );
    }

    #[test]
    fn subkeys_are_encoded_big_endian() {
        let key = keys::encode(
            &AccumulatorId::ZERO,
            Table::Nullifiers,
            0x0102_0304_0506_0708,
        );
        assert_eq!(
            &key[key.len() - 8..],
            &[1, 2, 3, 4, 5, 6, 7, 8],
            "the subkey bytes are big-endian"
        );
    }

    #[test]
    fn custom_length_ids_round_trip() {
        let short = ThreeByteId([0x11, 0x22, 0x33]);
        let key = keys::encode(&short, Table::TreeNode, 7);
        assert_eq!(key.len(), 1 + 3 + 1 + 8, "the layout carries 3-byte ids");
        let (decoded_id, decoded_table, decoded_subkey) =
            keys::decode(&key).expect("encoded keys must decode");
        assert_eq!(
            decoded_id,
            vec![0x11, 0x22, 0x33],
            "raw id bytes in encoding order"
        );
        assert_eq!(decoded_table, Table::TreeNode);
        assert_eq!(decoded_subkey, 7);
        assert_eq!(ThreeByteId::from_bytes(&decoded_id), Some(short));

        let wide = WideId([0x5a; 32]);
        let key = keys::encode(&wide, Table::TreeMeta, 0);
        assert_eq!(key.len(), 1 + 32 + 1 + 8, "the layout carries 32-byte ids");
        let (decoded_id, _, _) = keys::decode(&key).expect("encoded keys must decode");
        assert_eq!(WideId::from_bytes(&decoded_id), Some(wide));
    }
}

mod memory {
    use accumulators::store::memory::InMemoryStore;
    use accumulators::store::{Batch, Retrievable, Store, StoreLocator};

    #[test]
    fn read_results_are_positionally_aligned() {
        let store = InMemoryStore::new();
        let mut batch = Batch::new();
        batch.put(b"alpha", b"value-1");
        batch.put(b"beta", b"value-2");
        batch.put(b"gamma", b"value-3");
        store.write(batch).expect("memory writes are infallible");

        let keys: &[&[u8]] = &[b"beta", b"absent", b"alpha", b"alpha"];
        let results = store.read(keys).expect("memory reads are infallible");
        assert_eq!(results.len(), 4, "one result per requested key");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value-2".as_slice()),
            "results follow key order"
        );
        assert_eq!(results[1], None, "absent keys read back as None");
        assert_eq!(results[2].as_deref(), Some(b"value-1".as_slice()));
        assert_eq!(
            results[3].as_deref(),
            Some(b"value-1".as_slice()),
            "repeated keys repeat their result"
        );
    }

    #[test]
    fn read_with_no_keys_returns_no_results() {
        let store = InMemoryStore::new();
        let results = store.read(&[]).expect("memory reads are infallible");
        assert!(results.is_empty(), "no keys, no results");
    }

    #[test]
    fn batch_applies_puts_and_deletes_together() {
        let store = InMemoryStore::new();
        let mut setup = Batch::new();
        setup.put(b"doomed", b"old");
        store.write(setup).expect("memory writes are infallible");

        let mut batch = Batch::new();
        batch.put(b"fresh", b"new");
        batch.delete(b"doomed");
        store.write(batch).expect("memory writes are infallible");

        let results = store
            .read(&[b"fresh", b"doomed"])
            .expect("memory reads are infallible");
        assert_eq!(
            results[0].as_deref(),
            Some(b"new".as_slice()),
            "puts in the batch apply"
        );
        assert_eq!(results[1], None, "deletes in the batch apply");
    }

    #[test]
    fn later_batch_ops_override_earlier_ones() {
        let store = InMemoryStore::new();

        let mut batch = Batch::new();
        batch.put(b"key", b"first");
        batch.put(b"key", b"second");
        store.write(batch).expect("memory writes are infallible");
        let results = store.read(&[b"key"]).expect("memory reads are infallible");
        assert_eq!(
            results[0].as_deref(),
            Some(b"second".as_slice()),
            "the last put wins"
        );

        let mut batch = Batch::new();
        batch.put(b"other", b"doomed");
        batch.delete(b"other");
        store.write(batch).expect("memory writes are infallible");
        let results = store
            .read(&[b"other"])
            .expect("memory reads are infallible");
        assert_eq!(results[0], None, "a trailing delete removes the key");

        let mut batch = Batch::new();
        batch.delete(b"third");
        batch.put(b"third", b"kept");
        store.write(batch).expect("memory writes are infallible");
        let results = store
            .read(&[b"third"])
            .expect("memory reads are infallible");
        assert_eq!(
            results[0].as_deref(),
            Some(b"kept".as_slice()),
            "a put after a delete keeps the key"
        );
    }

    #[test]
    fn owned_batch_ops_write_runtime_built_keys_and_values() {
        let store = InMemoryStore::new();
        let runtime_key = vec![9, 8, 7];

        let mut batch = Batch::new();
        batch.put(runtime_key.as_slice(), b"borrowed-value");
        batch.put_owned(runtime_key.clone(), vec![1, 2, 3]);
        batch.put(b"static", b"static-value");
        store.write(batch).expect("memory writes are infallible");

        let results = store
            .read(&[runtime_key.as_slice(), b"static"])
            .expect("memory reads are infallible");
        assert_eq!(
            results[0].as_deref(),
            Some([1, 2, 3].as_slice()),
            "the owned put over the borrowed one wins"
        );
        assert_eq!(results[1].as_deref(), Some(b"static-value".as_slice()));

        let mut batch = Batch::new();
        batch.delete(runtime_key);
        store.write(batch).expect("memory writes are infallible");
        let results = store
            .read(&[&[9, 8, 7]])
            .expect("memory reads are infallible");
        assert_eq!(results[0], None, "the owned delete removes the key");
    }

    #[test]
    fn empty_batch_is_a_noop() {
        let store = InMemoryStore::new();
        assert!(Batch::new().is_empty(), "a fresh batch is empty");
        store
            .write(Batch::new())
            .expect("memory writes are infallible");
        let results = store
            .read(&[b"anything"])
            .expect("memory reads are infallible");
        assert_eq!(results[0], None, "an empty batch writes nothing");
    }

    #[test]
    fn clones_share_data_and_identity() {
        let store = InMemoryStore::new();
        let clone = store.clone();

        let mut batch = Batch::new();
        batch.put(b"shared", b"visible");
        clone.write(batch).expect("memory writes are infallible");

        let results = store
            .read(&[b"shared"])
            .expect("memory reads are infallible");
        assert_eq!(
            results[0].as_deref(),
            Some(b"visible".as_slice()),
            "clones share the map"
        );
        assert!(store.same_store(&clone), "clones report the same storage");
        assert!(clone.same_store(&store), "same_store is symmetric");

        let fresh = InMemoryStore::new();
        assert!(
            !store.same_store(&fresh),
            "independent stores are distinct storage"
        );
    }

    #[test]
    fn standalone_stores_are_isolated() {
        let first = InMemoryStore::new();
        let second = InMemoryStore::new();

        let mut batch = Batch::new();
        batch.put(b"key", b"first");
        first.write(batch).expect("memory writes are infallible");

        let results = second.read(&[b"key"]).expect("memory reads are infallible");
        assert_eq!(results[0], None, "standalone stores must not share data");
        assert!(
            !first.same_store(&second),
            "standalone stores are distinct storage"
        );
    }

    #[test]
    fn shared_stores_with_the_same_locator_share_data() {
        let first = InMemoryStore::shared("store-test-shared-same");
        let second = InMemoryStore::shared("store-test-shared-same");

        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        first.write(batch).expect("memory writes are infallible");

        let results = second.read(&[b"key"]).expect("memory reads are infallible");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "same-locator shared stores see the same data"
        );
        assert!(
            first.same_store(&second),
            "same-locator shared stores share storage"
        );

        let other = InMemoryStore::shared("store-test-shared-other");
        assert!(
            !first.same_store(&other),
            "different locators are different stores"
        );
        let results = other.read(&[b"key"]).expect("memory reads are infallible");
        assert_eq!(
            results[0], None,
            "other named stores must not see this data"
        );
    }

    #[test]
    fn standalone_and_shared_stores_do_not_collide() {
        let shared = InMemoryStore::shared("store-test-shared-vs-standalone");
        let standalone = InMemoryStore::new();

        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        shared.write(batch).expect("memory writes are infallible");

        let results = standalone
            .read(&[b"key"])
            .expect("memory reads are infallible");
        assert_eq!(
            results[0], None,
            "standalone stores live outside the registry"
        );
        assert!(!shared.same_store(&standalone));
    }

    #[test]
    fn shared_locator_round_trips_through_open() {
        let original = InMemoryStore::shared("store-test-open-roundtrip");

        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        original.write(batch).expect("memory writes are infallible");

        let locator = Retrievable::canonical_locator(&original);
        let reopened = InMemoryStore::open(&locator).expect("memory stores always open");
        assert_eq!(
            Retrievable::canonical_locator(&reopened),
            locator,
            "re-opening keeps the locator"
        );

        let results = reopened
            .read(&[b"key"])
            .expect("memory reads are infallible");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "open reattaches to the named data"
        );
        assert!(
            original.same_store(&reopened),
            "open resolves to the registered store"
        );
    }

    #[test]
    fn opening_an_unknown_locator_registers_a_fresh_store() {
        let locator = StoreLocator::from("store-test-open-unknown");
        let opened = InMemoryStore::open(&locator).expect("memory stores always open");
        let results = opened
            .read(&[b"seed"])
            .expect("memory reads are infallible");
        assert_eq!(results[0], None, "unknown locators start empty");

        let mut batch = Batch::new();
        batch.put(b"seed", b"planted");
        opened.write(batch).expect("memory writes are infallible");

        let joined = InMemoryStore::shared("store-test-open-unknown");
        let results = joined
            .read(&[b"seed"])
            .expect("memory reads are infallible");
        assert_eq!(
            results[0].as_deref(),
            Some(b"planted".as_slice()),
            "open must register the store under its locator name"
        );
        assert!(opened.same_store(&joined));
    }

    #[test]
    fn locators_reflect_the_construction_mode() {
        let standalone = InMemoryStore::new();
        assert_eq!(
            Store::locator(&standalone),
            Some(StoreLocator::from(Vec::new())),
            "standalone stores have an empty locator"
        );

        let shared = InMemoryStore::shared("store-test-locator-name");
        assert_eq!(
            Store::locator(&shared),
            Some(StoreLocator::from("store-test-locator-name")),
            "shared stores report their registered name"
        );
    }

    #[test]
    fn clear_removes_every_entry() {
        let store = InMemoryStore::new();
        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        store.write(batch).expect("memory writes are infallible");

        store.clear();
        let results = store.read(&[b"key"]).expect("memory reads are infallible");
        assert_eq!(results[0], None, "clear must empty the map");
    }

    #[test]
    fn memory_writes_are_infallible() {
        let store = InMemoryStore::new();
        let outcome: Result<(), core::convert::Infallible> = Store::write(&store, Batch::new());
        assert!(outcome.is_ok(), "the memory error type is Infallible");
    }
}

mod mmr_id {
    use core::str::FromStr;

    use accumulators::ids::{AccumulatorId, AccumulatorIdParseError, TreeId};

    #[test]
    fn display_is_lowercase_hex_and_reparses() {
        let id = AccumulatorId::from_bytes([
            0x00, 0x01, 0x0a, 0xff, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0,
            0xb0, 0xc0,
        ]);
        let text = id.to_string();
        assert_eq!(text.len(), 32, "16 bytes render as 32 hex characters");
        assert_eq!(text, text.to_lowercase(), "display is lowercase");
        assert_eq!(
            AccumulatorId::from_str(&text).expect("display output must reparse"),
            id
        );
    }

    #[test]
    fn uppercase_hex_parses_to_the_same_id() {
        let lower =
            AccumulatorId::from_str("000102030405060708090a0b0c0d0e0f").expect("lowercase parses");
        let upper =
            AccumulatorId::from_str("000102030405060708090A0B0C0D0E0F").expect("uppercase parses");
        assert_eq!(lower, upper, "hex parsing is case-insensitive");
    }

    #[test]
    fn wrong_length_is_rejected() {
        let error = AccumulatorId::from_str("00ff").expect_err("4 characters are not an id");
        assert_eq!(
            error,
            AccumulatorIdParseError::WrongLength(4),
            "the error carries the length"
        );
        assert!(matches!(
            AccumulatorId::from_str(""),
            Err(AccumulatorIdParseError::WrongLength(0))
        ));
    }

    #[test]
    fn non_hex_characters_are_rejected() {
        let error = AccumulatorId::from_str(&"g".repeat(32)).expect_err("'g' is not a hex digit");
        assert_eq!(error, AccumulatorIdParseError::BadHex);
    }

    #[test]
    fn zero_id_is_all_zeroes() {
        assert_eq!(AccumulatorId::ZERO.as_bytes(), &[0; 16]);
    }

    #[test]
    fn tree_id_encoding_round_trips() {
        let id = AccumulatorId::from_bytes([7; 16]);
        let mut encoded = Vec::new();
        id.encode_into(&mut encoded);
        assert_eq!(
            encoded.len(),
            16,
            "AccumulatorId encodes as its 16 raw bytes"
        );
        assert_eq!(<AccumulatorId as TreeId>::from_bytes(&encoded), Some(id));
        assert!(
            <AccumulatorId as TreeId>::from_bytes(&[0; 15]).is_none(),
            "short encodings are rejected"
        );
        assert!(
            <AccumulatorId as TreeId>::from_bytes(&[0; 17]).is_none(),
            "long encodings are rejected"
        );
    }

    #[cfg(feature = "uuid_v4")]
    #[test]
    fn random_v4_ids_are_unique() {
        assert_ne!(
            AccumulatorId::random_v4(),
            AccumulatorId::random_v4(),
            "v4 ids are random"
        );
        assert_ne!(AccumulatorId::random_v4(), AccumulatorId::ZERO);
    }

    #[cfg(all(feature = "uuid_v7", feature = "std"))]
    #[test]
    fn now_v7_ids_carry_the_version_and_are_unique() {
        let first = AccumulatorId::now_v7();
        let second = AccumulatorId::now_v7();
        assert_ne!(first, second, "v7 ids are time-generated");
        assert_eq!(
            first.as_bytes()[6] >> 4,
            7,
            "the version nibble (byte 6, high bits) marks uuid v7"
        );
    }

    #[cfg(all(feature = "ulid", feature = "std"))]
    #[test]
    fn ulid_ids_round_trip_their_bytes() {
        assert_ne!(
            AccumulatorId::generate_ulid(),
            AccumulatorId::generate_ulid(),
            "generated ulids are unique"
        );
        let ulid = ulid::Ulid::generate();
        assert_eq!(
            AccumulatorId::from_ulid(ulid).as_bytes(),
            &ulid.to_bytes(),
            "from_ulid keeps the 16 bytes"
        );
    }
}

#[cfg(all(feature = "sqlite", not(target_family = "wasm")))]
mod sqlite {
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use accumulators::store::sqlite::SqliteStore;
    use accumulators::store::{AsyncStore, Batch};

    static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);

    /// A unique file path per call so tests never share a database.
    fn temp_db_path(label: &str) -> PathBuf {
        let id = NEXT_DB_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "accumulators-store-{label}-{}-{id}.db",
            std::process::id()
        ))
    }

    /// Removes the database and its WAL/SHM sidecars, ignoring absence.
    fn cleanup_db(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let sidecar = format!("{}{suffix}", path.display());
            let _ = std::fs::remove_file(sidecar);
        }
    }

    #[tokio::test]
    async fn file_databases_round_trip_batched_writes() {
        let path = temp_db_path("roundtrip");
        let store = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");

        let mut batch = Batch::new();
        batch.put(b"alpha", &[0, 1, 2, 255]);
        batch.put(b"beta", b"value-2");
        store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");

        let keys: &[&[u8]] = &[b"beta", b"alpha", b"absent"];
        let results = store
            .read(keys)
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(results.len(), 3, "one result per requested key");
        assert_eq!(results[0].as_deref(), Some(b"value-2".as_slice()));
        assert_eq!(
            results[1].as_deref(),
            Some([0, 1, 2, 255].as_slice()),
            "binary values round-trip verbatim"
        );
        assert_eq!(results[2], None, "absent keys read back as None");

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn duplicate_read_keys_stay_positionally_aligned() {
        let path = temp_db_path("duplicates");
        let store = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");

        let mut batch = Batch::new();
        batch.put(b"dup", b"value");
        batch.put(b"other", b"value-2");
        store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");

        let keys: &[&[u8]] = &[b"dup", b"other", b"dup", b"dup", b"absent"];
        let results = store
            .read(keys)
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(results.len(), 5, "duplicate keys must not collapse results");
        for value in [
            results[0].as_deref(),
            results[2].as_deref(),
            results[3].as_deref(),
        ] {
            assert_eq!(
                value,
                Some(b"value".as_slice()),
                "every duplicate entry carries the value"
            );
        }
        assert_eq!(results[1].as_deref(), Some(b"value-2".as_slice()));
        assert_eq!(results[4], None);

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn read_with_no_keys_returns_no_results() {
        let path = temp_db_path("empty-read");
        let store = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");
        let results = store
            .read(&[])
            .await
            .expect("sqlite reads only fail on I/O");
        assert!(results.is_empty(), "no keys, no results");

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn batch_applies_puts_and_deletes_together() {
        let path = temp_db_path("batch");
        let store = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");

        let mut setup = Batch::new();
        setup.put(b"doomed", b"old");
        store
            .write(setup)
            .await
            .expect("sqlite writes only fail on I/O");

        let mut batch = Batch::new();
        batch.put(b"fresh", b"new");
        batch.delete(b"doomed");
        store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");

        let results = store
            .read(&[b"fresh", b"doomed"])
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(
            results[0].as_deref(),
            Some(b"new".as_slice()),
            "puts in the batch apply"
        );
        assert_eq!(results[1], None, "deletes in the batch apply");

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn later_batch_ops_override_earlier_ones() {
        let path = temp_db_path("override");
        let store = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");

        let mut batch = Batch::new();
        batch.put(b"key", b"first");
        batch.put(b"key", b"second");
        store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");
        let results = store
            .read(&[b"key"])
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(
            results[0].as_deref(),
            Some(b"second".as_slice()),
            "the last put wins"
        );

        let mut batch = Batch::new();
        batch.put(b"other", b"doomed");
        batch.delete(b"other");
        store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");
        let results = store
            .read(&[b"other"])
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(results[0], None, "a trailing delete removes the key");

        let mut batch = Batch::new();
        batch.delete(b"third");
        batch.put(b"third", b"kept");
        store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");
        let results = store
            .read(&[b"third"])
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(
            results[0].as_deref(),
            Some(b"kept".as_slice()),
            "a put after a delete keeps the key"
        );

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn empty_batch_write_succeeds() {
        let path = temp_db_path("empty-batch");
        let store = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");
        store
            .write(Batch::new())
            .await
            .expect("empty batches are a no-op");
        let results = store
            .read(&[b"anything"])
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(results[0], None, "an empty batch writes nothing");

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn cloned_handles_share_data_and_identity() {
        let path = temp_db_path("clone");
        let store = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");
        let clone = store.clone();

        let mut batch = Batch::new();
        batch.put(b"shared", b"value");
        clone
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");

        let results = store
            .read(&[b"shared"])
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "clones share the pool"
        );
        assert!(store.same_store(&clone), "clones report the same storage");

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn in_memory_databases_have_unique_locators() {
        // Data behavior is exercised on file databases: the pool fronts
        // several connections, and each `:memory:` connection owns a separate
        // database, so in-memory stores are only safe for single-connection
        // use. Locator semantics are connection-independent.
        let first = SqliteStore::in_memory()
            .await
            .expect("in-memory sqlite always opens");
        let second = SqliteStore::in_memory()
            .await
            .expect("in-memory sqlite always opens");

        let first_locator = AsyncStore::locator(&first).expect("in-memory databases have locators");
        let second_locator =
            AsyncStore::locator(&second).expect("in-memory databases have locators");
        assert_ne!(
            first_locator, second_locator,
            "in-memory databases cannot be re-opened, so their locators are unique"
        );
        assert!(
            !first.same_store(&second),
            "distinct in-memory databases are distinct storage"
        );
    }

    #[tokio::test]
    async fn file_databases_share_a_locator_across_connections() {
        let path = temp_db_path("locator");
        let first = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");
        let second = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");

        let first_locator = AsyncStore::locator(&first).expect("file databases have locators");
        let second_locator = AsyncStore::locator(&second).expect("file databases have locators");
        assert_eq!(
            first_locator, second_locator,
            "the locator is the database path"
        );
        assert!(
            first.same_store(&second),
            "same-path connections name the same storage"
        );

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn file_databases_persist_across_connections() {
        let path = temp_db_path("persist");
        {
            let store = SqliteStore::connect(&path)
                .await
                .expect("file sqlite opens");
            let mut batch = Batch::new();
            batch.put(b"durable", b"value");
            store
                .write(batch)
                .await
                .expect("sqlite writes only fail on I/O");
        }

        let reopened = SqliteStore::connect(&path)
            .await
            .expect("file sqlite re-opens");
        let results = reopened
            .read(&[b"durable"])
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "data survives dropping the handle"
        );

        cleanup_db(&path);
    }

    #[tokio::test]
    async fn open_async_reconnects_from_the_locator() {
        let path = temp_db_path("open-async");
        let original = SqliteStore::connect(&path)
            .await
            .expect("file sqlite opens");

        let mut batch = Batch::new();
        batch.put(b"key", b"value");
        original
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");
        let locator = AsyncStore::locator(&original).expect("file databases have locators");

        let reopened = SqliteStore::open_async(&locator)
            .await
            .expect("open_async re-opens the path");
        let results = reopened
            .read(&[b"key"])
            .await
            .expect("sqlite reads only fail on I/O");
        assert_eq!(
            results[0].as_deref(),
            Some(b"value".as_slice()),
            "open_async reattaches to the persisted data"
        );
        assert!(
            reopened.same_store(&original),
            "same-path stores are the same storage"
        );

        cleanup_db(&path);
    }
}
