//! Behavior tests for the storage layer: the binary key layout,
//! `AccumulatorId`, the in-memory reference backend, the SQLite backend on
//! native targets, and the backend-agnostic conformance suite
//! ([`conformance`]) that both backends satisfy.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#[path = "../common/mod.rs"]
mod common;

mod conformance;

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

    /// An id that encodes past the 255-byte wire bound — encode must panic
    /// instead of truncating (silent truncation would alias keyspaces
    /// across accumulators).
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    struct OverlongId;

    impl TreeId for OverlongId {
        fn encode_into(&self, out: &mut Vec<u8>) {
            out.extend_from_slice(&[0u8; 256]);
        }

        fn from_bytes(bytes: &[u8]) -> Option<Self> {
            if bytes.len() == 256 { Some(Self) } else { None }
        }
    }

    #[test]
    #[should_panic(expected = "caps ids at 255")]
    fn encoding_an_id_past_the_wire_bound_panics() {
        let _ = keys::encode(&OverlongId, Table::Nodes, 0);
    }

    #[test]
    fn encoded_keys_follow_the_wire_layout() {
        let id = AccumulatorId::from_bytes([0xab; 16]);
        // A subkey whose byte pattern is asymmetric so the endianness of the
        // trailing 8 bytes is observable, not just their length.
        let subkey = 0x0102_0304_0506_0708;
        let key = keys::encode(&id, Table::Nodes, subkey);
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
        assert_eq!(
            &key[18..],
            &subkey.to_be_bytes(),
            "the subkey is big-endian"
        );
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

    /// The unassigned-tag half of the wire-tag contract: anything outside the
    /// assigned discriminants must decode as foreign. (The assigned half is
    /// owned by `encode_decode_round_trips_every_table_and_subkey` and the
    /// discriminant declarations themselves — a `from_repr(tag) == tag` loop
    /// over the same enum would only compare the subject with itself.)
    #[test]
    fn unassigned_table_tags_are_foreign() {
        for tag in [11u8, 64, 200, 255] {
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
    use accumulators::store::{Retrievable, Store, StoreLocator};

    #[test]
    fn clones_share_data_and_identity() {
        let store = InMemoryStore::new();
        let clone = store.clone();

        let mut batch = accumulators::store::Batch::new();
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

        let mut batch = accumulators::store::Batch::new();
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

        let mut batch = accumulators::store::Batch::new();
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

        let mut batch = accumulators::store::Batch::new();
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

        let mut batch = accumulators::store::Batch::new();
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

        let mut batch = accumulators::store::Batch::new();
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
        // A standalone store is session-local: no locator at all (an empty
        // locator would violate canonical-locator equality — every
        // standalone store would collide on it).
        let standalone = InMemoryStore::new();
        assert_eq!(
            Store::locator(&standalone),
            None,
            "standalone stores have no locator"
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
        let mut batch = accumulators::store::Batch::new();
        batch.put(b"key", b"value");
        store.write(batch).expect("memory writes are infallible");

        store.clear();
        let results = store.read(&[b"key"]).expect("memory reads are infallible");
        assert_eq!(results[0], None, "clear must empty the map");
    }

    #[test]
    fn memory_writes_are_infallible() {
        let store = InMemoryStore::new();
        let outcome: Result<(), core::convert::Infallible> =
            Store::write(&store, accumulators::store::Batch::new());
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
    use accumulators::store::sqlite::SqliteStore;
    use accumulators::store::{AsyncStore, Batch, StoreLocator};

    use crate::common::TempDb;

    #[tokio::test]
    async fn cloned_handles_share_data_and_identity() {
        let db = TempDb::new("clone");
        let store = SqliteStore::connect(db.path())
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
        let db = TempDb::new("locator");
        let first = SqliteStore::connect(db.path())
            .await
            .expect("file sqlite opens");
        let second = SqliteStore::connect(db.path())
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
    }

    #[tokio::test]
    async fn file_databases_persist_across_connections() {
        let db = TempDb::new("persist");
        {
            let store = SqliteStore::connect(db.path())
                .await
                .expect("file sqlite opens");
            let mut batch = Batch::new();
            batch.put(b"durable", b"value");
            store
                .write(batch)
                .await
                .expect("sqlite writes only fail on I/O");
        }

        let reopened = SqliteStore::connect(db.path())
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
    }

    #[tokio::test]
    async fn open_async_reconnects_from_the_locator() {
        let db = TempDb::new("open-async");
        let original = SqliteStore::connect(db.path())
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
    }

    /// Locators are the raw OS path bytes. A non-UTF-8 locator is rejected
    /// by the backend (SQLite requires UTF-8 filenames) rather than lossily
    /// fabricated into a wrong file — the locator round trip never invents
    /// bytes.
    #[tokio::test]
    async fn non_utf8_locators_fail_closed_instead_of_fabricating_a_path() {
        // The raw-byte locator contract: the bytes are the exact OS path.
        let db = TempDb::new("raw-bytes");
        let original = SqliteStore::connect(db.path())
            .await
            .expect("file sqlite opens");
        let locator = AsyncStore::locator(&original).expect("file databases have locators");
        assert_eq!(
            locator.as_bytes(),
            db.path().as_os_str().as_encoded_bytes(),
            "the locator is the raw OS path, never a lossy string"
        );
        drop(original);

        // A non-UTF-8 locator cannot become a lossy path: the backend
        // rejects it, it does not silently open something else.
        let mut forged = b"accumulators-store-".to_vec();
        forged.extend_from_slice(&[0xff, 0xfe, b'.', b'd', b'b']);
        let forged_locator = StoreLocator::from_bytes(forged);
        assert!(
            SqliteStore::open_async(&forged_locator).await.is_err(),
            "a non-utf8 locator must fail closed"
        );
    }

    /// `:memory:` detection is an exact match: a file with `:memory:` inside
    /// its name is a real, re-openable file — not a database alias.
    #[tokio::test]
    async fn a_path_containing_memory_marker_is_a_real_file() {
        let db = TempDb::new("inner-memory");
        // Build a path that embeds the `:memory:` marker inside the file name.
        let marker_path = db.path().with_file_name(format!(
            "prefix:memory:{}",
            db.path()
                .file_name()
                .and_then(|n| n.to_str())
                .expect("utf8 name")
        ));

        let original = SqliteStore::connect(&marker_path)
            .await
            .expect("opens as a file database");
        let locator = AsyncStore::locator(&original).expect("file databases have locators");
        assert!(
            !locator.as_bytes().starts_with(b"memory:"),
            "a file containing the marker keeps its path locator"
        );

        let reopened = SqliteStore::open_async(&locator)
            .await
            .expect("the file is re-openable");
        assert!(
            reopened.same_store(&original),
            "the marker-bearing file behaves like any file database"
        );

        // The marker file lives outside the guard's path — clean it up here.
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", marker_path.display()));
        }
    }

    /// In-memory locators are synthetic ids — `open_async` rejects them
    /// instead of silently fabricating a *file* named `memory:…`.
    #[tokio::test]
    async fn open_async_rejects_memory_locators() {
        let store = SqliteStore::in_memory()
            .await
            .expect("in-memory sqlite opens");
        let locator =
            AsyncStore::locator(&store).expect("in-memory stores carry a synthetic locator");
        assert!(
            locator.as_bytes().starts_with(b"memory:"),
            "in-memory locators are synthetic `memory:` ids"
        );

        match SqliteStore::open_async(&locator).await {
            Err(_) => {}
            Ok(_) => panic!("a memory: locator must not fabricate a file"),
        }
    }
}
