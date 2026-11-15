//! Fault-injection tests for the atomicity + error-preservation contract:
//! a failed store write must leave NO partial batch behind —
//! counters, nodes and root move together or not at all — and the failure
//! must surface as a typed `Err`, never as `Ok`-garbage or a silently
//! truncated operation.
//!
//! The store atomicity contract (`store::mod` docs) is the hard requirement
//! these tests pin: an append persists nodes + counters + root in ONE batch,
//! so a partially-applied batch would corrupt every later proof. A wrapper
//! store that fails before delegating makes "the batch was not applied at
//! all" observable, and reopening the store after the failure proves the
//! persisted state stayed coherent.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(feature = "mmr", feature = "memory", feature = "keccak_sol"))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::KeccakSolHasher;
use accumulators::mmr::{Mmr, MmrError};
use accumulators::primitives::LeafIndex;
use accumulators::store::Store;
use accumulators::store::keys::{self, Table};
use accumulators::store::memory::InMemoryStore;

use common::{FaultError, FaultyStore, TempDb, reference_root};

type FaultyMmr = Mmr<KeccakSolHasher, FaultyStore<InMemoryStore>>;
type FaultyError = MmrError<FaultyStore<InMemoryStore>>;

fn id(byte: u8) -> accumulators::ids::AccumulatorId {
    common::id(byte)
}

fn element(index: u64) -> Vec<u8> {
    common::element(index)
}

/// Reads a single-subkey record straight from the wrapped (healthy) store —
/// the honest way to observe what the MMR actually persisted.
fn stored_counter(
    store: &InMemoryStore,
    id: accumulators::ids::AccumulatorId,
    table: Table,
) -> u64 {
    let key = keys::encode(&id, table, 0);
    let value = store
        .read(&[&key])
        .expect("in-memory reads are infallible")
        .pop()
        .flatten()
        .unwrap_or_else(|| panic!("the {table:?} record exists"));
    u64::from_be_bytes(value.as_slice().try_into().expect("counters are 8 bytes"))
}

fn expect_injected(error: &FaultyError) {
    match error {
        FaultyError::Store(FaultError::Injected(_)) => {}
        other => panic!("expected the injected store failure, got {other:?}"),
    }
}

// ------------------------------------------------------------ failed writes

mod failed_writes {
    use super::*;

    /// Contract: a single `append` is ONE batch write at the store boundary
    /// (the batching contract, observed from the fault wrapper), and when
    /// that write fails nothing is persisted and the handle's cached state is
    /// untouched. The regression this catches: an append that mutates the
    /// handle state (or the store counters) *before* the write, leaving a
    /// handle that disagrees with its own store.
    #[test]
    fn a_failed_append_persists_nothing_and_keeps_the_handle_consistent() {
        let h = KeccakSolHasher;
        let store = FaultyStore::new(InMemoryStore::new());
        let mut mmr = FaultyMmr::create(h, store.clone(), id(1)).expect("create");
        for el in common::elements(3) {
            mmr.append(&el).expect("append must succeed");
        }
        let root_before = mmr.root();
        let count_before = mmr.leaf_count();

        store.fault().fail_writes(true);
        match mmr.append(b"doomed") {
            Err(error) => expect_injected(&error),
            Ok(outcome) => panic!("the failed append must not succeed, got {outcome:?}"),
        }

        // Handle state: untouched — the append is all-or-nothing.
        assert_eq!(mmr.leaf_count(), count_before, "no phantom leaf");
        assert_eq!(mmr.root(), root_before, "no phantom root");

        // Store state: the one batch that failed wrote nothing at all — the
        // counters (and by the atomicity contract every other record in that
        // batch) are exactly where they were.
        assert_eq!(
            stored_counter(store.inner(), id(1), Table::LeafCount),
            3,
            "the leaf counter must not move on a failed append"
        );
        assert_eq!(
            stored_counter(store.inner(), id(1), Table::NodeCount),
            4,
            "the node counter must not move on a failed append"
        );
        assert_eq!(
            store.fault().write_calls(),
            5,
            "one write call per append (create + 3 seed appends + 1 failed), never more"
        );

        // Reopen is coherent with the pre-failure state, and a retry after
        // the fault clears lands exactly on the reference root.
        store.fault().fail_writes(false);
        let mut reopened = FaultyMmr::open(h, store, id(1)).expect("reopen");
        assert_eq!(reopened.root(), root_before, "the store stayed coherent");
        reopened.append(b"retry").expect("the retry succeeds");
        let mut all = common::elements(3);
        all.push(b"retry".to_vec());
        assert_eq!(
            reopened.root(),
            reference_root(&h, &common::slices(&all)),
            "the recovered append tracks the reference"
        );
    }

    /// Contract: `append_batch` is one atomic write for N elements — a
    /// failure must not leave "some of the batch" in the store.
    #[test]
    fn a_failed_batch_append_leaves_no_partial_batch() {
        let h = KeccakSolHasher;
        let store = FaultyStore::new(InMemoryStore::new());
        let mut mmr = FaultyMmr::create(h, store.clone(), id(1)).expect("create");
        mmr.append(b"seed").expect("append must succeed");

        store.fault().fail_writes(true);
        let elements: Vec<Vec<u8>> = (0..5).map(element).collect();
        match mmr.append_batch(&common::slices(&elements)) {
            Err(error) => expect_injected(&error),
            Ok(outcome) => panic!("the failed batch must not succeed, got {outcome:?}"),
        }
        assert_eq!(mmr.leaf_count().get(), 1, "a failed batch appends nothing");
        assert_eq!(
            stored_counter(store.inner(), id(1), Table::LeafCount),
            1,
            "no partial batch may persist"
        );
    }

    /// Contract: a failed *edit* must not corrupt the edit path either — the
    /// batch carrying the rewritten path is atomic, and the root stays at the
    /// pre-edit value.
    #[test]
    fn a_failed_edit_leaves_the_root_unchanged() {
        type FaultyEdit = Mmr<
            KeccakSolHasher,
            FaultyStore<InMemoryStore>,
            accumulators::mmr::Plain,
            accumulators::mmr::Editable,
        >;
        let h = KeccakSolHasher;
        let store = FaultyStore::new(InMemoryStore::new());
        let mut mmr = FaultyEdit::create_editable(h, store.clone(), id(1)).expect("create");
        for el in common::elements(4) {
            mmr.append(&el).expect("append must succeed");
        }
        let root_before = mmr.root();

        store.fault().fail_writes(true);
        match mmr.update(LeafIndex::new(1), b"doomed", None) {
            Err(error) => expect_injected(&error),
            Ok(outcome) => panic!("the failed edit must not succeed, got {outcome:?}"),
        }
        assert_eq!(
            mmr.root(),
            root_before,
            "a failed edit must not move the root"
        );
        assert_eq!(
            mmr.leaf_hash(LeafIndex::new(1)).expect("read"),
            Some(accumulators::hashers::Hasher::hash_leaf(&h, &common::element(1)).expect("hash")),
            "the leaf keeps its pre-edit value"
        );
    }
}

// ------------------------------------------------------------- failed reads

mod failed_reads {
    use super::*;

    /// Contract: read failures surface as typed `Err(Store)` —
    /// never as `Ok` with garbage inside, never as a silent `None` masquerade.
    /// The regression this catches: a read path that maps an I/O error to
    /// "record absent" (e.g. via `unwrap_or_default`) would issue a
    /// wrong proof instead of refusing.
    #[test]
    fn read_failures_are_typed_errors_never_ok_garbage() {
        let h = KeccakSolHasher;
        let store = FaultyStore::new(InMemoryStore::new());
        let mut mmr = FaultyMmr::create(h, store.clone(), id(1)).expect("create");
        for el in common::elements(8) {
            mmr.append(&el).expect("append must succeed");
        }

        store.fault().fail_reads(true);
        match mmr.proof(LeafIndex::new(3)) {
            Err(FaultyError::Store(FaultError::Injected(_))) => {}
            other => panic!("proof must fail as a store error, got {other:?}"),
        }
        match mmr.leaf_hash(LeafIndex::new(3)) {
            Err(FaultyError::Store(FaultError::Injected(_))) => {}
            other => panic!("leaf_hash must fail as a store error, got {other:?}"),
        }
        match mmr.multiproof([LeafIndex::new(1), LeafIndex::new(4)]) {
            Err(FaultyError::Store(FaultError::Injected(_))) => {}
            other => panic!("multiproof must fail as a store error, got {other:?}"),
        }
        // Appends never read; a read fault must not wedge them either.
        store.fault().fail_reads(false);
        mmr.append(b"still-works").expect("append after read fault");
    }

    /// The read error is *preserved*: it chains to the injected mock error
    /// (the `#[source]` of `MmrError::Store`), so diagnostics never lose the
    /// backend failure.
    #[test]
    fn the_store_error_is_preserved_as_the_source() {
        let h = KeccakSolHasher;
        let store = FaultyStore::new(InMemoryStore::new());
        let mut mmr = FaultyMmr::create(h, store.clone(), id(1)).expect("create");
        mmr.append(b"only").expect("append must succeed");
        store.fault().fail_reads(true);
        let error = mmr.proof(LeafIndex::FIRST).expect_err("read fault");
        let source = std::error::Error::source(&error).expect("the source is preserved");
        assert!(
            source.is::<FaultError<core::convert::Infallible>>(),
            "the injected failure must survive as the error source, got {source}"
        );
    }
}

// ------------------------------------------------------- async sqlite twins

#[cfg(all(feature = "sqlite", not(target_family = "wasm")))]
mod async_sqlite {
    use super::*;
    use accumulators::mmr::AsyncMmr;
    use accumulators::store::sqlite::SqliteStore;

    type AsyncFaultyMmr = AsyncMmr<KeccakSolHasher, FaultyStore<SqliteStore>>;
    type AsyncFaultyError = MmrError<FaultyStore<SqliteStore>>;

    /// The async twin: a sqlite write failure injected *before delegating*
    /// (the wrapper never reaches the transaction) leaves no partial rows in
    /// the database — the async shell must behave exactly like the sync one.
    #[tokio::test]
    async fn a_failed_async_append_persists_nothing_and_the_reopen_is_coherent() {
        let h = KeccakSolHasher;
        let db = TempDb::new("atomicity");
        let inner = SqliteStore::connect(db.path()).await.expect("opens");
        let store = FaultyStore::new(inner.clone());
        let mut mmr = AsyncFaultyMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");
        for el in common::elements(3) {
            mmr.append(&el).await.expect("append must succeed");
        }
        let root_before = mmr.root();

        store.fault().fail_writes(true);
        match mmr.append(b"doomed").await {
            Err(AsyncFaultyError::Store(FaultError::Injected(_))) => {}
            other => panic!("expected the injected failure, got {other:?}"),
        }
        assert_eq!(
            mmr.leaf_count().get(),
            3,
            "the async handle must not move on a failed append"
        );
        let key = keys::encode(&id(1), Table::LeafCount, 0);
        let rows = accumulators::store::AsyncStore::read(&inner, &[&key])
            .await
            .expect("sqlite reads only fail on I/O");
        let value = rows[0].as_deref().expect("the leaf counter record exists");
        assert_eq!(
            u64::from_be_bytes(value.try_into().expect("counters are 8 bytes")),
            3,
            "no partial rows may reach sqlite"
        );
        assert_eq!(
            store.fault().write_calls(),
            5,
            "one write per append (create + 3 appends + 1 failed)"
        );

        // The persisted database re-opens coherent with the pre-failure
        // state; the retry after the fault clears lands on the reference.
        store.fault().fail_writes(false);
        let mut reopened = AsyncFaultyMmr::open(
            h,
            FaultyStore::new(SqliteStore::connect(db.path()).await.expect("opens")),
            id(1),
        )
        .await
        .expect("reopen");
        assert_eq!(reopened.root(), root_before, "the database stayed coherent");
        reopened.append(b"retry").await.expect("the retry succeeds");
        let mut all = common::elements(3);
        all.push(b"retry".to_vec());
        assert_eq!(
            reopened.root(),
            reference_root(&h, &common::slices(&all)),
            "the recovered append tracks the reference"
        );
    }

    /// Async read failures are typed errors too — never an empty-result
    /// masquerade.
    #[tokio::test]
    async fn async_read_failures_are_typed_errors() {
        let h = KeccakSolHasher;
        let db = TempDb::new("atomicity-reads");
        let store = FaultyStore::new(SqliteStore::connect(db.path()).await.expect("opens"));
        let mut mmr = AsyncFaultyMmr::create(h, store.clone(), id(1))
            .await
            .expect("create");
        for el in common::elements(4) {
            mmr.append(&el).await.expect("append must succeed");
        }

        store.fault().fail_reads(true);
        match mmr.proof(LeafIndex::new(2)).await {
            Err(AsyncFaultyError::Store(FaultError::Injected(_))) => {}
            other => panic!("proof must fail as a store error, got {other:?}"),
        }
        match mmr.leaf_hash(LeafIndex::new(2)).await {
            Err(AsyncFaultyError::Store(FaultError::Injected(_))) => {}
            other => panic!("leaf_hash must fail as a store error, got {other:?}"),
        }
    }
}
