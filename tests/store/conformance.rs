//! The store conformance suite: the backend-agnostic contract every pluggable
//! store must satisfy — positional reads plus atomic
//! multi-key writes — generic over `Store` with an async twin over
//! `AsyncStore`. Each concrete backend calls the suite exactly once, so a new
//! backend inherits the whole contract with one call.
//!
//! The error-preservation variant takes the fault seam from
//! `common::FaultyStore`: the fault fires in the wrapper *before* the backend
//! is reached, so it pins the MMR-side contract (typed errors, untouched
//! handle state) — not backend transactional atomicity. Backends without a
//! fault seam don't call it. The backend-internal fault seams (a failure
//! firing inside the backend's own transaction) live with the backends that
//! can express one: the `sqlite_backend` module below and `store_redb.rs`.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
use accumulators::store::{AsyncStore, Batch, Store};

use crate::common::FaultyStore;

/// Unique key namespace per check so suites over shared stores never collide.
fn key(prefix: &str, name: &[u8]) -> Vec<u8> {
    let mut out = prefix.as_bytes().to_vec();
    out.push(b'/');
    out.extend_from_slice(name);
    out
}

// ------------------------------------------------------------------ sync core

pub fn positional_reads<S: Store>(store: &S) {
    let mut batch = Batch::new();
    let conf_pos_b_alpha = key("conf-pos", b"alpha");
    batch.put(&conf_pos_b_alpha, b"value-1");
    let conf_pos_b_beta = key("conf-pos", b"beta");
    batch.put(&conf_pos_b_beta, b"value-2");
    let conf_pos_b_gamma = key("conf-pos", b"gamma");
    batch.put(&conf_pos_b_gamma, b"value-3");
    store.write(batch).expect("write succeeds");

    let alpha = key("conf-pos", b"alpha");
    let beta = key("conf-pos", b"beta");
    let absent = key("conf-pos", b"absent");
    let keys: &[&[u8]] = &[&beta, &absent, &alpha, &alpha];
    let results = store.read(keys).expect("read succeeds");
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

pub fn empty_key_list<S: Store>(store: &S) {
    let results = store.read(&[]).expect("read succeeds");
    assert!(results.is_empty(), "no keys, no results");
}

pub fn put_delete_batch<S: Store>(store: &S) {
    let mut setup = Batch::new();
    let conf_putdel_b_doomed = key("conf-putdel", b"doomed");
    setup.put(&conf_putdel_b_doomed, b"old");
    store.write(setup).expect("write succeeds");

    let mut batch = Batch::new();
    let conf_putdel_b_fresh = key("conf-putdel", b"fresh");
    batch.put(&conf_putdel_b_fresh, b"new");
    let conf_putdel_b_doomed = key("conf-putdel", b"doomed");
    batch.delete(&conf_putdel_b_doomed);
    store.write(batch).expect("write succeeds");

    let fresh = key("conf-putdel", b"fresh");
    let doomed = key("conf-putdel", b"doomed");
    let results = store.read(&[&fresh, &doomed]).expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"new".as_slice()),
        "puts in the batch apply"
    );
    assert_eq!(results[1], None, "deletes in the batch apply");
}

pub fn last_op_wins<S: Store>(store: &S) {
    let k = key("conf-last", b"key");
    let mut batch = Batch::new();
    batch.put(&k, b"first");
    batch.put(&k, b"second");
    store.write(batch).expect("write succeeds");
    let results = store.read(&[&k]).expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"second".as_slice()),
        "the last put wins"
    );

    let other = key("conf-last", b"other");
    let mut batch = Batch::new();
    batch.put(&other, b"doomed");
    batch.delete(&other);
    store.write(batch).expect("write succeeds");
    let results = store.read(&[&other]).expect("read succeeds");
    assert_eq!(results[0], None, "a trailing delete removes the key");

    let third = key("conf-last", b"third");
    let mut batch = Batch::new();
    batch.delete(&third);
    batch.put(&third, b"kept");
    store.write(batch).expect("write succeeds");
    let results = store.read(&[&third]).expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"kept".as_slice()),
        "a put after a delete keeps the key"
    );
}

pub fn empty_batch<S: Store>(store: &S) {
    assert!(Batch::new().is_empty(), "a fresh batch is empty");
    store.write(Batch::new()).expect("write succeeds");
    let anything = key("conf-empty", b"anything");
    let results = store.read(&[&anything]).expect("read succeeds");
    assert_eq!(results[0], None, "an empty batch writes nothing");
}

pub fn duplicate_keys_alignment<S: Store>(store: &S) {
    let dup = key("conf-dup", b"dup");
    let other = key("conf-dup", b"other");
    let mut batch = Batch::new();
    batch.put(&dup, b"value");
    batch.put(&other, b"value-2");
    store.write(batch).expect("write succeeds");

    let absent = key("conf-dup", b"absent");
    let keys: &[&[u8]] = &[&dup, &other, &dup, &dup, &absent];
    let results = store.read(keys).expect("read succeeds");
    assert_eq!(results.len(), 5, "duplicate keys must not collapse results");
    for value in [
        results[0].as_deref(),
        results[2].as_deref(),
        results[3].as_deref(),
    ] {
        assert_eq!(value, Some(b"value".as_slice()));
    }
    assert_eq!(results[1].as_deref(), Some(b"value-2".as_slice()));
    assert_eq!(results[4], None);
}

pub fn owned_ops<S: Store>(store: &S) {
    let runtime_key = key("conf-owned", b"runtime");
    let mut batch = Batch::new();
    batch.put(runtime_key.as_slice(), b"borrowed-value");
    batch.put_owned(runtime_key.clone(), vec![1, 2, 3]);
    let conf_owned_b_static = key("conf-owned", b"static");
    batch.put(&conf_owned_b_static, b"static-value");
    store.write(batch).expect("write succeeds");

    let static_key = key("conf-owned", b"static");
    let results = store
        .read(&[runtime_key.as_slice(), &static_key])
        .expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some([1, 2, 3].as_slice()),
        "the owned put over the borrowed one wins"
    );
    assert_eq!(results[1].as_deref(), Some(b"static-value".as_slice()));

    let mut batch = Batch::new();
    batch.delete(runtime_key);
    store.write(batch).expect("write succeeds");
    let results = store
        .read(&[&key("conf-owned", b"runtime")])
        .expect("read succeeds");
    assert_eq!(results[0], None, "the owned delete removes the key");
}

/// The wrapper-level error-preservation contract over the fault seam:
/// the fault fires in the [`FaultyStore`] wrapper **before the backend is
/// reached**, so this asserts the MMR-side contract — a failed write must
/// surface as a typed error and a retry after the fault clears succeeds.
/// (The untouched-store assertions here hold trivially: the backend never
/// saw the batch.) Each backend's *internal* transactional atomicity — a
/// fault firing inside the backend's own write — is covered by the
/// backend-specific in-backend tests (`sqlite_backend` module below,
/// `store_redb.rs`).
pub fn error_preservation_before_backend<S: Store>(store: &FaultyStore<S>) {
    let kept = key("conf-fault", b"kept");
    let mut batch = Batch::new();
    batch.put(&kept, b"before");
    store.write(batch).expect("the initial write succeeds");

    store.fault().fail_writes(true);
    let rejected = key("conf-fault", b"rejected");
    let mut batch = Batch::new();
    batch.put(&rejected, b"must-not-land");
    batch.put(&kept, b"must-not-overwrite");
    match store.write(batch) {
        Err(error) => assert!(matches!(error, crate::common::FaultError::Injected(_))),
        Ok(()) => panic!("the injected write failure must surface"),
    }

    // The failed batch left no trace: the old value survives, the new key
    // does not exist.
    let results = store.read(&[&kept, &rejected]).expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"before".as_slice()),
        "a failed batch must not partially apply"
    );
    assert_eq!(results[1], None, "the failed put must not land");

    store.fault().fail_writes(false);
    let mut batch = Batch::new();
    batch.put(&kept, b"after");
    store.write(batch).expect("the retry succeeds");
    let results = store.read(&[&kept]).expect("read succeeds");
    assert_eq!(results[0].as_deref(), Some(b"after".as_slice()));

    // Failed reads are typed errors, never Ok-garbage.
    store.fault().fail_reads(true);
    match store.read(&[&kept]) {
        Err(error) => assert!(matches!(error, crate::common::FaultError::Injected(_))),
        Ok(results) => panic!("the injected read failure must surface, got {results:?}"),
    }
    store.fault().fail_reads(false);
    let results = store.read(&[&kept]).expect("read succeeds");
    assert_eq!(results[0].as_deref(), Some(b"after".as_slice()));
}

// ----------------------------------------------------------------- async core

pub async fn positional_reads_async<S: AsyncStore>(store: &S) {
    let mut batch = Batch::new();
    let aconfl_pos_b_alpha = key("aconfl-pos", b"alpha");
    batch.put(&aconfl_pos_b_alpha, b"value-1");
    let aconfl_pos_b_beta = key("aconfl-pos", b"beta");
    batch.put(&aconfl_pos_b_beta, b"value-2");
    store.write(batch).await.expect("write succeeds");

    let alpha = key("aconfl-pos", b"alpha");
    let absent = key("aconfl-pos", b"absent");
    let results = store
        .read(&[&alpha, &absent, &alpha])
        .await
        .expect("read succeeds");
    assert_eq!(results.len(), 3, "one result per requested key");
    assert_eq!(results[0].as_deref(), Some(b"value-1".as_slice()));
    assert_eq!(results[1], None, "absent keys read back as None");
    assert_eq!(results[2].as_deref(), Some(b"value-1".as_slice()));
}

pub async fn empty_key_list_async<S: AsyncStore>(store: &S) {
    let results = store.read(&[]).await.expect("read succeeds");
    assert!(results.is_empty(), "no keys, no results");
}

pub async fn put_delete_batch_async<S: AsyncStore>(store: &S) {
    let mut setup = Batch::new();
    let aconfl_putdel_b_doomed = key("aconfl-putdel", b"doomed");
    setup.put(&aconfl_putdel_b_doomed, b"old");
    store.write(setup).await.expect("write succeeds");

    let mut batch = Batch::new();
    let aconfl_putdel_b_fresh = key("aconfl-putdel", b"fresh");
    batch.put(&aconfl_putdel_b_fresh, b"new");
    let aconfl_putdel_b_doomed = key("aconfl-putdel", b"doomed");
    batch.delete(&aconfl_putdel_b_doomed);
    store.write(batch).await.expect("write succeeds");

    let fresh = key("aconfl-putdel", b"fresh");
    let doomed = key("aconfl-putdel", b"doomed");
    let results = store.read(&[&fresh, &doomed]).await.expect("read succeeds");
    assert_eq!(results[0].as_deref(), Some(b"new".as_slice()));
    assert_eq!(results[1], None, "deletes in the batch apply");
}

pub async fn last_op_wins_async<S: AsyncStore>(store: &S) {
    let k = key("aconfl-last", b"key");
    let mut batch = Batch::new();
    batch.put(&k, b"first");
    batch.put(&k, b"second");
    store.write(batch).await.expect("write succeeds");
    let results = store.read(&[&k]).await.expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"second".as_slice()),
        "the last put wins"
    );

    let other = key("aconfl-last", b"other");
    let mut batch = Batch::new();
    batch.put(&other, b"doomed");
    batch.delete(&other);
    store.write(batch).await.expect("write succeeds");
    let results = store.read(&[&other]).await.expect("read succeeds");
    assert_eq!(results[0], None, "a trailing delete removes the key");

    let third = key("aconfl-last", b"third");
    let mut batch = Batch::new();
    batch.delete(&third);
    batch.put(&third, b"kept");
    store.write(batch).await.expect("write succeeds");
    let results = store.read(&[&third]).await.expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"kept".as_slice()),
        "a put after a delete keeps the key"
    );
}

pub async fn empty_batch_async<S: AsyncStore>(store: &S) {
    store.write(Batch::new()).await.expect("write succeeds");
    let anything = key("aconfl-empty", b"anything");
    let results = store.read(&[&anything]).await.expect("read succeeds");
    assert_eq!(results[0], None, "an empty batch writes nothing");
}

pub async fn duplicate_keys_alignment_async<S: AsyncStore>(store: &S) {
    let dup = key("aconfl-dup", b"dup");
    let other = key("aconfl-dup", b"other");
    let mut batch = Batch::new();
    batch.put(&dup, b"value");
    batch.put(&other, b"value-2");
    store.write(batch).await.expect("write succeeds");

    let absent = key("aconfl-dup", b"absent");
    let keys: &[&[u8]] = &[&dup, &other, &dup, &dup, &absent];
    let results = store.read(keys).await.expect("read succeeds");
    assert_eq!(results.len(), 5, "duplicates must not collapse results");
    for value in [
        results[0].as_deref(),
        results[2].as_deref(),
        results[3].as_deref(),
    ] {
        assert_eq!(value, Some(b"value".as_slice()));
    }
    assert_eq!(results[1].as_deref(), Some(b"value-2".as_slice()));
    assert_eq!(results[4], None);
}

pub async fn owned_ops_async<S: AsyncStore>(store: &S) {
    let runtime_key = key("aconfl-owned", b"runtime");
    let mut batch = Batch::new();
    batch.put(runtime_key.as_slice(), b"borrowed-value");
    batch.put_owned(runtime_key.clone(), vec![1, 2, 3]);
    store.write(batch).await.expect("write succeeds");

    let results = store
        .read(&[runtime_key.as_slice()])
        .await
        .expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some([1, 2, 3].as_slice()),
        "the owned put wins and binary values round-trip verbatim"
    );

    let mut batch = Batch::new();
    batch.delete(runtime_key);
    store.write(batch).await.expect("write succeeds");
    let results = store
        .read(&[&key("aconfl-owned", b"runtime")])
        .await
        .expect("read succeeds");
    assert_eq!(results[0], None, "the owned delete removes the key");
}

/// The async twin of [`error_preservation_before_backend`]: the fault fires
/// in the wrapper before the backend is reached; backend-internal atomicity
/// is covered by the backend-specific in-backend tests.
pub async fn error_preservation_before_backend_async<S: AsyncStore + Send + Sync>(
    store: &FaultyStore<S>,
) {
    let kept = key("aconfl-fault", b"kept");
    let mut batch = Batch::new();
    batch.put(&kept, b"before");
    store
        .write(batch)
        .await
        .expect("the initial write succeeds");

    store.fault().fail_writes(true);
    let rejected = key("aconfl-fault", b"rejected");
    let mut batch = Batch::new();
    batch.put(&rejected, b"must-not-land");
    batch.put(&kept, b"must-not-overwrite");
    match store.write(batch).await {
        Err(error) => assert!(matches!(error, crate::common::FaultError::Injected(_))),
        Ok(()) => panic!("the injected write failure must surface"),
    }

    let results = store
        .read(&[&kept, &rejected])
        .await
        .expect("read succeeds");
    assert_eq!(
        results[0].as_deref(),
        Some(b"before".as_slice()),
        "a failed batch must not partially apply"
    );
    assert_eq!(results[1], None, "the failed put must not land");

    store.fault().fail_writes(false);
    let mut batch = Batch::new();
    batch.put(&kept, b"after");
    store.write(batch).await.expect("the retry succeeds");
    let results = store.read(&[&kept]).await.expect("read succeeds");
    assert_eq!(results[0].as_deref(), Some(b"after".as_slice()));

    store.fault().fail_reads(true);
    match store.read(&[&kept]).await {
        Err(error) => assert!(matches!(error, crate::common::FaultError::Injected(_))),
        Ok(results) => panic!("the injected read failure must surface, got {results:?}"),
    }
    store.fault().fail_reads(false);
    let results = store.read(&[&kept]).await.expect("read succeeds");
    assert_eq!(results[0].as_deref(), Some(b"after".as_slice()));
}

// ------------------------------------------------------------ backend runners

#[cfg(feature = "memory")]
mod memory_backend {
    use super::*;
    use accumulators::store::memory::InMemoryStore;

    #[test]
    fn the_in_memory_store_satisfies_the_conformance_suite() {
        let store = InMemoryStore::new();
        positional_reads(&store);
        empty_key_list(&store);
        put_delete_batch(&store);
        last_op_wins(&store);
        empty_batch(&store);
        duplicate_keys_alignment(&store);
        owned_ops(&store);
        error_preservation_before_backend(&FaultyStore::new(InMemoryStore::new()));
    }

    #[tokio::test]
    async fn the_in_memory_store_satisfies_the_async_conformance_suite() {
        let store = InMemoryStore::new();
        positional_reads_async(&store).await;
        empty_key_list_async(&store).await;
        put_delete_batch_async(&store).await;
        last_op_wins_async(&store).await;
        empty_batch_async(&store).await;
        duplicate_keys_alignment_async(&store).await;
        owned_ops_async(&store).await;
        error_preservation_before_backend_async(&FaultyStore::new(InMemoryStore::new())).await;
    }
}

#[cfg(all(feature = "sqlite", not(target_family = "wasm")))]
mod sqlite_backend {
    use super::*;
    use accumulators::store::sqlite::SqliteStore;

    use crate::common::TempDb;

    #[tokio::test]
    async fn the_sqlite_store_satisfies_the_conformance_suite() {
        let db = TempDb::new("conformance");
        let store = SqliteStore::connect(db.path())
            .await
            .expect("file sqlite opens");
        positional_reads_async(&store).await;
        empty_key_list_async(&store).await;
        put_delete_batch_async(&store).await;
        last_op_wins_async(&store).await;
        empty_batch_async(&store).await;
        duplicate_keys_alignment_async(&store).await;
        owned_ops_async(&store).await;
        error_preservation_before_backend_async(&FaultyStore::new(
            SqliteStore::connect(db.path()).await.expect("opens"),
        ))
        .await;
    }

    /// The **in-backend** fault seam for SQLite: a SQL trigger aborts the
    /// store's write mid-batch — after the transaction has begun and two of
    /// the batch's statements have already executed inside it. The failing
    /// write must return the backend's own error, and the store's transaction
    /// must roll back the partial work: none of the batch applies and the
    /// pre-batch state survives verbatim. This exercises SQLite's own
    /// `BEGIN`/`ROLLBACK` boundary, which the wrapper-level
    /// [`error_preservation_before_backend_async`] seam cannot reach.
    #[tokio::test]
    async fn a_backend_internal_failure_mid_batch_rolls_the_transaction_back() {
        use sqlx::Connection as _;

        let db = TempDb::new("conformance-mid-batch");
        let store = SqliteStore::connect(db.path())
            .await
            .expect("file sqlite opens");

        let (setup, prior, poisoned, tail) = (
            key("conf-sql-mid", b"setup"),
            key("conf-sql-mid", b"prior"),
            key("conf-sql-mid", b"poisoned"),
            key("conf-sql-mid", b"tail"),
        );
        let mut setup_batch = Batch::new();
        setup_batch.put(&setup, b"old");
        store
            .write(setup_batch)
            .await
            .expect("the setup write succeeds");

        // A separate connection arms the in-backend fault: the trigger
        // aborts (RAISE(ABORT)) any INSERT whose key is the poisoned one.
        // ABORT undoes only the current statement; the store's sqlx
        // transaction then drops and rolls back the statements before it.
        let mut poison_conn = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(db.path()),
        )
        .await
        .expect("a raw connection opens");
        let mut hex_key = String::with_capacity(2 * poisoned.len());
        for byte in &poisoned {
            use core::fmt::Write as _;
            let _ = write!(hex_key, "{byte:02x}");
        }
        // The DDL is built from this test's own constant key bytes (no
        // external input), so the sqlx injection audit is discharged here.
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
            "CREATE TRIGGER conformance_poison AFTER INSERT ON store \
             WHEN NEW.key = X'{hex_key}' \
             BEGIN SELECT RAISE(ABORT, 'injected mid-batch failure'); END;",
        )))
        .execute(&mut poison_conn)
        .await
        .expect("the poison trigger is armed");

        // put(prior) executes, then delete(setup) executes (both inside the
        // transaction), then the multi-row upsert carrying the poisoned key
        // hits the trigger. Earlier runs must flush first for the fault to
        // be mid-batch — the op order below forces exactly that.
        let mut batch = Batch::new();
        batch.put(&prior, b"must-not-land");
        batch.delete(&setup);
        batch.put(&poisoned, b"must-not-land");
        batch.put(&tail, b"must-not-land");
        match store.write(batch).await {
            Err(accumulators::store::sqlite::SqliteError::Database(_)) => {}
            Err(other) => panic!("expected the backend's own error, got {other:?}"),
            Ok(()) => panic!("the poisoned write must fail inside the transaction"),
        }

        // The transaction rolled back its partial work: nothing from the
        // batch applied, and the delete of the setup key was undone with it.
        let results = store
            .read(&[&prior, &setup, &poisoned, &tail])
            .await
            .expect("read succeeds");
        assert_eq!(
            results,
            [None, Some(b"old".to_vec()), None, None],
            "the failed batch must not partially apply — all-or-nothing"
        );

        // Clear the fault: the same batch shape succeeds and applies.
        sqlx::query("DROP TRIGGER conformance_poison")
            .execute(&mut poison_conn)
            .await
            .expect("the poison trigger is removed");
        let mut batch = Batch::new();
        batch.put(&prior, b"lands-now");
        batch.delete(&setup);
        batch.put(&poisoned, b"lands-now");
        batch.put(&tail, b"lands-now");
        store.write(batch).await.expect("the retry succeeds");
        let results = store
            .read(&[&prior, &setup, &poisoned, &tail])
            .await
            .expect("read succeeds");
        assert_eq!(
            results,
            [
                Some(b"lands-now".to_vec()),
                None,
                Some(b"lands-now".to_vec()),
                Some(b"lands-now".to_vec())
            ],
            "after the fault clears the batch applies whole"
        );
    }
}
