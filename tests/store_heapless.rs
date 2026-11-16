//! Behavior tests for the heapless store backend: the backend-agnostic
//! conformance suite plus heapless-specific semantics — entry capacity,
//! key/value caps, all-or-nothing batches, clone independence, and
//! concurrent access from multiple threads.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]

#[path = "common/mod.rs"]
mod common;

#[path = "store/conformance.rs"]
mod conformance;

use std::sync::Arc;

use accumulators::store::heapless::{HeaplessError, HeaplessStore};
use accumulators::store::{Batch, Store};

use common::FaultyStore;

// ---------------------------------------------------------------- conformance

#[test]
fn the_heapless_store_satisfies_the_conformance_suite() {
    let store = HeaplessStore::<64>::new();
    conformance::positional_reads(&store);
    conformance::empty_key_list(&store);
    conformance::put_delete_batch(&store);
    conformance::last_op_wins(&store);
    conformance::empty_batch(&store);
    conformance::duplicate_keys_alignment(&store);
    conformance::owned_ops(&store);
    conformance::binary_keys(&store);
    conformance::error_preservation_before_backend(&FaultyStore::new(HeaplessStore::<64>::new()));
}

#[tokio::test]
async fn the_heapless_store_satisfies_the_async_conformance_suite() {
    let store = HeaplessStore::<64>::new();
    conformance::positional_reads_async(&store).await;
    conformance::empty_key_list_async(&store).await;
    conformance::put_delete_batch_async(&store).await;
    conformance::last_op_wins_async(&store).await;
    conformance::empty_batch_async(&store).await;
    conformance::duplicate_keys_alignment_async(&store).await;
    conformance::owned_ops_async(&store).await;
    conformance::binary_keys_async(&store).await;
    conformance::error_preservation_before_backend_async(&FaultyStore::new(
        HeaplessStore::<64>::new(),
    ))
    .await;
}

// ------------------------------------------------------------- entry capacity

#[test]
fn capacity_is_typed_full_at_exactly_n_plus_one() {
    let store = HeaplessStore::<2>::new();
    let mut batch = Batch::new();
    batch.put(b"a", b"1");
    batch.put(b"b", b"2");
    store.write(batch).expect("two entries fit");

    let mut batch = Batch::new();
    batch.put(b"c", b"3");
    assert_eq!(
        store.write(batch),
        Err(HeaplessError::Full(2)),
        "the third distinct key must be a typed Full, not a panic"
    );

    // The rejected insert landed nowhere; deleting frees the slot again.
    let results = store.read(&[b"a", b"b", b"c"]).expect("read succeeds");
    assert_eq!(results, [Some(b"1".to_vec()), Some(b"2".to_vec()), None]);
    assert_eq!(store.len(), 2);

    let mut batch = Batch::new();
    batch.delete(b"a");
    batch.put(b"c", b"3");
    store.write(batch).expect("delete frees capacity");
    assert_eq!(store.len(), 2);
}

#[test]
fn overwrites_and_deletes_do_not_consume_capacity() {
    let store = HeaplessStore::<1>::new();
    for i in 0..8u32 {
        let value = i.to_be_bytes();
        let mut batch = Batch::new();
        batch.put(b"key", &value);
        store.write(batch).expect("overwrites never grow the map");
    }
    assert_eq!(store.len(), 1);

    let mut batch = Batch::new();
    batch.delete(b"key");
    batch.delete(b"absent");
    store.write(batch).expect("delete of a live key succeeds");
    assert!(store.is_empty());
}

// ---------------------------------------------------------------- atomicity

#[test]
fn an_overflowing_batch_leaves_the_store_untouched() {
    let store = HeaplessStore::<3>::new();
    let mut batch = Batch::new();
    batch.put(b"kept", b"original");
    batch.put(b"second", b"stays");
    store.write(batch).expect("setup fits");

    // Overwrite + delete + three inserts against one free slot: every op
    // before the overflow must roll back with it.
    let mut batch = Batch::new();
    batch.put(b"second", b"overwritten");
    batch.delete(b"kept");
    batch.put(b"new-1", b"v");
    batch.put(b"new-2", b"v");
    batch.put(b"new-3", b"v");
    batch.put(b"new-4", b"v");
    assert!(
        matches!(store.write(batch), Err(HeaplessError::Full(3))),
        "the overflow must surface as the typed Full error"
    );

    let results = store
        .read(&[b"kept", b"second", b"new-1", b"new-4"])
        .expect("read succeeds");
    assert_eq!(
        results,
        [
            Some(b"original".to_vec()),
            Some(b"stays".to_vec()),
            None,
            None
        ],
        "the failed batch must not partially apply"
    );
    assert_eq!(store.len(), 2);
}

// --------------------------------------------------------------------- caps

#[test]
fn oversized_keys_and_values_are_typed_errors() {
    let store = HeaplessStore::<8, 8, 8>::new();

    let mut batch = Batch::new();
    batch.put(b"nine-byte", b"v");
    assert_eq!(
        store.write(batch),
        Err(HeaplessError::KeyTooLong { len: 9, cap: 8 })
    );

    let mut batch = Batch::new();
    batch.put(b"k", &[0u8; 9]);
    assert_eq!(
        store.write(batch),
        Err(HeaplessError::ValueTooLong { len: 9, cap: 8 })
    );

    assert!(store.is_empty(), "rejected writes must land nothing");

    // Boundary sizes fit.
    let mut batch = Batch::new();
    batch.put(b"eightbyt", &[0u8; 8]);
    store.write(batch).expect("cap-sized key and value fit");
    assert_eq!(store.len(), 1);
}

#[test]
fn default_caps_cover_the_crate_key_wire_bound() {
    // A maximal crate key (255-byte id + prefix + tag + subkey) fits the
    // default KEY_CAP; nothing rejects it.
    let store = HeaplessStore::<4>::new();
    let mut key = vec![255u8];
    key.extend_from_slice(&[0u8; 255]);
    key.push(0);
    key.extend_from_slice(&u64::MAX.to_be_bytes());
    assert_eq!(key.len(), 265);

    let mut batch = Batch::new();
    batch.put_owned(key, vec![1, 2, 3]);
    store
        .write(batch)
        .expect("the maximal crate key fits KEY_CAP");
    assert_eq!(store.len(), 1);
}

// -------------------------------------------------------------------- clones

#[test]
fn clones_are_independent_stores() {
    let store = HeaplessStore::<8>::new();
    let clone = store.clone();

    let mut batch = Batch::new();
    batch.put(b"key", b"value");
    clone.write(batch).expect("clone write");

    let results = store.read(&[b"key"]).expect("read succeeds");
    assert_eq!(
        results,
        [None],
        "the clone's write must not reach the original"
    );
    assert_eq!(store.len(), 0);
    assert_eq!(clone.len(), 1);
    assert_ne!(store.identity(), clone.identity(), "independent identities");
    assert!(!store.same_store(&clone));
    assert!(!clone.same_store(&store));
}

// --------------------------------------------------------------- concurrency

#[test]
fn concurrent_threads_are_serialized_correctly() {
    let store = Arc::new(HeaplessStore::<256>::new());
    let threads: Vec<_> = (0..4)
        .map(|t| {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for i in 0..32u32 {
                    let key = format!("thread-{t}-key-{i}");
                    let value = i.to_be_bytes();
                    let mut batch = Batch::new();
                    batch.put(key.as_bytes(), &value);
                    store.write(batch).expect("write succeeds");
                    let results = store.read(&[key.as_bytes()]).expect("read succeeds");
                    assert_eq!(results, [Some(value.to_vec())]);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().expect("thread succeeds");
    }

    assert_eq!(store.len(), 128);
    let keys: Vec<Vec<u8>> = (0..4)
        .flat_map(|t| (0..32u32).map(move |i| format!("thread-{t}-key-{i}").into_bytes()))
        .collect();
    let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
    let results = store.read(&refs).expect("read succeeds");
    assert!(results.iter().all(Option::is_some), "every key round-trips");
}
