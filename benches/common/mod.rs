//! Shared benchmark suite for store backends.
//!
//! Every `store_*` benchmark binary drives the exact same workload through
//! [`bench_store_sync`] (or [`bench_store_async`] for async-only backends),
//! so criterion numbers are directly comparable across backends.
//!
//! The workload mirrors the MMR benchmark's legs: building 10 000 leaves,
//! a 1 000-element batch append, single-proof generation, a 100-leaf
//! multiproof, proof verification, and two raw-store baselines
//! (`Store::read`/`Store::write` with no MMR logic) so backend latency
//! separates from accumulator work per backend.
//!
//! Store construction and opening happen in setup, never inside the timed
//! loops; the build legs isolate themselves by appending under a fresh
//! [`AccumulatorId`] per iteration, so no store-clearing API is needed and
//! no backend gets an unfair warm cache. Element vectors are identical
//! across iterations (leaf identity comes from append order, not bytes), so
//! they are built once outside the timed loops.

// Bench harness: a failed operation aborts the run, so unwrapping is the
// honest control flow. One of the two suite variants is unused per binary
// (each backend is sync or async, never both).
#![expect(
    clippy::unwrap_used,
    clippy::semicolon_if_nothing_returned,
    dead_code,
    reason = "bench harness; each store binary exercises exactly one suite variant"
)]

use std::fmt::Debug;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{BenchmarkGroup, Throughput};
use tokio::runtime::Runtime;

use accumulators::hashers::KeccakSolHasher;
use accumulators::ids::AccumulatorId;
use accumulators::mmr::{AppendOnly, AsyncMmr, Mmr, Plain};
use accumulators::primitives::LeafIndex;
use accumulators::store::{AsyncStore, Batch, Store, keys};

const BUILD_LEAVES: u64 = 10_000;
const BATCH_LEAVES: u64 = 1_000;
const PROOF_LEAF: u64 = 1_000;
const MULTIPROOF_LEAVES: u64 = 100;
const ELEMENT: &[u8] = b"store-benchmark-element";

/// Monotonic ids keep every build iteration in a fresh keyspace without
/// touching randomness, so iterations are independent and reproducible.
fn next_id() -> AccumulatorId {
    static COUNTER: AtomicU64 = AtomicU64::new(1);
    let raw = COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes();
    let mut bytes = [0u8; 16];
    bytes[8..].copy_from_slice(&raw);
    AccumulatorId::from(bytes)
}

fn element(i: u64) -> Vec<u8> {
    let mut e = ELEMENT.to_vec();
    e.extend_from_slice(&i.to_be_bytes());
    e
}

fn elements(count: u64) -> Vec<Vec<u8>> {
    (0..count).map(element).collect()
}

/// A 32-byte value shaped like an MMR node hash, distinct per index.
fn hash_value(i: u64) -> Vec<u8> {
    let mut v = vec![0_u8; 32];
    v[..8].copy_from_slice(&i.to_be_bytes());
    v
}

/// Benchmark a synchronous store backend: build, batch append, proof,
/// multiproof, verify, raw read/write.
pub fn bench_store_sync<S, F>(
    group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    make_store: F,
) where
    S: Store + Clone + Debug + 'static,
    F: Fn() -> S,
{
    type MmrOf<S> = Mmr<KeccakSolHasher, S, Plain, AppendOnly, AccumulatorId>;

    // Elements are identical across iterations — leaf identity comes from
    // append order and each iteration appends into a fresh keyspace — so
    // both element vectors are built once here, outside the timed loops.
    let build_elements = elements(BUILD_LEAVES);
    let batch_elements: Vec<Vec<u8>> = (0..BATCH_LEAVES).map(element).collect();

    // Build: appends one at a time into a fresh keyspace per iteration.
    let store = make_store();
    group.throughput(Throughput::Elements(BUILD_LEAVES));
    group.bench_function(format!("{name}/build/{BUILD_LEAVES}"), |b| {
        b.iter(|| {
            let id = next_id();
            let mut mmr = MmrOf::<S>::create(KeccakSolHasher, store.clone(), id).unwrap();
            for e in &build_elements {
                black_box(mmr.append(e).unwrap());
            }
            black_box(mmr.root())
        })
    });

    // Batch append: the one-write-for-N contract, into a fresh keyspace per
    // iteration — bounded-capacity backends must not have the leg's growth
    // depend on how many iterations criterion samples.
    let store = make_store();
    group.throughput(Throughput::Elements(BATCH_LEAVES));
    group.bench_function(format!("{name}/append_batch/{BATCH_LEAVES}"), |b| {
        b.iter(|| {
            let id = next_id();
            let mut mmr = MmrOf::<S>::create(KeccakSolHasher, store.clone(), id).unwrap();
            black_box(mmr.append_batch(&batch_elements).unwrap())
        })
    });

    // Read fixtures: build a tree in setup (never timed); the proof,
    // multiproof, and verify legs run against it.
    let store = make_store();
    let id = next_id();
    let mut mmr = MmrOf::<S>::create(KeccakSolHasher, store, id).unwrap();
    for e in &build_elements {
        mmr.append(e).unwrap();
    }

    // Single proof + verification.
    let proof = mmr.proof(LeafIndex::new(PROOF_LEAF)).unwrap();
    let proof_element = element(PROOF_LEAF);
    // Sanity: the proof must verify before we benchmark verification.
    assert!(
        mmr.verify(&proof, &proof_element).unwrap(),
        "sanity: the proof for leaf {PROOF_LEAF} must verify"
    );
    group.throughput(Throughput::Elements(1));
    group.bench_function(format!("{name}/proof/leaf-{PROOF_LEAF}"), |b| {
        b.iter(|| black_box(mmr.proof(LeafIndex::new(PROOF_LEAF)).unwrap()))
    });
    group.bench_function(format!("{name}/verify/leaf-{PROOF_LEAF}"), |b| {
        b.iter(|| black_box(mmr.verify(&proof, &proof_element).unwrap()))
    });

    // Multiproof over a scattered set of leaves.
    let leaves: Vec<LeafIndex> = (0..MULTIPROOF_LEAVES)
        .map(|k| LeafIndex::new(k * (BUILD_LEAVES / MULTIPROOF_LEAVES)))
        .collect();
    let multi = mmr.multiproof(leaves.clone()).unwrap();
    let multi_elements: Vec<Vec<u8>> = leaves.iter().map(|l| element(l.get())).collect();
    // Sanity: the multiproof must verify before we benchmark verification.
    assert!(
        mmr.verify_multi(&multi, multi_elements.clone()).unwrap(),
        "sanity: the {MULTIPROOF_LEAVES}-leaf multiproof must verify"
    );
    group.throughput(Throughput::Elements(MULTIPROOF_LEAVES));
    group.bench_function(format!("{name}/multiproof/k-{MULTIPROOF_LEAVES}"), |b| {
        b.iter(|| black_box(mmr.multiproof(leaves.clone()).unwrap()))
    });
    group.bench_function(format!("{name}/verify_multi/k-{MULTIPROOF_LEAVES}"), |b| {
        b.iter(|| black_box(mmr.verify_multi(&multi, multi_elements.clone()).unwrap()))
    });

    // Raw store baselines: `Store::read`/`Store::write` with no MMR logic,
    // so backend latency separates from accumulator work. Same key count
    // and value shape as the MMR batch leg, pre-populated in setup; the
    // write leg overwrites the same keys, so capacity stays bounded.
    let raw_store = make_store();
    let raw_id = next_id();
    let raw_keys: Vec<Vec<u8>> = (0..BATCH_LEAVES)
        .map(|i| keys::encode(&raw_id, keys::Table::Nodes, i))
        .collect();
    let raw_values: Vec<Vec<u8>> = (0..BATCH_LEAVES).map(hash_value).collect();
    let raw_key_refs: Vec<&[u8]> = raw_keys.iter().map(Vec::as_slice).collect();
    {
        let mut populate = Batch::new();
        for (key, value) in raw_keys.iter().zip(&raw_values) {
            populate.put(key, value);
        }
        raw_store.write(populate).unwrap();
    }
    // Sanity: the raw fixture must be present before benchmarking reads.
    let probe = raw_store.read(&raw_key_refs).unwrap();
    assert_eq!(
        probe[0].as_deref(),
        Some(raw_values[0].as_slice()),
        "sanity: raw read fixture must be present"
    );
    group.throughput(Throughput::Elements(BATCH_LEAVES));
    group.bench_function(format!("{name}/raw_read/{BATCH_LEAVES}"), |b| {
        b.iter(|| black_box(raw_store.read(&raw_key_refs).unwrap()))
    });
    group.bench_function(format!("{name}/raw_write/{BATCH_LEAVES}"), |b| {
        b.iter(|| {
            let mut batch = Batch::new();
            for (key, value) in raw_keys.iter().zip(&raw_values) {
                batch.put(key, value);
            }
            raw_store.write(batch).unwrap()
        })
    });
}

/// Benchmark an async-only store backend. Runs the same legs as
/// [`bench_store_sync`] through [`AsyncMmr`], blocking on a shared runtime.
///
/// Setup and each timed call drive the runtime with `block_on` from the
/// plain calling thread — `block_on` must never run inside another
/// `block_on`'s context (tokio panics on the nesting), so the suite is
/// structured like `mmr_benchmark`'s sqlite legs: build the fixtures at the
/// suite level, block per call inside the closures.
#[expect(
    clippy::too_many_lines,
    reason = "one leg per benchmark; splitting the suite would hide the shared-fixture structure"
)]
pub fn bench_store_async<S, F>(
    group: &mut BenchmarkGroup<'_, criterion::measurement::WallTime>,
    name: &str,
    runtime: &Runtime,
    make_store: F,
) where
    S: AsyncStore + Clone + Debug + 'static,
    F: Fn() -> S,
{
    type MmrOf<S> = AsyncMmr<KeccakSolHasher, S, Plain, AppendOnly, AccumulatorId>;

    // Elements are identical across iterations (same as the sync suite).
    let build_elements = elements(BUILD_LEAVES);
    let batch_elements: Vec<Vec<u8>> = (0..BATCH_LEAVES).map(element).collect();

    // Build: appends one at a time into a fresh keyspace per iteration.
    let store = make_store();
    group.throughput(Throughput::Elements(BUILD_LEAVES));
    group.bench_function(format!("{name}/build/{BUILD_LEAVES}"), |b| {
        b.iter(|| {
            runtime.block_on(async {
                let id = next_id();
                let mut mmr = MmrOf::<S>::create(KeccakSolHasher, store.clone(), id)
                    .await
                    .unwrap();
                for e in &build_elements {
                    black_box(mmr.append(e).await.unwrap());
                }
                black_box(mmr.root())
            })
        })
    });

    // Batch append: fresh keyspace per iteration (same as the sync suite)
    // so bounded-capacity backends never overflow mid-sampling.
    let store = make_store();
    group.throughput(Throughput::Elements(BATCH_LEAVES));
    group.bench_function(format!("{name}/append_batch/{BATCH_LEAVES}"), |b| {
        b.iter(|| {
            runtime.block_on(async {
                let id = next_id();
                let mut mmr = MmrOf::<S>::create(KeccakSolHasher, store.clone(), id)
                    .await
                    .unwrap();
                black_box(mmr.append_batch(&batch_elements).await.unwrap())
            })
        })
    });

    // Read fixtures: build a tree in setup (never timed); the proof,
    // multiproof, and verify legs run against it.
    let id = next_id();
    let mmr = runtime.block_on(async {
        let mut mmr = MmrOf::<S>::create(KeccakSolHasher, store.clone(), id)
            .await
            .unwrap();
        for e in &build_elements {
            mmr.append(e).await.unwrap();
        }
        mmr
    });

    // Single proof + verification.
    let proof = runtime
        .block_on(mmr.proof(LeafIndex::new(PROOF_LEAF)))
        .unwrap();
    let proof_element = element(PROOF_LEAF);
    // Sanity: the proof must verify before we benchmark verification.
    assert!(
        mmr.verify(&proof, &proof_element).unwrap(),
        "sanity: the proof for leaf {PROOF_LEAF} must verify"
    );
    group.throughput(Throughput::Elements(1));
    group.bench_function(format!("{name}/proof/leaf-{PROOF_LEAF}"), |b| {
        b.iter(|| {
            runtime
                .block_on(async { black_box(mmr.proof(LeafIndex::new(PROOF_LEAF)).await.unwrap()) })
        })
    });
    group.bench_function(format!("{name}/verify/leaf-{PROOF_LEAF}"), |b| {
        b.iter(|| {
            runtime.block_on(async { black_box(mmr.verify(&proof, &proof_element).unwrap()) })
        })
    });

    // Multiproof over a scattered set of leaves.
    let leaves: Vec<LeafIndex> = (0..MULTIPROOF_LEAVES)
        .map(|k| LeafIndex::new(k * (BUILD_LEAVES / MULTIPROOF_LEAVES)))
        .collect();
    let multi = runtime.block_on(mmr.multiproof(leaves.clone())).unwrap();
    let multi_elements: Vec<Vec<u8>> = leaves.iter().map(|l| element(l.get())).collect();
    // Sanity: the multiproof must verify before we benchmark verification.
    assert!(
        mmr.verify_multi(&multi, multi_elements.clone()).unwrap(),
        "sanity: the {MULTIPROOF_LEAVES}-leaf multiproof must verify"
    );
    group.throughput(Throughput::Elements(MULTIPROOF_LEAVES));
    group.bench_function(format!("{name}/multiproof/k-{MULTIPROOF_LEAVES}"), |b| {
        b.iter(|| {
            runtime.block_on(async { black_box(mmr.multiproof(leaves.clone()).await.unwrap()) })
        })
    });
    group.bench_function(format!("{name}/verify_multi/k-{MULTIPROOF_LEAVES}"), |b| {
        b.iter(|| black_box(mmr.verify_multi(&multi, multi_elements.clone()).unwrap()))
    });

    // Raw store baselines (same as the sync suite): `Store::read`/
    // `Store::write` with no MMR logic, pre-populated in setup.
    let raw_store = make_store();
    let raw_id = next_id();
    let raw_keys: Vec<Vec<u8>> = (0..BATCH_LEAVES)
        .map(|i| keys::encode(&raw_id, keys::Table::Nodes, i))
        .collect();
    let raw_values: Vec<Vec<u8>> = (0..BATCH_LEAVES).map(hash_value).collect();
    let raw_key_refs: Vec<&[u8]> = raw_keys.iter().map(Vec::as_slice).collect();
    runtime.block_on(async {
        let mut populate = Batch::new();
        for (key, value) in raw_keys.iter().zip(&raw_values) {
            populate.put(key, value);
        }
        raw_store.write(populate).await.unwrap();
        // Sanity: the raw fixture must be present before benchmarking reads.
        let probe = raw_store.read(&raw_key_refs).await.unwrap();
        assert_eq!(
            probe[0].as_deref(),
            Some(raw_values[0].as_slice()),
            "sanity: raw read fixture must be present"
        );
    });
    group.throughput(Throughput::Elements(BATCH_LEAVES));
    group.bench_function(format!("{name}/raw_read/{BATCH_LEAVES}"), |b| {
        b.iter(|| {
            runtime.block_on(async { black_box(raw_store.read(&raw_key_refs).await.unwrap()) })
        })
    });
    group.bench_function(format!("{name}/raw_write/{BATCH_LEAVES}"), |b| {
        b.iter(|| {
            runtime.block_on(async {
                let mut batch = Batch::new();
                for (key, value) in raw_keys.iter().zip(&raw_values) {
                    batch.put(key, value);
                }
                raw_store.write(batch).await.unwrap()
            })
        })
    });
}
