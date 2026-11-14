//! MMR benchmark suite.
//!
//! Groups:
//! - `hasher` - raw [`Hasher::hash`] baseline for every hasher (no MMR, no store)
//! - `MMR build` - cold build from N appends (amortized append throughput; successor
//!   of the old `MMR insertion` benchmark)
//! - `MMR append live` - appends into a pre-built 100k MMR via `iter_custom`, so the
//!   tree grows only ~10% during the run and steady-state append cost at a large
//!   size is measured
//! - `MMR get_proof` - single-proof generation, batched 10 per iteration
//! - `MMR get_proofs` - batched multi-proof generation for k indexes in one store
//!   pass; the ratio against `MMR get_proof` is the multiproof payoff
//! - `MMR verify_proof` - proof verification (store reads + path hashing)
//! - `MMR peaks` - peak retrieval and root (bagging) computation
//! - `Stacked MMR` - proof generation and appends routed across 3 stacked sub MMRs
//! - `MMR draft` - `start_draft` + in-memory appends + `commit` workflow
//!
//! MMR-logic benches use `InMemoryStore` unless the id says `sqlite`, so numbers
//! reflect MMR and hashing cost; sqlite variants quantify the persistence overhead
//! separately (at 10k appends SQLite was ~7x the in-memory cost).
//!
//! Sizes are log-spaced. The old 1M-element legs (~1h for 10 samples) were dropped
//! deliberately; add them back behind a feature flag only if ever needed.
//!
//! Run: `cargo bench --features all --bench mmr_benchmark -- --save-baseline <name>`
//! Compare later: `cargo bench --features all --bench mmr_benchmark -- --baseline <name>`
//! Results live in `target/criterion` (gitignored).

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use accumulators::{
    hasher::{
        Hasher, keccak::KeccakHasher, stark_blake::StarkBlakeHasher,
        stark_pedersen::StarkPedersenHasher, stark_poseidon::StarkPoseidonHasher,
    },
    mmr::{MMR, PeaksOptions, map_leaf_index_to_element_index},
    store::{Store, memory::InMemoryStore, sqlite::SQLiteStore},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::runtime::Runtime;

/// Appends per timed iteration in the live-append benchmarks.
const LIVE_APPEND_BATCH: usize = 500;
/// Appends per draft in the draft workflow benchmark.
const DRAFT_BATCH: usize = 1_000;
/// Proofs per iteration in the proof-generation benchmarks.
const PROOF_BATCH: usize = 10;

/// A valid element for the Poseidon hasher: 31-byte hex fits the 252-bit block.
fn element(index: usize) -> String {
    format!("0x{index:062x}")
}

/// 28-byte hex elements are valid for every hasher (Blake requires a
/// multiple-of-4 byte size, Pedersen 252 bits).
fn hash_pair_element(index: usize) -> String {
    format!("0x{index:056x}")
}

/// Leaf index (0-based) in an MMR built by appending `element(i)` for
/// `i in 0..leaves`, in element-index space.
fn leaf_to_element(leaf: usize) -> usize {
    map_leaf_index_to_element_index(leaf)
}

async fn build_mmr(store: Arc<dyn Store>, count: usize) -> MMR {
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let mut mmr = MMR::new(store, hasher, None);
    for i in 0..count {
        mmr.append(element(i)).await.unwrap();
    }
    mmr
}

/// Builds `stacks` stacked layers of `per_stack_leaves` leaves each.
///
/// Mirrors the `start_draft` pattern: each layer is a stacked MMR whose
/// appends continue the global element index space of the previous layers,
/// and its metadata covers everything stacked before it. The returned MMR is
/// a fresh top layer routing lookups across all `stacks` stores.
async fn build_stacked(stacks: usize, per_stack_leaves: usize) -> MMR {
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let mut metadata = Vec::with_capacity(stacks);
    let mut appended = 0usize;

    {
        let store = Arc::new(InMemoryStore::new(Some("stack-0")));
        let mut m = MMR::new(store, hasher.clone(), None);
        for i in 0..per_stack_leaves {
            m.append(element(i)).await.unwrap();
        }
        let elements_count = m.elements_count.get().await.unwrap();
        metadata.push((elements_count, m.get_metadata()));
    }
    appended += per_stack_leaves;

    for stack in 1..stacks {
        let store = Arc::new(InMemoryStore::new(Some(&format!("stack-{stack}"))));
        let mut stacked = MMR::new_stacked(store, hasher.clone(), None, metadata.clone())
            .await
            .unwrap();
        for i in 0..per_stack_leaves {
            stacked.append(element(appended + i)).await.unwrap();
        }
        appended += per_stack_leaves;
        let elements_count = stacked.elements_count.get().await.unwrap();
        metadata.push((elements_count, stacked.get_metadata()));
    }

    let top = Arc::new(InMemoryStore::new(Some("stacked-top")));
    let mut stacked = MMR::new_stacked(top, hasher, None, metadata).await.unwrap();
    for i in 0..100 {
        stacked.append(element(appended + i)).await.unwrap();
    }
    stacked
}

fn bench_hashers(c: &mut Criterion) {
    let mut group = c.benchmark_group("hasher");
    group.throughput(Throughput::Elements(2));
    group.sample_size(100);

    let left = hash_pair_element(1);
    let right = hash_pair_element(2);
    let hashers: [(&str, Arc<dyn Hasher>); 4] = [
        ("poseidon", Arc::new(StarkPoseidonHasher::new(Some(false)))),
        ("pedersen", Arc::new(StarkPedersenHasher::new())),
        ("keccak", Arc::new(KeccakHasher::new())),
        ("blake", Arc::new(StarkBlakeHasher::new(false))),
    ];
    for (name, hasher) in hashers {
        group.bench_function(BenchmarkId::new("hash_pair", name), |bench| {
            bench.iter(|| black_box(hasher.hash(vec![left.clone(), right.clone()]).unwrap()));
        });
    }
    group.finish();
}

fn bench_build(c: &mut Criterion, rt: &Runtime) {
    let mut group = c.benchmark_group("MMR build");
    for size in [1_000usize, 10_000, 100_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.sample_size(if size >= 100_000 { 10 } else { 20 });
        group.measurement_time(Duration::from_secs(3));
        group.bench_function(BenchmarkId::new("memory", size), |b| {
            b.iter(|| {
                black_box(rt.block_on(build_mmr(Arc::new(InMemoryStore::new(Some("bench"))), size)))
            });
        });
    }
    for size in [1_000usize, 10_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(5));
        group.bench_function(BenchmarkId::new("sqlite", size), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let store = SQLiteStore::new(":memory:", None, Some("bench"))
                        .await
                        .unwrap();
                    black_box(build_mmr(Arc::new(store), size).await)
                })
            });
        });
    }
    group.finish();
}

fn bench_live_append(c: &mut Criterion, rt: &Runtime) {
    let mut group = c.benchmark_group("MMR append live");
    group.throughput(Throughput::Elements(LIVE_APPEND_BATCH as u64));
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));
    group.measurement_time(Duration::from_millis(500));

    // The tree grows by roughly 10k appends across warmup and measurement
    // (~10% of 100k), so the measured size stays approximately constant.
    let mut mmr = rt.block_on(build_mmr(
        Arc::new(InMemoryStore::new(Some("bench"))),
        100_000,
    ));
    let counter = AtomicUsize::new(100_000);
    group.bench_function("memory/100_000", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let start = Instant::now();
                for _ in 0..iters {
                    for _ in 0..LIVE_APPEND_BATCH {
                        let i = counter.fetch_add(1, Ordering::Relaxed);
                        mmr.append(element(i)).await.unwrap();
                    }
                }
                start.elapsed()
            })
        });
    });

    let store = rt.block_on(async {
        SQLiteStore::new(":memory:", None, Some("bench"))
            .await
            .unwrap()
    });
    let mut mmr = rt.block_on(build_mmr(Arc::new(store), 100_000));
    let counter = AtomicUsize::new(100_000);
    group.bench_function("sqlite/100_000", |b| {
        b.iter_custom(|iters| {
            rt.block_on(async {
                let start = Instant::now();
                for _ in 0..iters {
                    for _ in 0..LIVE_APPEND_BATCH {
                        let i = counter.fetch_add(1, Ordering::Relaxed);
                        mmr.append(element(i)).await.unwrap();
                    }
                }
                start.elapsed()
            })
        });
    });
    group.finish();
}

fn bench_get_proof(c: &mut Criterion, rt: &Runtime) {
    let mut group = c.benchmark_group("MMR get_proof");
    group.throughput(Throughput::Elements(PROOF_BATCH as u64));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [1_000usize, 10_000, 100_000] {
        let mmr = rt.block_on(build_mmr(Arc::new(InMemoryStore::new(Some("bench"))), size));
        let counter = AtomicUsize::new(0);
        group.bench_function(BenchmarkId::new("memory", size), move |b| {
            b.iter(|| {
                rt.block_on(async {
                    let start = counter.fetch_add(PROOF_BATCH, Ordering::Relaxed);
                    for i in start..start + PROOF_BATCH {
                        let proof = mmr
                            .get_proof(leaf_to_element(i % size), None)
                            .await
                            .unwrap();
                        black_box(proof);
                    }
                });
            });
        });
    }
    group.finish();
}

fn bench_get_proofs(c: &mut Criterion, rt: &Runtime) {
    let mut group = c.benchmark_group("MMR get_proofs");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [10_000usize, 100_000] {
        let mmr = rt.block_on(build_mmr(Arc::new(InMemoryStore::new(Some("bench"))), size));
        for k in [1usize, 10, 100, 1_000] {
            group.throughput(Throughput::Elements(k as u64));
            let stride = (size / k).max(1);
            let indexes: Vec<usize> = (0..k).map(|i| leaf_to_element(i * stride)).collect();
            group.bench_function(BenchmarkId::new("memory", format!("{size}/k-{k}")), |b| {
                b.iter(|| {
                    let indexes = indexes.clone();
                    rt.block_on(async { black_box(mmr.get_proofs(indexes, None).await.unwrap()) })
                });
            });
        }
    }
    group.finish();
}

fn bench_verify_proof(c: &mut Criterion, rt: &Runtime) {
    let mut group = c.benchmark_group("MMR verify_proof");
    group.throughput(Throughput::Elements(1));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [1_000usize, 10_000, 100_000] {
        let mmr = rt.block_on(build_mmr(Arc::new(InMemoryStore::new(Some("bench"))), size));
        let leaf = size / 2;
        let proof = rt
            .block_on(mmr.get_proof(leaf_to_element(leaf), None))
            .unwrap();
        let value = element(leaf);
        // Sanity: the proof must verify before we benchmark verification.
        assert!(
            rt.block_on(mmr.verify_proof(proof.clone(), value.clone(), None))
                .unwrap()
        );
        assert!(
            rt.block_on(mmr.verify_proof(proof.clone(), value.clone(), None))
                .unwrap()
        );
        group.bench_function(BenchmarkId::new("memory", size), |b| {
            b.iter(|| {
                let valid = rt
                    .block_on(mmr.verify_proof(proof.clone(), value.clone(), None))
                    .unwrap();
                black_box(valid)
            });
        });
    }
    group.finish();
}

fn bench_peaks_root(c: &mut Criterion, rt: &Runtime) {
    let mut group = c.benchmark_group("MMR peaks");
    group.throughput(Throughput::Elements(1));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [10_000usize, 100_000] {
        let mmr = rt.block_on(build_mmr(Arc::new(InMemoryStore::new(Some("bench"))), size));
        group.bench_function(BenchmarkId::new("get_peaks", size), |b| {
            b.iter(|| {
                black_box(
                    rt.block_on(mmr.get_peaks(PeaksOptions {
                        elements_count: None,
                        formatting_opts: None,
                    }))
                    .unwrap(),
                )
            });
        });
        group.bench_function(BenchmarkId::new("root", size), |b| {
            b.iter(|| {
                let bag = rt.block_on(mmr.bag_the_peaks(None)).unwrap();
                black_box(mmr.calculate_root_hash(&bag, size).unwrap())
            });
        });
    }
    group.finish();
}

fn bench_stacked(c: &mut Criterion, rt: &Runtime) {
    let mut group = c.benchmark_group("Stacked MMR");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));

    let mut stacked = rt.block_on(build_stacked(3, 3_300));
    // Sanity: proofs must generate across the stacks before benchmarking.
    let proof = rt
        .block_on(stacked.get_proof(leaf_to_element(5_000), None))
        .unwrap();
    assert!(
        rt.block_on(stacked.verify_proof(proof, element(5_000), None))
            .unwrap()
    );

    group.throughput(Throughput::Elements(PROOF_BATCH as u64));
    let proof_counter = AtomicUsize::new(0);
    group.bench_function("get_proof/3-stacks-10k", |b| {
        b.iter(|| {
            rt.block_on(async {
                let start = proof_counter.fetch_add(PROOF_BATCH, Ordering::Relaxed);
                for i in start..start + PROOF_BATCH {
                    let proof = stacked
                        .get_proof(leaf_to_element(i % 10_000), None)
                        .await
                        .unwrap();
                    black_box(proof);
                }
            });
        });
    });

    group.throughput(Throughput::Elements(LIVE_APPEND_BATCH as u64));
    let append_counter = AtomicUsize::new(10_000);
    group.bench_function("append/hot", |b| {
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..LIVE_APPEND_BATCH {
                    let i = append_counter.fetch_add(1, Ordering::Relaxed);
                    stacked.append(element(i)).await.unwrap();
                }
            });
        });
    });
    group.finish();
}

fn bench_draft(c: &mut Criterion, rt: &Runtime) {
    let mut group = c.benchmark_group("MMR draft");
    group.throughput(Throughput::Elements(DRAFT_BATCH as u64));
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));

    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));
    let counter = AtomicUsize::new(0);

    let mut memory_ref = rt.block_on(async {
        let mut mmr = MMR::new(
            Arc::new(InMemoryStore::new(Some("draft-ref"))),
            hasher.clone(),
            None,
        );
        for i in 0..10 {
            mmr.append(element(i)).await.unwrap();
        }
        mmr
    });
    let mut sqlite_ref = rt.block_on(async {
        let store = SQLiteStore::new(":memory:", None, Some("draft-ref"))
            .await
            .unwrap();
        let mut mmr = MMR::new(Arc::new(store), hasher, None);
        for i in 0..10 {
            mmr.append(element(i)).await.unwrap();
        }
        mmr
    });

    group.bench_function("workflow-1000/ref-memory", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut draft = memory_ref.start_draft().await.unwrap();
                for _ in 0..DRAFT_BATCH {
                    let i = counter.fetch_add(1, Ordering::Relaxed);
                    draft.mmr.append(element(i)).await.unwrap();
                }
                let _: () = draft.commit().await.unwrap();
                black_box(());
            });
        });
    });

    group.bench_function("workflow-1000/ref-sqlite", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut draft = sqlite_ref.start_draft().await.unwrap();
                for _ in 0..DRAFT_BATCH {
                    let i = counter.fetch_add(1, Ordering::Relaxed);
                    draft.mmr.append(element(i)).await.unwrap();
                }
                let _: () = draft.commit().await.unwrap();
                black_box(());
            });
        });
    });
    group.finish();
}

fn bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    bench_hashers(c);
    bench_build(c, &rt);
    bench_live_append(c, &rt);
    bench_get_proof(c, &rt);
    bench_get_proofs(c, &rt);
    bench_verify_proof(c, &rt);
    bench_peaks_root(c, &rt);
    bench_stacked(c, &rt);
    bench_draft(c, &rt);
}

criterion_group!(name = benches; config = Criterion::default(); targets = bench);
criterion_main!(benches);
