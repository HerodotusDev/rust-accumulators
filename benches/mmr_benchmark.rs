//! MMR benchmark suite.
//!
//! Groups:
//! - `hasher` - raw [`Hasher::hash_pair`] baseline for every hasher (no MMR, no store)
//! - `MMR build` - cold build from N appends (amortized append throughput)
//! - `MMR append live` - appends into a pre-built 100k MMR via `iter_custom`, so the
//!   MMR grows only ~10% during the run and steady-state append cost at a large
//!   size is measured
//! - `MMR get_proof` - single-proof generation, batched 10 per iteration
//! - `MMR get_proofs` - multiproof generation for k indexes in one store pass;
//!   the ratio against `MMR get_proof` is the multiproof payoff
//! - `MMR verify_proof` - proof verification (path hashing against the cached root)
//! - `MMR peaks` - peak retrieval and root computation (both cache reads)
//! - `Stacked MMR` - proof generation and appends routed across 3 stacked
//!   sub-MMRs (one shared store and a 3-distinct-stores variant)
//! - `MMR draft` - `start_draft` + in-memory appends + `commit` workflow
//!
//! MMR-logic benches use `InMemoryStore`, so numbers reflect MMR and hashing
//! cost. The v0.5 sqlite variants are dropped: the SQLite store is async-only
//! (the sync [`Mmr`] cannot use it), and the sqlite *draft* variant has no
//! counterpart in the redesign (drafts exist on the sync shell only).
//!
//! Sizes are log-spaced. The 1M-element legs (~1h for 10 samples in v0.5) remain
//! dropped deliberately.
//!
//! Run: `cargo bench --features all --bench mmr_benchmark -- --save-baseline <name>`
//! Compare later: `cargo bench --features all --bench mmr_benchmark -- --baseline <name>`
//! Results live in `target/criterion` (gitignored).

use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use accumulators::{
    hashers::{Blake2sHasher, Hasher, Keccak256Hasher, PedersenHasher, PoseidonHasher},
    ids::AccumulatorId,
    mmr::{Mmr, Optimise, kinds},
    primitives::LeafIndex,
    store::memory::InMemoryStore,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Appends per timed iteration in the live-append benchmarks.
const LIVE_APPEND_BATCH: usize = 500;
/// Appends per draft in the draft workflow benchmark.
const DRAFT_BATCH: usize = 1_000;
/// Proofs per iteration in the proof-generation benchmarks.
const PROOF_BATCH: usize = 10;

/// A valid element for every hasher: the 32-byte big-endian encoding of the
/// index (left-zero-padded, so distinct indexes give distinct elements, and
/// small values stay below the Starknet field modulus).
fn element(index: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(index as u64).to_be_bytes());
    bytes
}

/// Builds a plain keccak MMR of `count` leaves, one append (one atomic store
/// batch) at a time — the amortized per-append cost the build group measures.
fn build_mmr(count: usize) -> Mmr<Keccak256Hasher, InMemoryStore> {
    let mut mmr = Mmr::create(Keccak256Hasher, InMemoryStore::new(), AccumulatorId::ZERO)
        .expect("mmr creation succeeds");
    for i in 0..count {
        mmr.append(&element(i)).expect("append succeeds");
    }
    mmr
}

fn bench_hashers(c: &mut Criterion) {
    let mut group = c.benchmark_group("hasher");
    group.throughput(Throughput::Elements(2));
    group.sample_size(100);

    let keccak = Keccak256Hasher;
    let left = keccak.hash_leaf(&element(1)).expect("valid element");
    let right = keccak.hash_leaf(&element(2)).expect("valid element");
    group.bench_function(BenchmarkId::new("hash_pair", "keccak"), |b| {
        b.iter(|| black_box(keccak.hash_pair(left, right)));
    });

    let poseidon = PoseidonHasher { pad: false };
    let left = poseidon.hash_leaf(&element(1)).expect("valid element");
    let right = poseidon.hash_leaf(&element(2)).expect("valid element");
    group.bench_function(BenchmarkId::new("hash_pair", "poseidon"), |b| {
        b.iter(|| black_box(poseidon.hash_pair(left, right)));
    });

    let pedersen = PedersenHasher;
    let left = pedersen.hash_leaf(&element(1)).expect("valid element");
    let right = pedersen.hash_leaf(&element(2)).expect("valid element");
    group.bench_function(BenchmarkId::new("hash_pair", "pedersen"), |b| {
        b.iter(|| black_box(pedersen.hash_pair(left, right)));
    });

    let blake = Blake2sHasher { truncate: false };
    let left = blake.hash_leaf(&element(1)).expect("valid element");
    let right = blake.hash_leaf(&element(2)).expect("valid element");
    group.bench_function(BenchmarkId::new("hash_pair", "blake"), |b| {
        b.iter(|| black_box(blake.hash_pair(left, right)));
    });

    group.finish();
}

fn bench_build(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR build");
    for size in [1_000usize, 10_000, 100_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.sample_size(if size >= 100_000 { 10 } else { 20 });
        group.measurement_time(Duration::from_secs(3));
        group.bench_function(BenchmarkId::new("memory", size), |b| {
            b.iter(|| black_box(build_mmr(size)));
        });
    }
    group.finish();
}

fn bench_live_append(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR append live");
    group.throughput(Throughput::Elements(LIVE_APPEND_BATCH as u64));
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));
    group.measurement_time(Duration::from_millis(500));

    // The MMR grows by roughly 10k appends across warmup and measurement
    // (~10% of 100k), so the measured size stays approximately constant.
    let mut mmr = build_mmr(100_000);
    let counter = AtomicUsize::new(100_000);
    group.bench_function("memory/100_000", |b| {
        b.iter_custom(|iters| {
            let start = Instant::now();
            for _ in 0..iters {
                for _ in 0..LIVE_APPEND_BATCH {
                    let i = counter.fetch_add(1, Ordering::Relaxed);
                    mmr.append(&element(i)).expect("append succeeds");
                }
            }
            start.elapsed()
        });
    });
    group.finish();
}

fn bench_get_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR get_proof");
    group.throughput(Throughput::Elements(PROOF_BATCH as u64));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [1_000usize, 10_000, 100_000] {
        let mmr = build_mmr(size);
        let counter = AtomicUsize::new(0);
        group.bench_function(BenchmarkId::new("memory", size), move |b| {
            b.iter(|| {
                let start = counter.fetch_add(PROOF_BATCH, Ordering::Relaxed);
                for i in start..start + PROOF_BATCH {
                    let proof = mmr
                        .proof(LeafIndex::new((i % size) as u64))
                        .expect("proof succeeds");
                    black_box(proof);
                }
            });
        });
    }
    group.finish();
}

fn bench_get_proofs(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR get_proofs");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [10_000usize, 100_000] {
        let mmr = build_mmr(size);
        for k in [1usize, 10, 100, 1_000] {
            group.throughput(Throughput::Elements(k as u64));
            let stride = (size / k).max(1);
            let indexes: Vec<LeafIndex> = (0..k)
                .map(|i| LeafIndex::new((i * stride) as u64))
                .collect();
            group.bench_function(BenchmarkId::new("memory", format!("{size}/k-{k}")), |b| {
                b.iter(|| {
                    black_box(
                        mmr.multiproof(indexes.iter().copied())
                            .expect("multiproof succeeds"),
                    );
                });
            });
        }
    }
    group.finish();
}

fn bench_verify_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR verify_proof");
    group.throughput(Throughput::Elements(1));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [1_000usize, 10_000, 100_000] {
        let mmr = build_mmr(size);
        let leaf = size / 2;
        let proof = mmr
            .proof(LeafIndex::new(leaf as u64))
            .expect("proof succeeds");
        let value = element(leaf);
        // Sanity: the proof must verify before we benchmark verification.
        assert!(
            mmr.verify(&proof, &value).expect("verify succeeds"),
            "sanity: the proof for leaf {leaf} must verify"
        );
        group.bench_function(BenchmarkId::new("memory", size), |b| {
            b.iter(|| {
                let valid = mmr.verify(&proof, &value).expect("verify succeeds");
                black_box(valid)
            });
        });
    }
    group.finish();
}

fn bench_peaks_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR peaks");
    group.throughput(Throughput::Elements(1));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [10_000usize, 100_000] {
        let mmr = build_mmr(size);
        group.bench_function(BenchmarkId::new("get_peaks", size), |b| {
            b.iter(|| black_box(mmr.peaks()));
        });
        group.bench_function(BenchmarkId::new("root", size), |b| {
            b.iter(|| black_box(mmr.root()));
        });
    }
    group.finish();
}

fn bench_draft(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR draft");
    group.throughput(Throughput::Elements(DRAFT_BATCH as u64));
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(5));

    let mut base = build_mmr(10);
    let counter = AtomicUsize::new(0);
    group.bench_function("workflow-1000/ref-memory", |b| {
        b.iter(|| {
            let mut draft = base.start_draft();
            for _ in 0..DRAFT_BATCH {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                draft.append(&element(i)).expect("draft append succeeds");
            }
            match draft.commit(Optimise::Off) {
                Ok(report) => black_box(report),
                Err(failure) => panic!("draft commit failed: {}", failure.into_error()),
            }
        });
    });
    group.finish();
}

fn build_stacked(shared: bool) -> Mmr<Keccak256Hasher, InMemoryStore, kinds::Stacked> {
    let store_for = |i: usize| {
        if shared {
            InMemoryStore::shared(format!("stacked-shared-{i}"))
        } else {
            InMemoryStore::shared(format!("stacked-distinct-{i}"))
        }
    };
    let mut base = Mmr::<Keccak256Hasher, _, kinds::Plain>::create(
        Keccak256Hasher,
        store_for(0),
        AccumulatorId::from_bytes([1; 16]),
    )
    .expect("layer creation succeeds");
    for i in 0..3_300 {
        base.append(&element(i)).expect("append succeeds");
    }
    let first = base.pin();

    let mut second = Mmr::<Keccak256Hasher, _, kinds::Stacked>::stack(
        Keccak256Hasher,
        store_for(1),
        AccumulatorId::from_bytes([2; 16]),
        [first.clone()],
    )
    .expect("stacking succeeds");
    for i in 0..3_300 {
        second.append(&element(3_300 + i)).expect("append succeeds");
    }
    let second_pin = second.pin();

    let mut third = Mmr::<Keccak256Hasher, _, kinds::Stacked>::stack(
        Keccak256Hasher,
        store_for(2),
        AccumulatorId::from_bytes([3; 16]),
        [first, second_pin],
    )
    .expect("stacking succeeds");
    for i in 0..3_400 {
        third.append(&element(6_600 + i)).expect("append succeeds");
    }
    let third_pin = third.pin();

    Mmr::<Keccak256Hasher, _, kinds::Stacked>::stack(
        Keccak256Hasher,
        store_for(3),
        AccumulatorId::from_bytes([4; 16]),
        [third_pin],
    )
    .expect("stacking succeeds")
}

fn bench_stacked(c: &mut Criterion) {
    let mut group = c.benchmark_group("Stacked MMR");
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));

    // Three chained stacked layers of ~3.3k elements each (≈10k total), plus
    // a top layer that starts at the largest pin — in one shared store and in
    // three distinct stores, so the routing/batching overhead difference is
    // visible. Layer k+1 stacks on layer k (each pin freezes the cumulative
    // node count), and the final stack flattens the whole chain.

    for (name, shared) in [
        ("3-stacks-10k-shared", true),
        ("3-stacks-10k-distinct", false),
    ] {
        let mut stacked = build_stacked(shared);
        // Sanity: proofs must generate across the stacks before benchmarking.
        let proof = stacked
            .proof(LeafIndex::new(5_000))
            .expect("proof succeeds");
        assert!(
            stacked
                .verify(&proof, &element(5_000))
                .expect("verification succeeds"),
            "stacked proofs must verify"
        );

        group.throughput(Throughput::Elements(PROOF_BATCH as u64));
        let proof_counter = AtomicUsize::new(0);
        group.bench_function(format!("get_proof/{name}"), |b| {
            b.iter(|| {
                let start = proof_counter.fetch_add(PROOF_BATCH, Ordering::Relaxed);
                for i in start..start + PROOF_BATCH {
                    let proof = stacked
                        .proof(LeafIndex::new(u64::try_from(i % 10_000).unwrap()))
                        .expect("proof succeeds");
                    black_box(proof);
                }
            });
        });

        group.throughput(Throughput::Elements(LIVE_APPEND_BATCH as u64));
        let append_counter = AtomicUsize::new(10_000);
        group.bench_function(format!("append/hot/{name}"), |b| {
            b.iter(|| {
                for _ in 0..LIVE_APPEND_BATCH {
                    let i = append_counter.fetch_add(1, Ordering::Relaxed);
                    stacked.append(&element(i)).expect("append succeeds");
                }
            });
        });
    }
    group.finish();
}

fn bench(c: &mut Criterion) {
    bench_hashers(c);
    bench_build(c);
    bench_live_append(c);
    bench_get_proof(c);
    bench_get_proofs(c);
    bench_verify_proof(c);
    bench_peaks_root(c);
    bench_stacked(c);
    bench_draft(c);
}

criterion_group!(name = benches; config = Criterion::default(); targets = bench);
criterion_main!(benches);
