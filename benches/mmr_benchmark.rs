//! MMR benchmark suite.
//!
//! Groups:
//! - `hasher` - raw [`Hasher::hash_pair`] baseline for every hasher (no MMR, no store)
//! - `MMR build` - cold build from N appends (amortized append throughput)
//! - `MMR append_batch` - cold build from one batched append of N (the
//!   one-batch-write contract; compare against `MMR build`)
//! - `MMR append live` - appends into a pre-built 100k MMR via `iter_custom`, so the
//!   MMR grows only ~10% during the run and steady-state append cost at a large
//!   size is measured
//! - `MMR get_proof` - single-proof generation, batched 10 per iteration
//! - `MMR get_proofs` - multiproof generation for k indexes in one store pass;
//!   the ratio against `MMR get_proof` is the multiproof payoff
//! - `MMR verify_proof` - proof verification (path hashing against the cached root)
//! - `MMR consistency_proof` - consistency-proof generation (one batched read
//!   plus the merge walk) and verification (re-bags both frontiers), taken at
//!   a half-size split of each tree
//! - `MMR peaks` - peak retrieval and root computation (both cache reads)
//! - `MMR nullify` - shallow nullifications, batched ~10 per iteration;
//!   records are dropped before each sample starts (untimed) so every timed
//!   nullify is a real record write, and the rotation window (100k leaves)
//!   keeps one sample's nullifications within a single pass
//! - `Stacked MMR` - proof/multiproof generation and appends routed across 3
//!   stacked sub-MMRs: one shared store, three distinct stores, and the
//!   2-shared + 1-distinct mix; the hot-append leg bounds tree growth with
//!   an append budget + untimed fixture rebuild, so it measures a
//!   steady-state ~100k-leaf hot append
//! - `MMR draft` - `start_draft` + in-memory appends + `commit` workflow,
//!   in both folding modes (`Optimise::Off` reference, `Optimise::On`
//!   folded commit)
//! - `MMR sqlite async` - async shell over the SQLite store (build via one
//!   batched append; proof generation), driven through a tokio runtime
//! - `MMR sqlite async stacked` - the async twin of the `Stacked MMR` group
//!   over one SQLite file (a file is one store, so all layers share it):
//!   chain build via one batched append per layer, proof/multiproof
//!   generation, budgeted hot append, and `open_stacked` reopen
//!
//! MMR-logic benches use `InMemoryStore`, so numbers reflect MMR and hashing
//! cost. The SQLite store is async-only, so it appears in the
//! `MMR sqlite async` and `MMR sqlite async stacked` groups, driven through
//! the `AsyncMmr` shell; drafts exist
//! on the sync shell only, so there is no sqlite draft leg.
//!
//! Sizes are log-spaced; 1M-element legs are excluded by design (~1h for 10
//! samples each).
//!
//! Run: `cargo bench --features all --bench mmr_benchmark -- --save-baseline <name>`
//! Compare later: `cargo bench --features all --bench mmr_benchmark -- --baseline <name>`
//! Results live in `target/criterion` (gitignored).

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![expect(
    clippy::unwrap_used,
    reason = "benchmark fixture unwraps fail loudly by design"
)]
use accumulators::store::{Batch, Store, keys};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use accumulators::{
    hashers::{
        Blake2sStarkHasher, Hasher, KeccakSolHasher, PedersenStarkHasher, PoseidonStarkHasher,
    },
    ids::AccumulatorId,
    mmr::async_mmr::open_stacked_append_only,
    mmr::{
        AppendOnly, AsyncMmr, LeafCount, Mmr, Nullifying, Optimise, bag_peaks, kinds, root_from,
        size_of, verify_consistency_proof,
    },
    primitives::LeafIndex,
    store::memory::InMemoryStore,
    store::sqlite::SqliteStore,
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

/// Appends per timed iteration in the live-append benchmarks.
const LIVE_APPEND_BATCH: usize = 500;
/// Appends per draft in the draft workflow benchmark.
const DRAFT_BATCH: usize = 1_000;
/// Proofs per iteration in the proof-generation benchmarks.
const PROOF_BATCH: usize = 10;
/// Nullifications per iteration in the nullify benchmark.
const NULLIFY_BATCH: usize = 10;
/// Leaves in the nullify benchmark's tree — also the rotation window the
/// leg's nullifications cycle through.
const NULLIFY_LEAVES: usize = 100_000;
/// Layer leaf count of the stacked hot-append fixture (~100k total across
/// the three base layers), sized so the leg's append budget stays ~10%
/// growth between rebuilds.
const STACKED_HOT_LAYER_LEAVES: usize = 33_000;
/// Appends one stacked fixture absorbs before the hot-append leg rebuilds
/// it (~10% growth of the ~100k-leaf fixture).
const STACKED_APPEND_BUDGET: usize = LIVE_APPEND_BATCH * 20;
/// Layer leaf count of the async stacked fixtures: the proof/open fixture
/// uses three layers of this size (10k total, same shape as the sync
/// `Stacked MMR` fixture), the hot-append fixture three layers of
/// [`SQLITE_STACKED_HOT_LAYER_LEAVES`].
const SQLITE_STACKED_LAYER_LEAVES: usize = 3_300;
/// Layer leaf count of the async stacked hot-append fixture (~30k total
/// across the three base layers), sized so the leg's append budget stays
/// ~10% growth between rebuilds.
const SQLITE_STACKED_HOT_LAYER_LEAVES: usize = 10_000;
/// Appends one async stacked fixture absorbs before the hot-append leg
/// rebuilds it (~10% growth of the ~30k-leaf fixture).
const SQLITE_STACKED_APPEND_BUDGET: usize = LIVE_APPEND_BATCH * 6;

/// A valid element for every hasher: the 32-byte big-endian encoding of the
/// index (left-zero-padded, so distinct indexes give distinct elements, and
/// small values stay below the Starknet field modulus).
fn element(index: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(index as u64).to_be_bytes());
    bytes
}

/// A distinct accumulator id per counter value (bench legs reuse one store
/// file and need non-colliding keyspaces).
fn id_from_counter(counter: u64) -> AccumulatorId {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&counter.to_be_bytes());
    AccumulatorId::from_bytes(bytes)
}

/// Builds a plain keccak MMR of `count` leaves, one append (one atomic store
/// batch) at a time — the amortized per-append cost the build group measures.
fn build_mmr(count: usize) -> Mmr<KeccakSolHasher, InMemoryStore> {
    let mut mmr = Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO)
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

    let keccak = KeccakSolHasher;
    let left = keccak.hash_leaf(&element(1)).expect("valid element");
    let right = keccak.hash_leaf(&element(2)).expect("valid element");
    group.bench_function(BenchmarkId::new("hash_pair", "keccak_sol"), |b| {
        b.iter(|| black_box(keccak.hash_pair(left, right)));
    });

    let poseidon = PoseidonStarkHasher { pad: false };
    let left = poseidon.hash_leaf(&element(1)).expect("valid element");
    let right = poseidon.hash_leaf(&element(2)).expect("valid element");
    group.bench_function(BenchmarkId::new("hash_pair", "poseidon_stark"), |b| {
        b.iter(|| black_box(poseidon.hash_pair(left, right)));
    });

    let pedersen = PedersenStarkHasher;
    let left = pedersen.hash_leaf(&element(1)).expect("valid element");
    let right = pedersen.hash_leaf(&element(2)).expect("valid element");
    group.bench_function(BenchmarkId::new("hash_pair", "pedersen_stark"), |b| {
        b.iter(|| black_box(pedersen.hash_pair(left, right)));
    });

    let blake = Blake2sStarkHasher { truncate: false };
    let left = blake.hash_leaf(&element(1)).expect("valid element");
    let right = blake.hash_leaf(&element(2)).expect("valid element");
    group.bench_function(BenchmarkId::new("hash_pair", "blake2s_stark"), |b| {
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
    // Same size set as `MMR get_proof`, so the multiproof payoff ratio is
    // comparable at every size.
    for size in [1_000usize, 10_000, 100_000] {
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

/// Consistency-proof generation and verification at a large size — the
/// gen leg is one batched read plus the merge walk, the verify leg re-bags
/// both frontiers. Mirrors the `verify_proof` legs' shape.
fn bench_consistency_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR consistency_proof");
    group.throughput(Throughput::Elements(1));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    for size in [10_000usize, 100_000] {
        let mmr = build_mmr(size);
        let prev_leaves = (size / 2) as u64;
        let prev_size = size_of(LeafCount::new(prev_leaves));
        let proof = mmr
            .consistency_proof(prev_size)
            .expect("consistency proof succeeds");
        // The two anchors, derived exactly as a verifier would: the earlier
        // root from the proof's own earlier peaks, the later root from the
        // handle's cache.
        let prev_root = root_from(
            &KeccakSolHasher,
            bag_peaks(&KeccakSolHasher, &proof.prev_peaks),
            prev_size,
        );
        // Sanity: the proof must verify before we benchmark verification.
        assert!(
            verify_consistency_proof(&KeccakSolHasher, &proof, prev_root, mmr.root())
                .expect("verify succeeds"),
            "sanity: the consistency proof ({prev_leaves}, {size}) must verify"
        );
        group.bench_function(BenchmarkId::new("gen", size), |b| {
            b.iter(|| {
                let proof = mmr
                    .consistency_proof(prev_size)
                    .expect("consistency proof succeeds");
                black_box(proof)
            });
        });
        group.bench_function(BenchmarkId::new("verify", size), |b| {
            b.iter(|| {
                let valid =
                    verify_consistency_proof(&KeccakSolHasher, &proof, prev_root, mmr.root())
                        .expect("verify succeeds");
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
    // The reference leg replays every buffered op (`Optimise::Off`); the
    // second leg folds each leaf's op sequence to its net effect first
    // (`Optimise::On`), so the ratio shows what folding costs and saves.
    group.bench_function("workflow-1000/ref-memory", |b| {
        b.iter(|| {
            let mut draft = base.start_draft();
            for _ in 0..DRAFT_BATCH {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                draft.append(&element(i)).expect("draft append succeeds");
            }
            match draft.commit(Optimise::Off) {
                Ok(report) => black_box(report),
                Err(failure) => panic!("draft commit failed: {}", failure.error),
            }
        });
    });
    group.bench_function("workflow-1000/fold-on-memory", |b| {
        b.iter(|| {
            let mut draft = base.start_draft();
            for _ in 0..DRAFT_BATCH {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                draft.append(&element(i)).expect("draft append succeeds");
            }
            match draft.commit(Optimise::On) {
                Ok(report) => black_box(report),
                Err(failure) => panic!("draft commit failed: {}", failure.error),
            }
        });
    });
    group.finish();
}

/// How the four stacked layers' stores are laid out. `Shared` is the
/// golden batching case (all layers on one store — one batched call per
/// operation), `Distinct` the no-merge case, `Mixed` the 2-shared +
/// 1-distinct scenario.
#[derive(Clone, Copy)]
enum StackPlan {
    Shared,
    Distinct,
    Mixed,
}

impl StackPlan {
    fn name(self) -> &'static str {
        match self {
            Self::Shared => "3-stacks-10k-shared",
            Self::Distinct => "3-stacks-10k-distinct",
            Self::Mixed => "3-stacks-10k-mixed",
        }
    }
}

fn build_stacked(plan: StackPlan) -> Mmr<KeccakSolHasher, InMemoryStore, kinds::Stacked> {
    build_stacked_sized(plan, 3_300)
}

/// Builds the layered fixture with `layer_leaves` leaves per base layer
/// (the third takes the +100 remainder, so the total is `3n + 100`).
fn build_stacked_sized(
    plan: StackPlan,
    layer_leaves: usize,
) -> Mmr<KeccakSolHasher, InMemoryStore, kinds::Stacked> {
    // Layer stores. `Shared` pins one constant locator so every layer joins
    // one routing group; `Mixed` shares the locator between the first two
    // layers only.
    let store_for = |i: usize| match plan {
        StackPlan::Shared => InMemoryStore::shared("stacked-shared"),
        StackPlan::Distinct => InMemoryStore::shared(format!("stacked-distinct-{i}")),
        StackPlan::Mixed if i < 2 => InMemoryStore::shared("stacked-mixed-shared"),
        StackPlan::Mixed => InMemoryStore::shared(format!("stacked-mixed-{i}")),
    };
    let stores: Vec<InMemoryStore> = (0..4).map(store_for).collect();

    // Setup-time batching-plan sanity: the shared case must collapse to one
    // routing group (all layers same-store), the mixed case to exactly the
    // 2-shared + 1-distinct shape — otherwise the leg would silently
    // measure the unbatched layout again.
    match plan {
        StackPlan::Shared => {
            for window in stores.windows(2) {
                assert!(
                    window[0].same_store(&window[1]),
                    "shared-store leg must put every layer on one store"
                );
            }
        }
        StackPlan::Mixed => {
            assert!(
                stores[0].same_store(&stores[1]),
                "mixed leg: the first two layers share a store"
            );
            for window in stores.windows(2).skip(1) {
                assert!(
                    !window[0].same_store(&window[1]),
                    "mixed leg: remaining layers are distinct stores"
                );
            }
        }
        StackPlan::Distinct => {
            for window in stores.windows(2) {
                assert!(
                    !window[0].same_store(&window[1]),
                    "distinct-store leg must give every layer its own store"
                );
            }
        }
    }

    let mut base = Mmr::<KeccakSolHasher, _, kinds::Plain>::create(
        KeccakSolHasher,
        stores[0].clone(),
        AccumulatorId::from_bytes([1; 16]),
    )
    .expect("layer creation succeeds");
    for i in 0..layer_leaves {
        base.append(&element(i)).expect("append succeeds");
    }
    let first = base.pin();

    let mut second = Mmr::<KeccakSolHasher, _, kinds::Stacked>::stack(
        KeccakSolHasher,
        stores[1].clone(),
        AccumulatorId::from_bytes([2; 16]),
        [first.clone()],
    )
    .expect("stacking succeeds");
    for i in 0..layer_leaves {
        second
            .append(&element(layer_leaves + i))
            .expect("append succeeds");
    }
    let second_pin = second.pin();

    let mut third = Mmr::<KeccakSolHasher, _, kinds::Stacked>::stack(
        KeccakSolHasher,
        stores[2].clone(),
        AccumulatorId::from_bytes([3; 16]),
        [first, second_pin],
    )
    .expect("stacking succeeds");
    for i in 0..(layer_leaves + 100) {
        third
            .append(&element(2 * layer_leaves + i))
            .expect("append succeeds");
    }
    let third_pin = third.pin();

    Mmr::<KeccakSolHasher, _, kinds::Stacked>::stack(
        KeccakSolHasher,
        stores[3].clone(),
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
    // a top layer that starts at the largest pin — in one shared store (all
    // layers merge into one batched call), three distinct stores, and the
    // 2-shared + 1-distinct mix, so the routing/batching overhead difference
    // is visible. Layer k+1 stacks on layer k (each pin freezes the
    // cumulative node count), and the final stack flattens the whole chain.

    for plan in [StackPlan::Shared, StackPlan::Distinct, StackPlan::Mixed] {
        let name = plan.name();
        let stacked = build_stacked(plan);
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

        group.sample_size(30);
        group.measurement_time(Duration::from_secs(3));
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

        group.throughput(Throughput::Elements(PROOF_BATCH as u64));
        for k in [1usize, 10, 100] {
            let stride = (10_000 / k).max(1);
            let indexes: Vec<LeafIndex> = (0..k)
                .map(|i| LeafIndex::new((i * stride) as u64))
                .collect();
            group.bench_function(format!("get_proofs/{name}/k-{k}"), |b| {
                b.iter(|| {
                    black_box(
                        stacked
                            .multiproof(indexes.iter().copied())
                            .expect("multiproof succeeds"),
                    );
                });
            });
        }

        // Steady-state hot append. Stacked appends are cheap enough that a
        // time-bounded run would grow the tree severalfold (unlike
        // `MMR append live`, whose appends are far pricier), so growth is
        // bounded explicitly: the fixture absorbs `STACKED_APPEND_BUDGET`
        // appends (~10% of its ~100k leaves) and is then rebuilt untimed
        // between timed chunks, so every measured append lands on a
        // same-sized tree.
        group.sample_size(10);
        group.warm_up_time(Duration::from_millis(100));
        group.measurement_time(Duration::from_millis(500));
        group.throughput(Throughput::Elements(LIVE_APPEND_BATCH as u64));
        let mut hot = build_stacked_sized(plan, STACKED_HOT_LAYER_LEAVES);
        let mut budget = STACKED_APPEND_BUDGET;
        let append_counter = AtomicUsize::new(10_000);
        group.bench_function(format!("append/hot/{name}"), |b| {
            b.iter_custom(|iters| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iters {
                    if budget == 0 {
                        // Untimed: reset the fixture to its base size so the
                        // next chunk measures the same steady-state tree.
                        hot = build_stacked_sized(plan, STACKED_HOT_LAYER_LEAVES);
                        budget = STACKED_APPEND_BUDGET;
                    }
                    let start = Instant::now();
                    for _ in 0..LIVE_APPEND_BATCH {
                        let i = append_counter.fetch_add(1, Ordering::Relaxed);
                        hot.append(&element(i)).expect("append succeeds");
                    }
                    elapsed += start.elapsed();
                    budget -= LIVE_APPEND_BATCH;
                }
                elapsed
            });
        });
    }
    group.finish();
}

fn bench_append_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR append_batch");
    for size in [500usize, 1_000, 10_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.sample_size(if size >= 10_000 { 10 } else { 20 });
        group.measurement_time(Duration::from_secs(3));
        group.bench_function(BenchmarkId::new("memory", size), |b| {
            b.iter(|| {
                // One `append_batch` call: one batch write for all N appends
                // (the one-batch-write contract; compare against `MMR build`).
                let mut mmr = Mmr::<KeccakSolHasher, _, kinds::Plain, AppendOnly>::create(
                    KeccakSolHasher,
                    InMemoryStore::new(),
                    AccumulatorId::ZERO,
                )
                .expect("mmr creation succeeds");
                let elements: Vec<[u8; 32]> = (0..size).map(element).collect();
                mmr.append_batch(&elements).expect("batch append succeeds");
                black_box(mmr);
            });
        });
    }
    group.finish();
}

fn bench_nullify(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR nullify");
    group.throughput(Throughput::Elements(NULLIFY_BATCH as u64));
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(3));

    // Shallow records never strengthen (first wins), so re-nullifying a
    // leaf would be a read-only no-op. The leg rotates over a 100k-leaf
    // window — large enough that one sample's nullifications stay within a
    // single pass — and drops every record before each sample starts
    // (untimed, direct store deletes), so every timed nullify is a real
    // record write: one batched read miss plus one batched write.
    let store = InMemoryStore::new();
    let id = AccumulatorId::ZERO;
    let mut mmr = Mmr::<KeccakSolHasher, _, kinds::Plain, Nullifying>::create(
        KeccakSolHasher,
        store.clone(),
        id,
    )
    .expect("mmr creation succeeds");
    let elements: Vec<[u8; 32]> = (0..NULLIFY_LEAVES).map(element).collect();
    mmr.append_batch(&elements).expect("batch append succeeds");
    let counter = AtomicUsize::new(0);
    group.bench_function("shallow/memory/100_000", |b| {
        b.iter_custom(|iters| {
            let mut reset = Batch::new();
            for leaf in 0..NULLIFY_LEAVES as u64 {
                reset.delete(keys::encode(&id, keys::Table::Nullifiers, leaf));
            }
            store.write(reset).expect("nullify reset succeeds");
            let start = Instant::now();
            for _ in 0..iters {
                for _ in 0..NULLIFY_BATCH {
                    let i = counter.fetch_add(1, Ordering::Relaxed) % NULLIFY_LEAVES;
                    mmr.nullify_shallow(LeafIndex::new(i as u64))
                        .expect("nullify succeeds");
                }
            }
            start.elapsed()
        });
    });
    group.finish();
}

/// An async SQLite leg harness: a shared tokio runtime drives the async
/// store from the sync bench harness; each leg gets a fresh database file
/// (removed afterwards) so ids never collide across iterations.
struct SqliteLeg {
    runtime: tokio::runtime::Runtime,
    path: std::path::PathBuf,
}

impl SqliteLeg {
    fn new(name: &str) -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self {
            runtime: tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("tokio runtime builds"),
            path: std::env::temp_dir().join(format!(
                "accumulators-bench-{name}-{unique}-{}",
                std::process::id()
            )),
        }
    }
}

impl Drop for SqliteLeg {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn bench_sqlite_async(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR sqlite async");
    for size in [1_000usize, 10_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.sample_size(10);
        group.measurement_time(Duration::from_secs(3));

        let leg = SqliteLeg::new("build");
        let store = leg
            .runtime
            .block_on(SqliteStore::connect(&leg.path))
            .expect("sqlite store opens");
        let id_counter = AtomicU64::new(1);
        group.bench_function(BenchmarkId::new("build-append_batch", size), |b| {
            b.iter(|| {
                let id = id_from_counter(id_counter.fetch_add(1, Ordering::Relaxed));
                let elements: Vec<[u8; 32]> = (0..size).map(element).collect();
                let mmr = leg.runtime.block_on(async {
                    let mut mmr = AsyncMmr::<KeccakSolHasher, _, kinds::Plain>::create(
                        KeccakSolHasher,
                        store.clone(),
                        id,
                    )
                    .await
                    .expect("mmr creation succeeds");
                    mmr.append_batch(&elements)
                        .await
                        .expect("batch append succeeds");
                    mmr
                });
                black_box(mmr);
            });
        });

        // One batched proof read against a pre-built MMR (fresh id per leg
        // size; the tree is built once outside the timed loop).
        let id = id_from_counter(u64::from(u16::try_from(size).unwrap()) << 32);
        let store = leg
            .runtime
            .block_on(SqliteStore::connect(&leg.path))
            .expect("sqlite store opens");
        let mmr = leg.runtime.block_on(async {
            let mut mmr = AsyncMmr::<KeccakSolHasher, _, kinds::Plain>::create(
                KeccakSolHasher,
                store.clone(),
                id,
            )
            .await
            .expect("mmr creation succeeds");
            let elements: Vec<[u8; 32]> = (0..size).map(element).collect();
            mmr.append_batch(&elements)
                .await
                .expect("batch append succeeds");
            mmr
        });
        let leaf = size / 2;
        let proof = leg
            .runtime
            .block_on(mmr.proof(LeafIndex::new(leaf as u64)))
            .expect("proof succeeds");
        // Sanity: the proof must verify before we benchmark generation.
        assert!(
            mmr.verify(&proof, &element(leaf))
                .expect("verification succeeds"),
            "sqlite proof for leaf {leaf} must verify"
        );
        group.throughput(Throughput::Elements(1));
        group.bench_function(BenchmarkId::new("get_proof", size), |b| {
            b.iter(|| {
                let proof = leg
                    .runtime
                    .block_on(mmr.proof(LeafIndex::new(leaf as u64)))
                    .expect("proof succeeds");
                black_box(&proof);
            });
        });
    }
    group.finish();
}

/// Async twin of [`build_stacked_sized`] over SQLite: three chained stacked
/// layers of `layer_leaves` leaves each (the third takes the +100
/// remainder, so the total is `3n + 100`), plus a top layer that starts at
/// the largest pin. A single SQLite file is one store, so the layers always
/// share it (distinct ids per layer) — the golden batching case.
async fn build_stacked_sqlite(
    store: &SqliteStore,
    base_counter: u64,
    layer_leaves: usize,
) -> AsyncMmr<KeccakSolHasher, SqliteStore, kinds::Stacked> {
    let id_of = |offset: u64| id_from_counter(base_counter + offset);

    let mut base = AsyncMmr::<KeccakSolHasher, _, kinds::Plain>::create(
        KeccakSolHasher,
        store.clone(),
        id_of(0),
    )
    .await
    .expect("layer creation succeeds");
    let elements: Vec<[u8; 32]> = (0..layer_leaves).map(element).collect();
    base.append_batch(&elements)
        .await
        .expect("batch append succeeds");
    let first = base.pin();

    let mut second = AsyncMmr::<KeccakSolHasher, _, kinds::Stacked>::stack(
        KeccakSolHasher,
        store.clone(),
        id_of(1),
        [first.clone()],
    )
    .await
    .expect("stacking succeeds");
    let elements: Vec<[u8; 32]> = (layer_leaves..2 * layer_leaves).map(element).collect();
    second
        .append_batch(&elements)
        .await
        .expect("batch append succeeds");
    let second_pin = second.pin();

    let mut third = AsyncMmr::<KeccakSolHasher, _, kinds::Stacked>::stack(
        KeccakSolHasher,
        store.clone(),
        id_of(2),
        [first, second_pin],
    )
    .await
    .expect("stacking succeeds");
    let elements: Vec<[u8; 32]> = (2 * layer_leaves..3 * layer_leaves + 100)
        .map(element)
        .collect();
    third
        .append_batch(&elements)
        .await
        .expect("batch append succeeds");
    let third_pin = third.pin();

    AsyncMmr::<KeccakSolHasher, _, kinds::Stacked>::stack(
        KeccakSolHasher,
        store.clone(),
        id_of(3),
        [third_pin],
    )
    .await
    .expect("stacking succeeds")
}

/// Stacked legs over the async SQLite store, mirroring the `Stacked MMR`
/// sync group. All layers share one store file with distinct ids — a single
/// SQLite file is one store, so the shared layout is the only one a file
/// affords (and the golden batching case).
#[expect(
    clippy::too_many_lines,
    reason = "one leg per benchmark; splitting would hide the shared-fixture structure"
)]
fn bench_sqlite_async_stacked(c: &mut Criterion) {
    let mut group = c.benchmark_group("MMR sqlite async stacked");

    // Build: the full stacked chain from one batched append per layer,
    // into a fresh keyspace per iteration.
    let leg = SqliteLeg::new("stacked-build");
    let store = leg
        .runtime
        .block_on(SqliteStore::connect(&leg.path))
        .expect("sqlite store opens");
    let id_counter = AtomicU64::new(1);
    group.throughput(Throughput::Elements(
        (3 * SQLITE_STACKED_LAYER_LEAVES + 100) as u64,
    ));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("build-append_batch/3-stacks-10k-shared", |b| {
        b.iter(|| {
            let base = id_counter.fetch_add(4, Ordering::Relaxed);
            let stacked = leg.runtime.block_on(build_stacked_sqlite(
                &store,
                base,
                SQLITE_STACKED_LAYER_LEAVES,
            ));
            black_box(stacked)
        });
    });

    // Proof/multiproof generation against a pre-built fixture (built once
    // outside the timed loops).
    let leg = SqliteLeg::new("stacked-proof");
    let store = leg
        .runtime
        .block_on(SqliteStore::connect(&leg.path))
        .expect("sqlite store opens");
    let stacked = leg.runtime.block_on(build_stacked_sqlite(
        &store,
        1_000,
        SQLITE_STACKED_LAYER_LEAVES,
    ));
    let proof = leg
        .runtime
        .block_on(stacked.proof(LeafIndex::new(5_000)))
        .expect("proof succeeds");
    assert!(
        stacked
            .verify(&proof, &element(5_000))
            .expect("verification succeeds"),
        "sqlite stacked proof for leaf 5000 must verify"
    );
    group.throughput(Throughput::Elements(PROOF_BATCH as u64));
    let proof_counter = AtomicUsize::new(0);
    group.bench_function("get_proof/3-stacks-10k-shared", |b| {
        b.iter(|| {
            let start = proof_counter.fetch_add(PROOF_BATCH, Ordering::Relaxed);
            for i in start..start + PROOF_BATCH {
                let proof = leg
                    .runtime
                    .block_on(stacked.proof(LeafIndex::new(u64::try_from(i % 10_000).unwrap())))
                    .expect("proof succeeds");
                black_box(proof);
            }
        });
    });

    for k in [1usize, 10, 100] {
        let stride = (10_000 / k).max(1);
        let indexes: Vec<LeafIndex> = (0..k)
            .map(|i| LeafIndex::new((i * stride) as u64))
            .collect();
        group.throughput(Throughput::Elements(k as u64));
        group.bench_function(format!("get_proofs/3-stacks-10k-shared/k-{k}"), |b| {
            b.iter(|| {
                black_box(
                    leg.runtime
                        .block_on(stacked.multiproof(indexes.iter().copied()))
                        .expect("multiproof succeeds"),
                );
            });
        });
    }

    // Steady-state hot append, bounded like the sync stacked leg: the
    // fixture absorbs `SQLITE_STACKED_APPEND_BUDGET` appends (~10% of its
    // ~30k leaves) and is then rebuilt untimed between timed chunks, so
    // every measured append lands on a same-sized tree.
    let leg = SqliteLeg::new("stacked-hot");
    let store = leg
        .runtime
        .block_on(SqliteStore::connect(&leg.path))
        .expect("sqlite store opens");
    let mut hot = leg.runtime.block_on(build_stacked_sqlite(
        &store,
        1_000,
        SQLITE_STACKED_HOT_LAYER_LEAVES,
    ));
    let mut budget = SQLITE_STACKED_APPEND_BUDGET;
    let append_counter = AtomicUsize::new(3 * SQLITE_STACKED_HOT_LAYER_LEAVES + 100);
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(100));
    group.measurement_time(Duration::from_millis(500));
    group.throughput(Throughput::Elements(LIVE_APPEND_BATCH as u64));
    group.bench_function("append/hot/3-stacks-30k-shared", |b| {
        b.iter_custom(|iters| {
            let mut elapsed = Duration::ZERO;
            for _ in 0..iters {
                if budget == 0 {
                    // Untimed: reset the fixture to its base size so the
                    // next chunk measures the same steady-state tree.
                    hot = leg.runtime.block_on(build_stacked_sqlite(
                        &store,
                        1_000,
                        SQLITE_STACKED_HOT_LAYER_LEAVES,
                    ));
                    budget = SQLITE_STACKED_APPEND_BUDGET;
                }
                let start = Instant::now();
                for _ in 0..LIVE_APPEND_BATCH {
                    let i = append_counter.fetch_add(1, Ordering::Relaxed);
                    leg.runtime
                        .block_on(hot.append(&element(i)))
                        .expect("append succeeds");
                }
                elapsed += start.elapsed();
                budget -= LIVE_APPEND_BATCH;
            }
            elapsed
        });
    });

    // Reopen: `open_stacked` rebuilds every layer from the persisted
    // sub-view record and store locators — what the file-backed store is
    // for (the in-memory stacked legs cannot reopen at all).
    let leg = SqliteLeg::new("stacked-open");
    let store = leg
        .runtime
        .block_on(SqliteStore::connect(&leg.path))
        .expect("sqlite store opens");
    let fixture = leg.runtime.block_on(build_stacked_sqlite(
        &store,
        1_000,
        SQLITE_STACKED_LAYER_LEAVES,
    ));
    let id = id_from_counter(1_003); // the top layer's id
    let reopened = leg
        .runtime
        .block_on(open_stacked_append_only(KeccakSolHasher, store.clone(), id))
        .expect("reopen succeeds");
    assert_eq!(
        reopened.root(),
        fixture.root(),
        "sanity: reopen must reproduce the fixture root"
    );
    group.throughput(Throughput::Elements(1));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("open_stacked/3-stacks-10k-shared", |b| {
        b.iter(|| {
            let reopened = leg
                .runtime
                .block_on(open_stacked_append_only(KeccakSolHasher, store.clone(), id))
                .expect("reopen succeeds");
            black_box(reopened)
        });
    });

    group.finish();
}

fn bench(c: &mut Criterion) {
    bench_hashers(c);
    bench_build(c);
    bench_append_batch(c);
    bench_live_append(c);
    bench_get_proof(c);
    bench_get_proofs(c);
    bench_verify_proof(c);
    bench_consistency_proof(c);
    bench_peaks_root(c);
    bench_nullify(c);
    bench_stacked(c);
    bench_draft(c);
    bench_sqlite_async(c);
    bench_sqlite_async_stacked(c);
}

criterion_group!(name = benches; config = Criterion::default(); targets = bench);
criterion_main!(benches);
