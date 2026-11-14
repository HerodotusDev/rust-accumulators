//! Benchmarks for `IncrementalMerkleTree`.
//!
//! Groups:
//! - `initialize` - build the empty tree of N leaves and persist it
//! - `update` - repeated leaf updates against a live tree (proof verification +
//!   path rewrite); the same leaf is updated so proofs stay valid
//! - `get_inclusion_proof` - sibling retrieval for a leaf, batched 10 per iteration
//!
//! The sqlite variant of `initialize` quantifies persistence overhead; the
//! update and proof benches use `InMemoryStore` so numbers reflect tree and
//! hashing cost.
//!
//! Run: `cargo bench --features all --bench incremental_benchmark -- --save-baseline <name>`
//! Compare later: `cargo bench --features all --bench incremental_benchmark -- --baseline <name>`
//! Results live in `target/criterion` (gitignored).

use std::hint::black_box;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher,
    merkle_tree::incremental::IncrementalMerkleTree,
    store::{Store, memory::InMemoryStore, sqlite::SQLiteStore},
};
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use tokio::runtime::Runtime;

const UPDATE_BATCH: usize = 10;
const PROOF_BATCH: usize = 10;
/// Power of two: every level of the tree is complete, so all leaves have valid
/// proofs. Non-power-of-2 sizes hit unpadded virtual nodes (see known issue:
/// `get_inclusion_proof` errors for leaves under right-padded sub-trees).
const TREE_SIZE: usize = 16_384;

fn element(index: usize) -> String {
    format!("0x{index:062x}")
}

async fn build_tree(
    store: Arc<dyn Store>,
    size: usize,
) -> IncrementalMerkleTree<StarkPoseidonHasher> {
    let hasher = StarkPoseidonHasher::new(Some(false));
    IncrementalMerkleTree::initialize(size, "0x0".to_string(), hasher, store, None)
        .await
        .unwrap()
}

fn bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    let mut group = c.benchmark_group("IncrementalMerkleTree initialize");
    for size in [10_000usize, 100_000] {
        group.throughput(Throughput::Elements(size as u64));
        group.sample_size(if size >= 100_000 { 10 } else { 20 });
        group.measurement_time(Duration::from_secs(3));
        group.bench_function(BenchmarkId::new("memory", size), |b| {
            b.iter(|| {
                black_box(rt.block_on(build_tree(
                    Arc::new(InMemoryStore::new(Some("bench"))),
                    size,
                )))
            });
        });
    }
    group.throughput(Throughput::Elements(TREE_SIZE as u64));
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    group.bench_function(BenchmarkId::new("sqlite", TREE_SIZE), |b| {
        b.iter(|| {
            rt.block_on(async {
                let store = SQLiteStore::new(":memory:", None, Some("bench"))
                    .await
                    .unwrap();
                black_box(build_tree(Arc::new(store), TREE_SIZE).await)
            })
        });
    });
    group.finish();

    let tree = rt.block_on(build_tree(
        Arc::new(InMemoryStore::new(Some("bench"))),
        TREE_SIZE,
    ));

    let mut group = c.benchmark_group("IncrementalMerkleTree update");
    group.throughput(Throughput::Elements(UPDATE_BATCH as u64));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    let proof = rt.block_on(tree.get_inclusion_proof(5)).unwrap();
    let counter = AtomicUsize::new(0);
    let mut current = "0x0".to_string();
    group.bench_function("memory/10000", |b| {
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..UPDATE_BATCH {
                    let new_value = element(counter.fetch_add(1, Ordering::Relaxed));
                    let old_value = std::mem::replace(&mut current, new_value.clone());
                    let root = tree
                        .update(5, old_value, new_value, proof.clone())
                        .await
                        .unwrap();
                    black_box(root);
                }
            });
        });
    });
    group.finish();

    let mut group = c.benchmark_group("IncrementalMerkleTree get_inclusion_proof");
    group.throughput(Throughput::Elements(PROOF_BATCH as u64));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    let counter = AtomicUsize::new(0);
    group.bench_function("memory/10000", |b| {
        b.iter(|| {
            rt.block_on(async {
                for _ in 0..PROOF_BATCH {
                    let index = counter.fetch_add(1, Ordering::Relaxed) % TREE_SIZE;
                    let proof = tree.get_inclusion_proof(index).await.unwrap();
                    black_box(proof);
                }
            });
        });
    });
    group.finish();
}

criterion_group!(name = benches; config = Criterion::default(); targets = bench);
criterion_main!(benches);
