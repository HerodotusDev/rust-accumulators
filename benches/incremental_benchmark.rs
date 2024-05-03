use std::sync::Arc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, merkle_tree::incremental::IncrementalMerkleTree,
    store::sqlite::SQLiteStore,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::runtime::Runtime;

async fn prepare_incremental(count: usize) -> IncrementalMerkleTree<StarkPoseidonHasher> {
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = SQLiteStore::new(":memory:", None, Some("test"))
        .await
        .unwrap();

    let store = Arc::new(store);

    IncrementalMerkleTree::initialize(count, "0x0".to_string(), hasher, store, None)
        .await
        .unwrap()
}

fn bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap(); // Create a new Tokio runtime

    let mut group = c.benchmark_group("Incremental Merkle Tree insertion");
    let inputs = [10_000, 1_000_000];

    for &input in &inputs {
        group.bench_with_input(BenchmarkId::new("times", input), &input, |b, &size| {
            b.iter(|| {
                rt.block_on(async { prepare_incremental(size).await }); // Execute the async function
            });
        });
    }

    group.finish();
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
);
criterion_main!(benches);
