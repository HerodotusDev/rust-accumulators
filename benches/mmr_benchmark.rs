use std::sync::Arc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::sqlite::SQLiteStore,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use tokio::runtime::Runtime;

async fn prepare_mmr(count: usize) -> MMR {
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = SQLiteStore::new(":memory:", None).await.unwrap();

    let store = Arc::new(store);

    let mut mmr = MMR::new(store, hasher, None);

    for i in 0..count {
        let _ = mmr.append(i.to_string()).await.unwrap();
    }

    mmr
}

fn bench(c: &mut Criterion) {
    let rt = Runtime::new().unwrap(); // Create a new Tokio runtime

    let mut group = c.benchmark_group("MMR insertion");
    let inputs = [10_000, 1_000_000];

    for &input in &inputs {
        group.bench_with_input(BenchmarkId::new("times", input), &input, |b, &size| {
            b.iter(|| {
                rt.block_on(async { prepare_mmr(size).await }); // Execute the async function
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
