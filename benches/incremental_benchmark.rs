use std::rc::Rc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, merkle_tree::incremental::IncrementalMerkleTree,
    store::sqlite::SQLiteStore,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn prepare_incremental(count: usize) -> IncrementalMerkleTree<StarkPoseidonHasher> {
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = SQLiteStore::new(":memory:").unwrap();
    store.init().expect("Failed to init store");
    let store = Rc::new(store);

    IncrementalMerkleTree::initialize(count, "0x0".to_string(), hasher, store, None)
}

fn bench(c: &mut Criterion) {
    {
        let mut group = c.benchmark_group("Incremental Merkle Tree insertion");
        let inputs = [10_000, 1_000_000];

        for input in inputs.iter() {
            group.bench_with_input(BenchmarkId::new("times", input), &input, |b, &&size| {
                b.iter(|| prepare_incremental(size));
            });
        }
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = bench
);
criterion_main!(benches);
