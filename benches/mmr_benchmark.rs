use accumulators::{
    core::CoreMMR,
    hash::{stark_poseidon::StarkPoseidonHasher, IHasher},
    store::sqlite::SQLiteStore,
};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn prepare_mmr(count: usize) -> CoreMMR<SQLiteStore, StarkPoseidonHasher> {
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = SQLiteStore::new(":memory:").unwrap();
    store.init().expect("Failed to init store");

    let mut mmr = CoreMMR::new(store, hasher.clone(), None);

    for i in 0..count {
        let value = hasher.hash_single(&i.to_string());
        let _ = mmr.append(value).unwrap();
    }

    mmr
}

fn bench(c: &mut Criterion) {
    {
        let mut group = c.benchmark_group("MMR insertion");
        let inputs = [10_000, 1_000_000];

        for input in inputs.iter() {
            group.bench_with_input(BenchmarkId::new("times", input), &input, |b, &&size| {
                b.iter(|| prepare_mmr(size));
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
