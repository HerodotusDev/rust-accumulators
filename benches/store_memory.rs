//! Memory-store benchmark — same legs as every other `store_*` binary.

mod common;

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;

use accumulators::store::memory::InMemoryStore;

fn memory(c: &mut Criterion) {
    let mut group = c.benchmark_group("Store");
    common::bench_store_sync(&mut group, "memory", InMemoryStore::new);
    group.finish();
}

criterion_group!(benches, memory);
criterion_main!(benches);
