//! Heapless-store benchmark — same legs as every other `store_*` binary.
//!
//! The bench store is boxed: the fixed-capacity map is heap-placed so the
//! bench binary's stack frames stay small (an inline 2+ MiB store times
//! several live copies overflows an 8 MiB main-thread stack). The store's
//! code path and inline-array layout are unchanged — only where the buffer
//! lives differs, matching the `memory` backend's heap placement.
//!
//! Capacity note: every leg writes into a fresh store per iteration — the
//! batch-append leg clones the empty [`BenchStore`] and fills the clone's
//! fresh keyspace, so no leg mutates a shared tree and a full measurement
//! session never accumulates state across iterations. `BENCH_ENTRIES` is
//! sized for the largest single iteration (the 10 000-leaf build leg's node
//! count, plus headroom), never for cumulative growth. Run this binary for
//! parity checks (`cargo bench --bench store_heapless -- --test`) and
//! bounded comparisons, not for unbounded soak runs.

mod common;

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;
use std::boxed::Box;
use std::vec::Vec;

use accumulators::store::heapless::{HeaplessError, HeaplessStore};
use accumulators::store::{Batch, Storage, Store};

/// Node count of the largest single-iteration workload, the 10 000-leaf
/// build leg (`2n − popcount(n)`), plus headroom.
const BENCH_ENTRIES: usize = 24_576;
/// The bench keys are 26 bytes (16-byte `AccumulatorId` + tag + subkey).
const BENCH_KEY_CAP: usize = 32;
/// The bench values are 32-byte hashes and 8-byte counters.
const BENCH_VAL_CAP: usize = 48;

type BenchStore = HeaplessStore<BENCH_ENTRIES, BENCH_KEY_CAP, BENCH_VAL_CAP>;

/// A [`BenchStore`] behind a `Box`, so the criterion harness never holds
/// the multi-megabyte inline map on its stack.
struct BoxedHeaplessStore(Box<BenchStore>);

impl core::fmt::Debug for BoxedHeaplessStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.0, f)
    }
}

impl Clone for BoxedHeaplessStore {
    fn clone(&self) -> Self {
        Self(Box::new((*self.0).clone()))
    }
}

impl Storage for BoxedHeaplessStore {
    type Error = HeaplessError;
}

impl Store for BoxedHeaplessStore {
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        self.0.read(keys)
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        self.0.write(batch)
    }
}

fn heapless(c: &mut Criterion) {
    let mut group = c.benchmark_group("Store");
    common::bench_store_sync(&mut group, "heapless", || {
        BoxedHeaplessStore(Box::new(BenchStore::new()))
    });
    group.finish();
}

criterion_group!(benches, heapless);
criterion_main!(benches);
