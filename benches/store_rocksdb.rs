//! `RocksDB`-store benchmark — same legs as every other `store_*` binary.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::Criterion;
use criterion::criterion_group;
use criterion::criterion_main;

use accumulators::store::rocksdb::{RocksdbConfig, RocksdbStore};

/// Builds a fresh `RocksDB` store under one temp root per benchmark run:
/// unique subdirectory per call, so the build leg's fresh-keyspace
/// iterations never share state, and the whole root is removed on cleanup.
struct BenchStores {
    root: PathBuf,
    counter: AtomicU64,
}

impl BenchStores {
    fn new() -> Self {
        Self {
            root: std::env::temp_dir()
                .join(format!("accumulators-rocksdb-bench-{}", std::process::id())),
            counter: AtomicU64::new(0),
        }
    }

    fn make(&self) -> RocksdbStore {
        let path = self.root.join(format!(
            "db-{}",
            self.counter.fetch_add(1, Ordering::Relaxed)
        ));
        RocksdbStore::open(RocksdbConfig::new(path)).expect("bench store opens")
    }

    /// Removes the benchmark databases. Every handle is dropped by the time
    /// this runs, so the destroy is uncontended; best-effort on failure.
    fn cleanup(&self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn rocksdb(c: &mut Criterion) {
    let stores = BenchStores::new();
    let mut group = c.benchmark_group("Store");
    common::bench_store_sync(&mut group, "rocksdb", || stores.make());
    group.finish();
    stores.cleanup();
}

criterion_group!(benches, rocksdb);
criterion_main!(benches);
