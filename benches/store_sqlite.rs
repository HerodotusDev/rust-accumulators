//! SQLite-store benchmark — same legs as every other `store_*` binary.

#![expect(
    clippy::expect_used,
    reason = "benches fail loudly by design: expect on fixtures is the contract"
)]

mod common;

use std::path::{Path, PathBuf};

use criterion::{Criterion, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use accumulators::store::sqlite::SqliteStore;

/// A unique temp database file for the benchmark, removed with the guard.
/// One file per benchmark function: the suite isolates build legs by
/// appending under a fresh [`AccumulatorId`] per iteration, so no store
/// clearing is needed and the file only ever grows.
struct BenchDb(PathBuf);

impl BenchDb {
    fn new() -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self(std::env::temp_dir().join(format!(
            "accumulators-bench-sqlite-{unique}-{}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for BenchDb {
    fn drop(&mut self) {
        let name = self.0.to_string_lossy();
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{name}{suffix}"));
        }
    }
}

fn sqlite(c: &mut Criterion) {
    let runtime = Runtime::new().expect("tokio runtime builds");
    let db = BenchDb::new();
    // Opened once here, outside the timed loops; the shared suite clones the
    // handle (all clones share the pool).
    let store = runtime
        .block_on(SqliteStore::connect(db.path()))
        .expect("sqlite store opens");

    let mut group = c.benchmark_group("Store");
    common::bench_store_async(&mut group, "sqlite", &runtime, || store.clone());
    group.finish();
}

criterion_group!(benches, sqlite);
criterion_main!(benches);
