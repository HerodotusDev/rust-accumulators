//! Sled-store benchmark — same legs as every other `store_*` binary.

#![expect(
    clippy::expect_used,
    reason = "benches fail loudly by design: expect on fixtures is the contract"
)]

mod common;

use std::path::{Path, PathBuf};

use criterion::{Criterion, criterion_group, criterion_main};

use accumulators::store::sled::SledStore;

/// A unique temp database directory for the benchmark, removed with the
/// guard. One directory per benchmark function: the suite isolates build legs
/// by appending under a fresh [`accumulators::ids::AccumulatorId`] per
/// iteration, so no store clearing is needed.
struct BenchDb(PathBuf);

impl BenchDb {
    fn new() -> Self {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        Self(std::env::temp_dir().join(format!(
            "accumulators-bench-sled-{unique}-{}",
            std::process::id()
        )))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for BenchDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sled(c: &mut Criterion) {
    let db = BenchDb::new();
    // Opened once here, outside the timed loops; the shared suite clones the
    // handle (all clones share the database).
    let store = SledStore::open_path(db.path()).expect("sled store opens");

    let mut group = c.benchmark_group("Store");
    common::bench_store_sync(&mut group, "sled", || store.clone());
    group.finish();
}

criterion_group!(benches, sled);
criterion_main!(benches);
