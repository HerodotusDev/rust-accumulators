//! Redb-store benchmark — same legs as every other `store_*` binary, so
//! criterion numbers are directly comparable across backends.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};

use accumulators::store::redb::RedbStore;

static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);

/// A factory handing out a store on a fresh temp file per call, tracking
/// every path for cleanup once the benchmark legs have run.
fn make_factory() -> (impl Fn() -> RedbStore + 'static, Arc<Mutex<Vec<PathBuf>>>) {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let tracked = Arc::clone(&paths);
    let factory = move || {
        let path = std::env::temp_dir().join(format!(
            "accumulators-bench-redb-{}-{}.redb",
            std::process::id(),
            NEXT_DB_ID.fetch_add(1, Ordering::Relaxed)
        ));
        tracked
            .lock()
            .expect("the path registry is only poisoned by a panicking bench")
            .push(path.clone());
        RedbStore::open_path(&path).expect("bench redb opens")
    };
    (factory, paths)
}

fn redb(c: &mut Criterion) {
    let (factory, paths) = make_factory();
    let mut group = c.benchmark_group("Store");
    common::bench_store_sync(&mut group, "redb", factory);
    group.finish();

    // All store handles (and their file locks) are gone with
    // bench_store_sync's scope, so every temp file is removable.
    if let Ok(paths) = paths.lock() {
        for path in paths.iter() {
            let _ = std::fs::remove_file(path);
        }
    }
}

criterion_group!(benches, redb);
criterion_main!(benches);
