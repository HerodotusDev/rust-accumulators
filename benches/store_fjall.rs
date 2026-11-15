//! Fjall-store benchmark — same legs as every other `store_*` binary.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]

mod common;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use criterion::{Criterion, criterion_group, criterion_main};

use accumulators::store::fjall::{FjallConfig, FjallStore};

/// Unique temp database folder removed on drop, so benchmark runs never
/// leave fjall folders behind (including on ctrl-C through a panic path).
struct TempKeyspaceDir(PathBuf);

impl TempKeyspaceDir {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "accumulators-fjall-{label}-{}-{id}",
            std::process::id()
        )))
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempKeyspaceDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn fjall(c: &mut Criterion) {
    let mut group = c.benchmark_group("Store");

    // One database for the whole run; every leg isolates itself under a
    // fresh accumulator id, so make_store just hands out clones.
    let dir = TempKeyspaceDir::new("bench");
    let store = FjallStore::open(FjallConfig::new(dir.path())).expect("fjall store opens");
    common::bench_store_sync(&mut group, "fjall", move || store.clone());

    group.finish();
}

criterion_group!(benches, fjall);
criterion_main!(benches);
