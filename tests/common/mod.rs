//! Shared test fixtures — the suites' common spine.
//!
//! The brute-force reference oracles here are the independent ground truth
//! every root/peaks assertion leans on (built purely on [`Hasher::hash_leaf`]
//! and [`Hasher::hash_pair`] — never on the crate's state core), so they live
//! in exactly one place instead of drifting across per-suite copies.
//!
//! Also home to the fault-injection store wrapper (atomicity / error-
//! preservation tests and the store conformance suite) and the panic-safe
//! temp-database guard. Each integration-test crate compiles its own copy of
//! this module via `mod common;`, hence the blanket `dead_code` allowance:
//! not every copy uses every helper.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![allow(
    dead_code,
    reason = "each test crate compiles its own copy of this shared module and uses a subset"
)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use accumulators::hashers::Hasher;
use accumulators::ids::AccumulatorId;
#[cfg(feature = "mmr")]
use accumulators::mmr::{LeafCount, MmrSize};
use accumulators::primitives::{Hash, HashValue};
use accumulators::store::{AsyncStore, Batch, Store};
#[cfg(feature = "mmr")]
use accumulators::utils::mmr::size_of;

// ------------------------------------------------------------------ fixtures

pub fn element(index: u64) -> Vec<u8> {
    format!("element-{index}").into_bytes()
}

pub fn elements(count: u64) -> Vec<Vec<u8>> {
    (0..count).map(element).collect()
}

pub fn slices(elements: &[Vec<u8>]) -> Vec<&[u8]> {
    elements.iter().map(Vec::as_slice).collect()
}

pub fn id(byte: u8) -> AccumulatorId {
    AccumulatorId::from_bytes([byte; 16])
}

// -------------------------------------------------------------------- oracle

/// Brute-force peaks over raw leaf hashes: leaf hashes merged with
/// `trailing_ones` pair merges per append, peaks left in discovery order.
/// Independent of the crate's state core — only `hash_leaf`/`hash_pair`.
pub fn peaks_of_hashes<H: Hasher>(hasher: &H, leaf_hashes: &[H::Output]) -> Vec<H::Output> {
    let mut peaks: Vec<H::Output> = Vec::new();
    for (index, hash) in leaf_hashes.iter().enumerate() {
        peaks.push(*hash);
        for _ in 0..(index as u64).trailing_ones() {
            let right = peaks.pop().expect("merge consumes a right peak");
            let left = peaks.pop().expect("merge consumes a left peak");
            peaks.push(hasher.hash_pair(left, right));
        }
    }
    peaks
}

/// Brute-force reference root over raw leaf hashes: bag the peaks
/// right-to-left with the leftmost peak outermost, then bind
/// `root = H(node_count, bag)`.
pub fn root_of_hashes<H: Hasher>(hasher: &H, leaf_hashes: &[H::Output]) -> H::Output {
    let peaks = peaks_of_hashes(hasher, leaf_hashes);
    let leaves = leaf_hashes.len() as u64;
    let size = 2 * leaves - u64::from(leaves.count_ones());
    let bag = match peaks.len() {
        0 => hasher.genesis(),
        1 => peaks[0],
        n => {
            let mut acc = hasher.hash_pair(peaks[n - 2], peaks[n - 1]);
            for peak in peaks[..n - 2].iter().rev() {
                acc = hasher.hash_pair(*peak, acc);
            }
            acc
        }
    };
    hasher.hash_pair(H::Output::from_u64(size), bag)
}

/// Element hashes of the given raw elements (all valid for the byte hashers
/// the suites use).
pub fn leaf_hashes<H: Hasher>(hasher: &H, elements: &[&[u8]]) -> Vec<H::Output> {
    elements
        .iter()
        .map(|element| {
            hasher
                .hash_leaf(element)
                .expect("the suite's elements are valid for this hasher")
        })
        .collect()
}

/// Brute-force peaks for raw elements (element-level convenience wrapper
/// over [`peaks_of_hashes`]).
pub fn reference_peaks<H: Hasher>(hasher: &H, elements: &[&[u8]]) -> Vec<H::Output> {
    peaks_of_hashes(hasher, &leaf_hashes(hasher, elements))
}

/// Brute-force reference root for raw elements (element-level convenience
/// wrapper over [`root_of_hashes`]).
pub fn reference_root<H: Hasher>(hasher: &H, elements: &[&[u8]]) -> H::Output {
    root_of_hashes(hasher, &leaf_hashes(hasher, elements))
}

/// Naive level-wise reference root for a fixed-capacity sparse Merkle tree:
/// all `2^depth` leaf slots are materialized — `hash_leaf(element)` for each
/// occupied index, the zero ladder's null leaf for the rest — then folded up
/// level by level. Built only on the hasher primitives, never on the crate's
/// tree or planner code.
pub fn reference_merkle_root<H: Hasher, E: AsRef<[u8]>>(
    hasher: &H,
    depth: u8,
    null_leaf: H::Output,
    occupied: &[(u64, E)],
) -> H::Output {
    assert!(
        (1..=63).contains(&depth),
        "reference_merkle_root: depth {depth} is outside the valid range 1..=63"
    );
    let mut sorted: Vec<(u64, &E)> = occupied
        .iter()
        .map(|(index, element)| (*index, element))
        .collect();
    sorted.sort_unstable_by_key(|&(index, _)| index);

    let capacity = 1_u64 << depth;
    let mut level: Vec<H::Output> = Vec::with_capacity(1_usize << depth);
    let mut cursor = 0;
    for index in 0..capacity {
        level.push(match sorted.get(cursor) {
            Some(&(leaf_index, element)) if leaf_index == index => {
                cursor += 1;
                hasher
                    .hash_leaf(element.as_ref())
                    .expect("the suite's elements are valid for this hasher")
            }
            _ => null_leaf,
        });
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| hasher.hash_pair(pair[0], pair[1]))
            .collect();
    }
    level[0]
}

/// Effective leaf hashes of a composed draft view: the base hashes with the
/// buffered edits applied (update → the new hash, delete → genesis) and the
/// buffered appends appended. The flat oracle for every prefix root a
/// composed view can serve — built only on `hash_leaf`, never on the crate's
/// state core.
pub fn composed_hashes<H: Hasher>(
    hasher: &H,
    base: usize,
    edits: &[(usize, Option<Vec<u8>>)],
    appended: &[Vec<u8>],
) -> Vec<H::Output> {
    let mut composed = leaf_hashes(hasher, &slices(&elements(base as u64)));
    for (leaf, replacement) in edits {
        composed[*leaf] = match replacement {
            Some(element) => hasher.hash_leaf(element).expect("valid element"),
            None => hasher.genesis(),
        };
    }
    composed.extend(leaf_hashes(hasher, &slices(appended)));
    composed
}

/// Reference roots for every prefix of `values`.
pub fn prefix_roots<H: Hasher>(hasher: &H, values: &[H::Output]) -> Vec<H::Output> {
    (0..=values.len())
        .map(|leaves| root_of_hashes(hasher, &values[..leaves]))
        .collect()
}

/// Node-count sizes for leaf counts `0..=count`.
#[cfg(feature = "mmr")]
pub fn node_sizes(count: usize) -> Vec<MmrSize> {
    (0..=count)
        .map(|leaves| size_of(LeafCount::new(leaves as u64)))
        .collect()
}

/// The root with its first byte flipped — the tamper anchor for `Ok(false)`
/// assertions.
pub fn flipped(root: Hash) -> Hash {
    let mut bytes = root.to_vec();
    bytes[0] ^= 0x01;
    HashValue::from_bytes(&bytes).expect("32 bytes")
}

// -------------------------------------------------------------------- faults

/// The error a [`FaultyStore`] injects — inert, only ever surfaced wrapped in
/// `MmrError::Store` / `TreeError::Store`.
#[derive(Debug)]
pub struct MockError;

impl core::fmt::Display for MockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("injected mock failure")
    }
}

impl core::error::Error for MockError {}

/// A [`FaultyStore`]'s error axis: the injected [`MockError`] (the fault seam
/// firing) or the wrapped backend's own error, passed through untouched so a
/// real backend failure is never swallowed by the wrapper.
#[derive(Debug)]
pub enum FaultError<E> {
    /// The injected test fault.
    Injected(MockError),
    /// The wrapped backend's own error.
    Backend(E),
}

impl<E: core::fmt::Display> core::fmt::Display for FaultError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Injected(error) => core::fmt::Display::fmt(error, f),
            Self::Backend(error) => core::fmt::Display::fmt(error, f),
        }
    }
}

impl<E: core::error::Error + 'static> core::error::Error for FaultError<E> {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Injected(error) => Some(error),
            Self::Backend(error) => Some(error),
        }
    }
}

/// Shared fault switches + call counters for [`FaultyStore`].
#[derive(Debug, Default)]
pub struct Fault {
    fail_writes: AtomicBool,
    fail_reads: AtomicBool,
    /// Absolute write-call count at which writes start failing; `0` disarms
    /// the threshold. Set through [`Fault::arm_write_failure_after`].
    fail_writes_from: AtomicUsize,
    writes: AtomicUsize,
    reads: AtomicUsize,
}

impl Fault {
    pub fn fail_writes(&self, on: bool) {
        self.fail_writes.store(on, Ordering::Relaxed);
    }

    pub fn fail_reads(&self, on: bool) {
        self.fail_reads.store(on, Ordering::Relaxed);
    }

    /// Arms the write-failure threshold: the `additional`-th write counted
    /// from this call onward fails — and so does every write after it, until
    /// the threshold is disarmed with `arm_write_failure_after(0)`. Composes
    /// with `fail_writes(false)`: this seam fires *mid-replay* (after earlier
    /// writes of the same logical operation succeeded), which `fail_writes`
    /// cannot express.
    pub fn arm_write_failure_after(&self, additional: usize) {
        if additional == 0 {
            self.fail_writes_from.store(0, Ordering::Relaxed);
            return;
        }
        let baseline = self.writes.load(Ordering::Relaxed);
        self.fail_writes_from
            .store(baseline + additional, Ordering::Relaxed);
    }

    pub fn write_calls(&self) -> usize {
        self.writes.load(Ordering::Relaxed)
    }

    pub fn read_calls(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }

    /// Whether the write at the given (already incremented) call count must
    /// fail.
    fn write_fails(&self, call: usize) -> bool {
        if self.fail_writes.load(Ordering::Relaxed) {
            return true;
        }
        let threshold = self.fail_writes_from.load(Ordering::Relaxed);
        threshold != 0 && call >= threshold
    }
}

/// A store wrapper with injectable write/read failures and call counters —
/// the seam the atomicity, error-preservation and conformance tests hang on.
///
/// The seam fires **before the wrapped backend is reached** — that is the
/// wrapper-level error-preservation contract (a failed write must leave the
/// store untouched and surface as a typed error). It deliberately cannot
/// observe a backend's *internal* transaction; each file backend's own
/// mid-write fault seam lives in its backend test (`store_redb.rs`,
/// the `sqlite_backend` module of `conformance.rs`), where the fault fires
/// inside the backend's transaction.
///
/// `Clone` shares the fault switches and counters (a stacked MMR's layers
/// hold cloned handles; the contract is about the storage, not the handle).
#[derive(Clone, Debug)]
pub struct FaultyStore<S> {
    inner: S,
    fault: Arc<Fault>,
}

impl<S> FaultyStore<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            fault: Arc::new(Fault::default()),
        }
    }

    pub fn fault(&self) -> &Fault {
        &self.fault
    }

    pub fn inner(&self) -> &S {
        &self.inner
    }
}

impl<S: accumulators::store::Storage> accumulators::store::Storage for FaultyStore<S> {
    type Error = FaultError<S::Error>;
}

impl<S: Store> Store for FaultyStore<S> {
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        self.fault.reads.fetch_add(1, Ordering::Relaxed);
        if self.fault.fail_reads.load(Ordering::Relaxed) {
            return Err(FaultError::Injected(MockError));
        }
        self.inner.read(keys).map_err(FaultError::Backend)
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        self.fault.writes.fetch_add(1, Ordering::Relaxed);
        if self.fault.write_fails(self.fault.write_calls()) {
            return Err(FaultError::Injected(MockError));
        }
        self.inner.write(batch).map_err(FaultError::Backend)
    }

    fn same_store(&self, other: &Self) -> bool {
        self.inner.same_store(&other.inner)
    }

    fn locator(&self) -> Option<accumulators::store::StoreLocator> {
        self.inner.locator()
    }
}

impl<S: AsyncStore + Send + Sync> AsyncStore for FaultyStore<S> {
    async fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        self.fault.reads.fetch_add(1, Ordering::Relaxed);
        if self.fault.fail_reads.load(Ordering::Relaxed) {
            return Err(FaultError::Injected(MockError));
        }
        self.inner.read(keys).await.map_err(FaultError::Backend)
    }

    async fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        self.fault.writes.fetch_add(1, Ordering::Relaxed);
        if self.fault.write_fails(self.fault.write_calls()) {
            return Err(FaultError::Injected(MockError));
        }
        self.inner.write(batch).await.map_err(FaultError::Backend)
    }

    fn same_store(&self, other: &Self) -> bool {
        self.inner.same_store(&other.inner)
    }

    fn locator(&self) -> Option<accumulators::store::StoreLocator> {
        self.inner.locator()
    }
}

// ------------------------------------------------------------------ temp dbs

static NEXT_DB_ID: AtomicU64 = AtomicU64::new(0);

/// A unique temp database file removed on drop — including on test panics,
/// so a failing test never leaks `.db`/`-wal`/`-shm` files into the temp dir.
pub struct TempDb(PathBuf);

impl TempDb {
    pub fn new(label: &str) -> Self {
        let id = NEXT_DB_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "accumulators-{label}-{}-{id}.db",
            std::process::id()
        )))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl core::fmt::Debug for TempDb {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TempDb({})", self.0.display())
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let name = self.0.to_string_lossy();
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{name}{suffix}"));
        }
    }
}

/// A unique temp directory removed recursively on drop — including on test
/// panics, so a failing test never leaks directory-backed database folders
/// (sled's heap files, fjall's keyspaces, `RocksDB`'s SST/WAL trees) into
/// the temp dir. The directory-variant twin of [`TempDb`].
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        let id = NEXT_DB_ID.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!(
            "accumulators-dir-{label}-{}-{id}",
            std::process::id()
        )))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl core::fmt::Debug for TempDir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "TempDir({})", self.0.display())
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
