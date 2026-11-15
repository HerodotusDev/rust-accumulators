//! Batched-I/O call-count contracts: the audit-facing "one
//! batched read per proof, one batch write per mutation" guarantees, pinned
//! with a counting store so a batching regression fails loudly.
//!
//! Call counts (not just outcomes) are the contract here — the sibling test
//! suites already pin roots and outcomes; these tests pin how many store
//! calls producing them costs.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "memory",
    feature = "keccak_sol",
    feature = "stacked_mmr",
    feature = "draft_mmr",
    feature = "merkle_tree"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use accumulators::hashers::KeccakSolHasher;
use accumulators::ids::AccumulatorId;
use accumulators::merkle::IncrementalMerkleTree;
use accumulators::mmr::{Mmr, Optimise, Plain, Stacked};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::memory::InMemoryStore;
use accumulators::store::{Batch, Retrievable, Store, StoreLocator};

#[path = "common/mod.rs"]
mod common;

use common::{element, id};

/// An [`InMemoryStore`] wrapper that counts batched read/write calls.
///
/// Counters live behind `Arc` so clones share them: a stacked MMR's layers
/// hold cloned handles, and the contract is about the *storage* call count,
/// not per-handle calls.
#[derive(Clone, Debug)]
struct CountingStore {
    inner: InMemoryStore,
    reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}

impl CountingStore {
    fn shared(locator: &str) -> Self {
        Self {
            inner: InMemoryStore::shared(locator),
            reads: Arc::new(AtomicUsize::new(0)),
            writes: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// A clone sharing the same underlying storage *and* the same counters.
    fn handle(&self) -> Self {
        self.clone()
    }

    fn read_count(&self) -> usize {
        self.reads.load(Ordering::Relaxed)
    }

    fn write_count(&self) -> usize {
        self.writes.load(Ordering::Relaxed)
    }

    fn reset(&self) {
        self.reads.store(0, Ordering::Relaxed);
        self.writes.store(0, Ordering::Relaxed);
    }
}

impl accumulators::store::Storage for CountingStore {
    type Error = core::convert::Infallible;
}

impl Store for CountingStore {
    fn read(&self, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.read(keys)
    }

    fn write(&self, batch: Batch<'_>) -> Result<(), Self::Error> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.write(batch)
    }

    fn same_store(&self, other: &Self) -> bool {
        self.inner.same_store(&other.inner)
    }

    fn locator(&self) -> Option<StoreLocator> {
        self.inner.locator()
    }
}

impl Retrievable for CountingStore {
    fn canonical_locator(&self) -> StoreLocator {
        self.inner.canonical_locator()
    }

    fn open(locator: &StoreLocator) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: InMemoryStore::open(locator)?,
            reads: Arc::new(AtomicUsize::new(0)),
            writes: Arc::new(AtomicUsize::new(0)),
        })
    }
}

// ------------------------------------------------------------- plain MMR

#[test]
fn append_batch_is_one_write() {
    let store = CountingStore::shared("batching-append-batch");
    let mut mmr = Mmr::<KeccakSolHasher, _, Plain>::create(KeccakSolHasher, store.handle(), id(1))
        .expect("mmr creation succeeds");
    store.reset();

    let elements: Vec<Vec<u8>> = (0..100).map(element).collect();
    mmr.append_batch(&elements).expect("batch append succeeds");

    assert_eq!(store.write_count(), 1, "batch append = one batch write");
    assert_eq!(store.read_count(), 0, "appends never read");
}

#[test]
fn proof_is_one_batched_read() {
    let store = CountingStore::shared("batching-proof");
    let mut mmr = Mmr::<KeccakSolHasher, _, Plain>::create(KeccakSolHasher, store.handle(), id(2))
        .expect("mmr creation succeeds");
    let elements: Vec<Vec<u8>> = (0..50).map(element).collect();
    mmr.append_batch(&elements).expect("batch append succeeds");
    store.reset();

    let proof = mmr.proof(LeafIndex::new(17)).expect("proof succeeds");
    assert!(mmr.verify(&proof, &element(17)).expect("verify succeeds"));

    assert_eq!(store.read_count(), 1, "proof = one batched read");
    assert_eq!(store.write_count(), 0, "proofs never write");
}

#[test]
fn multiproof_is_one_batched_read() {
    let store = CountingStore::shared("batching-multiproof");
    let mut mmr = Mmr::<KeccakSolHasher, _, Plain>::create(KeccakSolHasher, store.handle(), id(3))
        .expect("mmr creation succeeds");
    let elements: Vec<Vec<u8>> = (0..200).map(element).collect();
    mmr.append_batch(&elements).expect("batch append succeeds");
    store.reset();

    let leaves: Vec<LeafIndex> = (0..20_u64).map(LeafIndex::new).collect();
    let proof = mmr
        .multiproof(leaves.iter().copied())
        .expect("multiproof succeeds");
    assert!(
        mmr.verify_multi(
            &proof,
            leaves
                .iter()
                .map(|leaf| &elements[usize::try_from(leaf.get()).expect("leaf in range")]),
        )
        .expect("verify succeeds"),
        "the multiproof must verify over the selected elements"
    );

    // Elements + sibling pool resolve in ONE load call (C3); adjacent
    // leaves share parents, so the dedup collapses the pool below the total
    // reference count.
    assert_eq!(store.read_count(), 1, "multiproof = one batched read");
    assert!(
        proof.sibling_pool.len() < proof.sibling_refs.len(),
        "sibling dedup: pool ({}) < total refs ({})",
        proof.sibling_pool.len(),
        proof.sibling_refs.len()
    );
}

#[test]
fn update_is_one_read_and_one_write() {
    let store = CountingStore::shared("batching-update");
    let mut mmr = Mmr::<KeccakSolHasher, _, Plain, accumulators::mmr::Editable>::create(
        KeccakSolHasher,
        store.handle(),
        id(4),
    )
    .expect("mmr creation succeeds");
    let elements: Vec<Vec<u8>> = (0..50).map(element).collect();
    mmr.append_batch(&elements).expect("batch append succeeds");
    store.reset();

    mmr.update(LeafIndex::new(5), b"new-value", None)
        .expect("update succeeds");

    assert_eq!(store.read_count(), 1, "leaf + siblings in one batched read");
    assert_eq!(store.write_count(), 1, "one batch write");
}

// ------------------------------------------------------------- stacked MMR

/// Two layers over ONE shared store: proof = one batched read (the
/// golden case — same-store layers merge into one routing group).
#[test]
fn stacked_proof_over_a_shared_store_is_one_batched_read() {
    let store = CountingStore::shared("batching-stacked-shared");
    let mut base = Mmr::<KeccakSolHasher, _, Plain>::create(KeccakSolHasher, store.handle(), id(5))
        .expect("base creation succeeds");
    let elements: Vec<Vec<u8>> = (0..20).map(element).collect();
    base.append_batch(&elements).expect("batch append succeeds");
    let pin = base.pin();

    let stacked =
        Mmr::<KeccakSolHasher, _, Stacked>::stack(KeccakSolHasher, store.handle(), id(6), [pin])
            .expect("stacking succeeds");
    store.reset();

    let proof = stacked.proof(LeafIndex::new(5)).expect("proof succeeds");
    assert!(
        stacked
            .verify(&proof, &element(5))
            .expect("verify succeeds")
    );

    assert_eq!(
        store.read_count(),
        1,
        "shared-store stacked proof = one batched read across both layers"
    );
    assert_eq!(store.write_count(), 0);
}

/// Two layers over DISTINCT stores: proof = one batched read per store.
#[test]
fn stacked_proof_over_distinct_stores_is_one_read_per_store() {
    let shared_counters = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
    let make_store = |locator: String| CountingStore {
        inner: InMemoryStore::shared(locator),
        reads: Arc::clone(&shared_counters.0),
        writes: Arc::clone(&shared_counters.1),
    };

    let mut base = Mmr::<KeccakSolHasher, _, Plain>::create(
        KeccakSolHasher,
        make_store("batching-stacked-a".into()),
        id(7),
    )
    .expect("base creation succeeds");
    let elements: Vec<Vec<u8>> = (0..20).map(element).collect();
    base.append_batch(&elements).expect("batch append succeeds");
    let pin = base.pin();

    let stacked = Mmr::<KeccakSolHasher, _, Stacked>::stack(
        KeccakSolHasher,
        make_store("batching-stacked-b".into()),
        id(8),
        [pin],
    )
    .expect("stacking succeeds");
    // Give the top layer its own leaves (in its own store) so a multiproof
    // can span both stores.
    let top_elements: Vec<Vec<u8>> = (20..40).map(element).collect();
    let mut stacked = stacked;
    stacked
        .append_batch(&top_elements)
        .expect("append succeeds");
    shared_counters.0.store(0, Ordering::Relaxed);

    let leaves = [LeafIndex::new(5), LeafIndex::new(30)];
    let proof = stacked
        .multiproof(leaves.iter().copied())
        .expect("multiproof succeeds");
    assert!(
        stacked
            .verify_multi(&proof, [&elements[5], &top_elements[10]])
            .expect("verify succeeds"),
        "the cross-layer multiproof must verify"
    );

    assert_eq!(
        shared_counters.0.load(Ordering::Relaxed),
        2,
        "distinct stores: exactly one batched read per store"
    );
}

// ---------------------------------------------------------------- drafts

#[test]
fn draft_commit_of_consecutive_appends_is_one_write() {
    let store = CountingStore::shared("batching-draft-appends");
    let mut base = Mmr::<KeccakSolHasher, _, Plain>::create(KeccakSolHasher, store.handle(), id(9))
        .expect("base creation succeeds");
    base.append(b"seed").expect("append succeeds");
    store.reset();

    let mut draft = base.start_draft();
    let elements: Vec<Vec<u8>> = (0..200).map(element).collect();
    draft
        .append_batch(&elements)
        .expect("draft append succeeds");
    let report = match draft.commit(Optimise::Off) {
        Ok(report) => report,
        Err(failure) => panic!("commit failed: {}", failure.error),
    };

    assert_eq!(report.appended.get(), 200);
    assert_eq!(
        store.write_count(),
        1,
        "consecutive appends coalesce into one batch write"
    );
    assert_eq!(store.read_count(), 0, "appends never read");
}

#[test]
fn draft_commit_of_a_nullify_run_is_one_write() {
    let store = CountingStore::shared("batching-draft-nullifies");
    let mut base = Mmr::<KeccakSolHasher, _, Plain, accumulators::mmr::Nullifying>::create(
        KeccakSolHasher,
        store.handle(),
        id(10),
    )
    .expect("base creation succeeds");
    let elements: Vec<Vec<u8>> = (0..50).map(element).collect();
    base.append_batch(&elements).expect("batch append succeeds");
    store.reset();

    let mut draft = base.start_draft();
    for leaf in [1_u64, 4, 9, 16, 25] {
        draft
            .nullify_shallow(LeafIndex::new(leaf))
            .expect("nullify buffers");
    }
    match draft.commit(Optimise::Off) {
        Ok(_) => {}
        Err(failure) => panic!("commit failed: {}", failure.error),
    }

    assert_eq!(
        store.write_count(),
        1,
        "a run of nullifications commits as one batched write"
    );
    assert_eq!(
        store.read_count(),
        1,
        "existing records resolve in one batched read"
    );
}

// -------------------------------------------------------------- nullifying

#[test]
fn replace_shallow_is_one_write() {
    let store = CountingStore::shared("batching-replace-shallow");
    let mut mmr = Mmr::<KeccakSolHasher, _, Plain, accumulators::mmr::Nullifying>::create(
        KeccakSolHasher,
        store.handle(),
        id(11),
    )
    .expect("mmr creation succeeds");
    let elements: Vec<Vec<u8>> = (0..50).map(element).collect();
    mmr.append_batch(&elements).expect("batch append succeeds");
    store.reset();

    let outcome = mmr
        .replace_shallow(LeafIndex::new(7), b"replacement")
        .expect("replace succeeds");

    assert_eq!(
        store.write_count(),
        1,
        "the nullifier record and the append delta share one atomic batch"
    );
    assert_eq!(store.read_count(), 1, "existing record read in one call");
    assert_eq!(outcome.nullified, LeafIndex::new(7));
    assert_eq!(outcome.appended.leaf, LeafIndex::new(50));

    // And the leaf is actually nullified + the tree grew.
    assert!(matches!(
        mmr.proof(LeafIndex::new(7)),
        Err(accumulators::mmr::MmrError::LeafNullified { .. })
    ));
    assert_eq!(mmr.leaf_count().get(), 51);
}

// ----------------------------------------------------------------- merkle

#[test]
fn merkle_set_leaf_is_one_batched_read() {
    let store = CountingStore::shared("batching-merkle");
    let mut tree = IncrementalMerkleTree::<KeccakSolHasher, _, AccumulatorId>::create(
        KeccakSolHasher,
        store.handle(),
        id(12),
        10,
        Hash::ZERO,
    )
    .expect("tree creation succeeds");
    store.reset();

    tree.set_leaf(LeafIndex::new(5), b"leaf-5", None)
        .expect("set_leaf succeeds");

    assert_eq!(
        store.read_count(),
        1,
        "leaf + every sibling heap in one batched read"
    );
    assert_eq!(store.write_count(), 1, "one batch write");
}
