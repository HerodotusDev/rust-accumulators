//! Benchmarks for the incremental Merkle tree (`accumulators::merkle`).
//!
//! Groups:
//! - `IncrementalMerkleTree initialize` - create the empty tree and persist
//!   metadata. Constant cost since the redesign (v0.5 materialized every
//!   node, `O(size)`); sizes are tree depths. The v0.5 sqlite variant is
//!   dropped: the redesigned tree is sync-only and the SQLite store is
//!   async-only.
//! - `IncrementalMerkleTree set_leaf` - repeated gated leaf writes against a
//!   live tree (update gate + path rewrite + one atomic batch), batched 10
//!   per iteration.
//! - `IncrementalMerkleTree get_inclusion_proof` - sibling retrieval for a
//!   leaf, batched 10 per iteration, against a fully occupied tree (v0.5
//!   semantics: every leaf has a materialized sibling path).
//! - `IncrementalMerkleTree verify_proof` - proof verification (pure path
//!   hashing, no store access).
//! - `IncrementalMerkleTree multiproof` - minimal sibling set for k scattered
//!   leaves in one store pass.
//! - `IncrementalMerkleTree verify_multi` - multiproof verification.
//!
//! Proof-family benches beyond `TREE_DEPTH` run against ~10k scattered
//! occupied leaves (a full materialization at depth 20 would be 1M writes);
//! the multiproof payoff is unaffected since dedup works on the index set.
//!
//! Run: `cargo bench --features all --bench incremental_benchmark -- --save-baseline <name>`
//! Compare later: `cargo bench --features all --bench incremental_benchmark -- --baseline <name>`
//! Results live in `target/criterion` (gitignored).

use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use accumulators::{
    hashers::{Hasher, Keccak256Hasher},
    ids::AccumulatorId,
    merkle::IncrementalMerkleTree,
    primitives::{Hash, LeafIndex},
    store::memory::InMemoryStore,
};
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};

/// Leaf writes per timed iteration in the set-leaf benchmark.
const UPDATE_BATCH: usize = 10;
/// Proofs per iteration in the proof-generation benchmarks.
const PROOF_BATCH: usize = 10;
/// Depth of the single-leg tree: capacity `2^14 = 16_384`, the v0.5 suite's
/// `TREE_SIZE`.
const TREE_DEPTH: u8 = 14;
/// Tree capacity at [`TREE_DEPTH`], in leaves.
const TREE_SIZE: usize = 16_384;
/// Depths for the create (sparse init) benchmark.
const INIT_DEPTHS: [u8; 4] = [8, 12, 16, 20];
/// Depths for the multiproof benchmarks.
const MULTIPROOF_DEPTHS: [u8; 3] = [12, 16, 20];
/// Leaves per multiproof.
const MULTIPROOF_KS: [usize; 3] = [1, 10, 100];
/// Occupied-leaf target for the scattered multiproof trees.
const OCCUPIED_TARGET: usize = 10_000;

/// A valid element for every hasher: the 32-byte big-endian encoding of the
/// index (left-zero-padded, so distinct indexes give distinct elements).
fn element(index: usize) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[24..].copy_from_slice(&(index as u64).to_be_bytes());
    bytes
}

/// An empty keccak tree of `depth` levels with the all-zero null leaf.
fn build_tree(depth: u8) -> IncrementalMerkleTree<Keccak256Hasher, InMemoryStore> {
    IncrementalMerkleTree::create(
        Keccak256Hasher,
        InMemoryStore::new(),
        AccumulatorId::ZERO,
        depth,
        Hash::ZERO,
    )
    .expect("tree creation succeeds")
}

/// Occupies `count` leaves of `tree`, scattered by stride over the capacity,
/// and returns the root after the last write (the authoritative current root
/// — see [`IncrementalMerkleTree::set_leaf`]).
///
/// Proof benches run against an occupied tree so sibling reads hit the store
/// (v0.5 semantics) instead of collapsing to ladder lookups.
fn occupy_scattered(
    tree: &mut IncrementalMerkleTree<Keccak256Hasher, InMemoryStore>,
    count: usize,
) -> Hash {
    let capacity = usize::try_from(tree.capacity()).expect("capacity fits usize");
    let stride = (capacity / count).max(1);
    let mut root = tree.root();
    for leaf in (0..capacity).step_by(stride).take(count) {
        root = tree
            .set_leaf(LeafIndex::new(leaf as u64), &element(leaf), None)
            .expect("leaf write succeeds")
            .root;
    }
    root
}

fn bench(c: &mut Criterion) {
    let mut group = c.benchmark_group("IncrementalMerkleTree initialize");
    for depth in INIT_DEPTHS {
        group.throughput(Throughput::Elements(1));
        group.sample_size(20);
        group.measurement_time(Duration::from_secs(3));
        group.bench_function(BenchmarkId::new("memory", depth), |b| {
            b.iter(|| black_box(build_tree(depth)));
        });
    }
    group.finish();

    let mut tree = build_tree(TREE_DEPTH);
    let leaf = LeafIndex::new(5);
    // Occupy the target leaf once; the benchmark then rewrites it in place,
    // gated on the current value (the v0.5 `update` semantics).
    let mut current = Keccak256Hasher
        .hash_leaf(&element(0))
        .expect("valid element");
    tree.set_leaf(leaf, &element(0), None)
        .expect("leaf write succeeds");

    let mut group = c.benchmark_group("IncrementalMerkleTree set_leaf");
    group.throughput(Throughput::Elements(UPDATE_BATCH as u64));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    let counter = AtomicUsize::new(1);
    group.bench_function("memory/16384", |b| {
        b.iter(|| {
            for _ in 0..UPDATE_BATCH {
                let i = counter.fetch_add(1, Ordering::Relaxed);
                tree.set_leaf(leaf, &element(i), Some(current))
                    .expect("gated write succeeds");
                current = Keccak256Hasher
                    .hash_leaf(&element(i))
                    .expect("valid element");
            }
        });
    });
    group.finish();

    let mut tree = build_tree(TREE_DEPTH);
    // Fully occupy: every leaf has a materialized sibling path, mirroring the
    // v0.5 initialized tree.
    let root = occupy_scattered(&mut tree, TREE_SIZE);
    bench_proof_legs(c, &tree, root);

    for (group_name, verify) in [
        ("IncrementalMerkleTree multiproof", false),
        ("IncrementalMerkleTree verify_multi", true),
    ] {
        let mut group = c.benchmark_group(group_name);
        group.sample_size(30);
        group.measurement_time(Duration::from_secs(3));
        for depth in MULTIPROOF_DEPTHS {
            let mut tree = build_tree(depth);
            occupy_scattered(&mut tree, OCCUPIED_TARGET);
            for &k in &MULTIPROOF_KS {
                bench_multiproof_leg(&mut group, &tree, depth, k, verify);
            }
        }
        group.finish();
    }
}

/// The single-leaf proof legs against the fully occupied depth-14 tree:
/// `get_inclusion_proof` (batched 10/iter) and `verify_proof` (pure hashing).
fn bench_proof_legs(
    c: &mut Criterion,
    tree: &IncrementalMerkleTree<Keccak256Hasher, InMemoryStore>,
    root: Hash,
) {
    let mut group = c.benchmark_group("IncrementalMerkleTree get_inclusion_proof");
    group.throughput(Throughput::Elements(PROOF_BATCH as u64));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    let counter = AtomicUsize::new(0);
    group.bench_function("memory/16384", |b| {
        b.iter(|| {
            for _ in 0..PROOF_BATCH {
                let index = counter.fetch_add(1, Ordering::Relaxed) % TREE_SIZE;
                let proof = tree
                    .proof(LeafIndex::new(index as u64))
                    .expect("proof succeeds");
                black_box(proof);
            }
        });
    });
    group.finish();

    let proof_leaf = TREE_SIZE / 2;
    let proof = tree
        .proof(LeafIndex::new(proof_leaf as u64))
        .expect("proof succeeds");
    assert!(
        tree.verify(
            LeafIndex::new(proof_leaf as u64),
            &element(proof_leaf),
            &proof,
            root,
        )
        .expect("verify succeeds"),
        "sanity: the proof for leaf {proof_leaf} must verify"
    );
    let mut group = c.benchmark_group("IncrementalMerkleTree verify_proof");
    group.throughput(Throughput::Elements(1));
    group.sample_size(30);
    group.measurement_time(Duration::from_secs(3));
    group.bench_function("memory/16384", |b| {
        b.iter(|| {
            let valid = tree
                .verify(
                    LeafIndex::new(proof_leaf as u64),
                    &element(proof_leaf),
                    &proof,
                    root,
                )
                .expect("verify succeeds");
            black_box(valid)
        });
    });
    group.finish();
}

/// One (depth, k) leg of the multiproof or verify-multi group.
fn bench_multiproof_leg(
    group: &mut BenchmarkGroup<'_, WallTime>,
    tree: &IncrementalMerkleTree<Keccak256Hasher, InMemoryStore>,
    depth: u8,
    k: usize,
    verify: bool,
) {
    let capacity = usize::try_from(tree.capacity()).expect("capacity fits usize");
    group.throughput(Throughput::Elements(k as u64));
    let stride = (capacity / k).max(1);
    let leaf_numbers: Vec<usize> = (0..k).map(|i| (i * stride) % capacity).collect();
    let indexes: Vec<LeafIndex> = leaf_numbers
        .iter()
        .map(|&leaf| LeafIndex::new(leaf as u64))
        .collect();
    if verify {
        let elements: Vec<[u8; 32]> = leaf_numbers.iter().map(|&leaf| element(leaf)).collect();
        let multi = tree
            .multiproof(indexes.iter().copied())
            .expect("multiproof succeeds");
        // No standalone sanity assert here on purpose: `verify_multi`
        // checks against the tree's own `root()`, which the tree must track
        // correctly for the result to be meaningful (asserted in
        // tests/merkle.rs).
        group.bench_function(
            BenchmarkId::new("memory", format!("depth-{depth}/k-{k}")),
            |b| {
                b.iter(|| {
                    let valid = tree
                        .verify_multi(&multi, &elements)
                        .expect("verify succeeds");
                    black_box(valid)
                });
            },
        );
    } else {
        group.bench_function(
            BenchmarkId::new("memory", format!("depth-{depth}/k-{k}")),
            |b| {
                b.iter(|| {
                    black_box(
                        tree.multiproof(indexes.iter().copied())
                            .expect("multiproof succeeds"),
                    );
                });
            },
        );
    }
}

criterion_group!(name = benches; config = Criterion::default(); targets = bench);
criterion_main!(benches);
