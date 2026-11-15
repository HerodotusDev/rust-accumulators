//! Consistency-proof test suite: exhaustive prefix verification against a
//! brute-force reference, adversarial fabrication, degenerate sizes,
//! peaks-only floors, stacked routing, single-batched-read generation, and
//! serde round-trips.
//!
//! Every root assertion leans on the shared brute-force oracle (built
//! directly on [`Hasher::hash_leaf`]/[`Hasher::hash_pair`] — never on the
//! crate's state core).

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(
    feature = "mmr",
    feature = "memory",
    feature = "keccak_sol",
    feature = "blake2s_stark"
))]

#[path = "common/mod.rs"]
mod common;

use accumulators::hashers::{Blake2sStarkHasher, Hasher, KeccakSolHasher};
use accumulators::mmr::{
    ConsistencyProof, Mmr, MmrError, MmrSize, VerifyError, WithPeaks, verify_consistency_proof,
};
use accumulators::mmr::{LeafCount, size_of};
use accumulators::primitives::{Hash, HashValue};
use accumulators::store::memory::InMemoryStore;

use common::{FaultyStore, element, elements, id, leaf_hashes, root_of_hashes, slices};

type TestMmr = Mmr<KeccakSolHasher, InMemoryStore>;
type BlakeDigest = <Blake2sStarkHasher as Hasher>::Output;

// ---------------------------------------------------------------- helpers

fn hasher() -> KeccakSolHasher {
    KeccakSolHasher
}

fn mmr_with(count: u64, byte: u8) -> TestMmr {
    let mut mmr: TestMmr =
        Mmr::create(hasher(), InMemoryStore::new(), id(byte)).expect("fixture MMR creation");
    for element in elements(count) {
        mmr.append(&element).expect("fixture append");
    }
    mmr
}

/// Independent reference roots for every prefix of `count` elements.
fn reference_roots<H: Hasher>(hasher: &H, count: usize) -> Vec<H::Output> {
    let all_hashes = leaf_hashes(hasher, &slices(&elements(count as u64)));
    (0..=count)
        .map(|leaves| root_of_hashes(hasher, &all_hashes[..leaves]))
        .collect()
}

/// Node-count sizes for leaf counts `0..=count`.
fn node_sizes(count: usize) -> Vec<MmrSize> {
    (0..=count)
        .map(|leaves| size_of(LeafCount::new(leaves as u64)))
        .collect()
}

fn flipped(root: Hash) -> Hash {
    let mut bytes = root.to_vec();
    bytes[0] ^= 0x01;
    HashValue::from_bytes(&bytes).expect("32 bytes")
}

// ----------------------------------------------------------- exhaustive

mod exhaustive {
    use super::*;

    /// Every pair 0 ≤ n ≤ m ≤ 600: the proof generated at (n, m) must
    /// verify against the two independently-computed reference roots.
    #[test]
    fn every_prefix_pair_verifies() {
        const LIMIT: usize = 600;
        let h = hasher();
        let roots = reference_roots(&h, LIMIT);
        let sizes = node_sizes(LIMIT);
        let elements = elements(LIMIT as u64);

        let mut mmr: TestMmr = Mmr::create(h, InMemoryStore::new(), id(1)).expect("create");
        for m in 0..=LIMIT {
            if m > 0 {
                mmr.append(&elements[m - 1]).expect("append must succeed");
            }
            assert_eq!(mmr.size(), sizes[m], "size tracking at {m}");
            for n in 0..=m {
                let proof = mmr
                    .consistency_proof(sizes[n])
                    .unwrap_or_else(|error| panic!("consistency proof ({n}, {m}) failed: {error}"));
                assert_eq!(proof.prev_size, sizes[n]);
                assert_eq!(proof.size, sizes[m]);
                match verify_consistency_proof(&h, &proof, roots[n], roots[m]) {
                    Ok(true) => {}
                    other => panic!("consistency ({n}, {m}) must verify: {other:?}"),
                }
            }
        }
    }

    /// Spot checks across power-of-two boundaries well past the exhaustive
    /// range — where peak shapes change most abruptly.
    #[test]
    fn boundary_sizes_spot_checks() {
        const LIMIT: usize = 5_000;
        let h = hasher();
        let targets = [1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 5000];
        let samples = [0_usize, 1, 2, 3, 5, 17, 100, 511, 512, 1023];

        let mut mmr: TestMmr = Mmr::create(h, InMemoryStore::new(), id(2)).expect("create");
        let all = elements(LIMIT as u64);
        for m in 1..=LIMIT {
            mmr.append(&all[m - 1]).expect("append must succeed");
            if !targets.contains(&m) {
                continue;
            }
            for &n in &samples {
                if n > m {
                    continue;
                }
                let proof = mmr
                    .consistency_proof(size_of(LeafCount::new(n as u64)))
                    .expect("consistency proof must generate");
                let prev_root = root_of_hashes(&h, &leaf_hashes(&h, &slices(&all[..n])));
                let root = root_of_hashes(&h, &leaf_hashes(&h, &slices(&all[..m])));
                assert!(
                    matches!(
                        verify_consistency_proof(&h, &proof, prev_root, root),
                        Ok(true)
                    ),
                    "consistency ({n}, {m}) must verify"
                );
            }
            // Trivial prefix at the boundary.
            let proof = mmr
                .consistency_proof(size_of(LeafCount::new(m as u64)))
                .expect("trivial prefix must generate");
            assert!(matches!(
                verify_consistency_proof(&h, &proof, mmr.root(), mmr.root()),
                Ok(true)
            ));
        }
    }

    /// A second hasher — different genesis, different digests, same layout.
    /// Blake2s requires 4-byte-aligned elements, so this test drives its own
    /// fixture.
    #[test]
    fn works_for_blake2s_stark_too() {
        let h = Blake2sStarkHasher::default();
        let blake_elements: Vec<[u8; 32]> = (0..40_u8).map(|i| [i; 32]).collect();
        let blake_slices: Vec<&[u8]> = blake_elements.iter().map(<[u8; 32]>::as_slice).collect();
        let hashes = leaf_hashes(&h, &blake_slices);
        let roots: Vec<BlakeDigest> = (0..=40_usize)
            .map(|leaves| root_of_hashes(&h, &hashes[..leaves]))
            .collect();
        let sizes = node_sizes(40);
        let mut mmr: Mmr<Blake2sStarkHasher, InMemoryStore> =
            Mmr::create(h, InMemoryStore::new(), id(3)).expect("create");
        for (i, blake_element) in blake_elements.iter().enumerate() {
            mmr.append(blake_element).expect("append must succeed");
            for n in 0..=i {
                let proof = mmr
                    .consistency_proof(sizes[n])
                    .expect("consistency proof must generate");
                assert!(
                    matches!(
                        verify_consistency_proof(&h, &proof, roots[n], roots[i + 1]),
                        Ok(true)
                    ),
                    "blake consistency ({n}, {}) must verify",
                    i + 1
                );
            }
        }
    }

    /// The degenerate sizes verify without any store history: empty → m,
    /// n → n, and empty → empty.
    #[test]
    fn degenerate_sizes_verify() {
        let h = hasher();
        let roots = reference_roots(&h, 20);
        let sizes = node_sizes(20);
        let mmr = mmr_with(20, 4);

        // Empty prefix: prev_peaks empty, path = the MMR's peaks.
        for m in [1_usize, 7, 8, 9, 20] {
            let target = mmr_with(m as u64, 4);
            let proof = target
                .consistency_proof(MmrSize::ZERO)
                .expect("empty prefix must generate");
            assert_eq!(proof.prev_peaks.len(), 0);
            let empty_root = root_of_hashes(&h, &[]);
            assert!(
                matches!(
                    verify_consistency_proof(&h, &proof, empty_root, roots[m]),
                    Ok(true)
                ),
                "empty → {m} must verify"
            );
        }
        // Empty → empty.
        let empty: TestMmr = Mmr::create(h, InMemoryStore::new(), id(15)).expect("create");
        let proof = empty
            .consistency_proof(MmrSize::ZERO)
            .expect("empty prefix must generate");
        let empty_root = root_of_hashes(&h, &[]);
        assert!(matches!(
            verify_consistency_proof(&h, &proof, empty_root, empty_root),
            Ok(true)
        ));
        // Trivial prefix n == m.
        let proof = mmr
            .consistency_proof(sizes[20])
            .expect("trivial prefix must generate");
        assert_eq!(proof.path.len(), 0);
        assert!(matches!(
            verify_consistency_proof(&h, &proof, roots[20], roots[20]),
            Ok(true)
        ));
    }
}

// ------------------------------------------------------------ rejection

mod rejection {
    use super::*;

    /// Tampered anchors: either root off by one bit is a negative result,
    /// never an error.
    #[test]
    fn tampered_roots_are_ok_false() {
        let h = hasher();
        let roots = reference_roots(&h, 10);
        let sizes = node_sizes(10);
        let mmr = mmr_with(10, 5);
        let proof = mmr
            .consistency_proof(sizes[4])
            .expect("consistency proof must generate");
        assert!(matches!(
            verify_consistency_proof(&h, &proof, flipped(roots[4]), roots[10]),
            Ok(false)
        ));
        assert!(matches!(
            verify_consistency_proof(&h, &proof, roots[4], flipped(roots[10])),
            Ok(false)
        ));
        // Wrong pair entirely.
        assert!(matches!(
            verify_consistency_proof(&h, &proof, roots[3], roots[10]),
            Ok(false)
        ));
        assert!(matches!(
            verify_consistency_proof(&h, &proof, roots[4], roots[9]),
            Ok(false)
        ));
    }

    /// Structural fabrication: truncation, extension, size lies — typed
    /// `Err`, never a panic.
    #[test]
    fn structurally_fabricated_proofs_are_typed_errors() {
        let h = hasher();
        let roots = reference_roots(&h, 10);
        let sizes = node_sizes(10);
        let mmr = mmr_with(10, 6);
        let proof = mmr
            .consistency_proof(sizes[4])
            .expect("consistency proof must generate");

        // Truncated path.
        let mut truncated = proof.clone();
        truncated.path.pop();
        assert!(matches!(
            verify_consistency_proof(&h, &truncated, roots[4], roots[10]),
            Err(VerifyError::Inconsistent(_))
        ));

        // Extended path.
        let mut extended = proof.clone();
        extended.path.push(Hash::from_u64(1));
        assert!(matches!(
            verify_consistency_proof(&h, &extended, roots[4], roots[10]),
            Err(VerifyError::Inconsistent(_))
        ));

        // Dropped / added earlier peak.
        let mut fewer_peaks = proof.clone();
        fewer_peaks.prev_peaks.pop();
        assert!(matches!(
            verify_consistency_proof(&h, &fewer_peaks, roots[4], roots[10]),
            Err(VerifyError::Inconsistent(_))
        ));
        let mut more_peaks = proof.clone();
        more_peaks.prev_peaks.push(Hash::from_u64(1));
        assert!(matches!(
            verify_consistency_proof(&h, &more_peaks, roots[4], roots[10]),
            Err(VerifyError::Inconsistent(_))
        ));

        // Size order lie: swap the two sizes.
        let mut swapped = proof.clone();
        core::mem::swap(&mut swapped.prev_size, &mut swapped.size);
        assert!(matches!(
            verify_consistency_proof(&h, &swapped, roots[4], roots[10]),
            Err(VerifyError::Inconsistent(_))
        ));

        // Malformed size (a leftover right spine).
        let mut malformed = proof.clone();
        malformed.prev_size = MmrSize::new_unchecked(3);
        assert!(matches!(
            verify_consistency_proof(&h, &malformed, roots[4], roots[10]),
            Err(VerifyError::Inconsistent(_))
        ));

        // Empty path for a non-trivial pair.
        let mut empty_path = proof;
        empty_path.path.clear();
        assert!(matches!(
            verify_consistency_proof(&h, &empty_path, roots[4], roots[10]),
            Err(VerifyError::Inconsistent(_))
        ));
    }

    /// Value fabrication with correct structure: swaps, duplicates, and
    /// foreign nodes all end at `Ok(false)` — never a false `Ok(true)`.
    #[test]
    fn value_fabrication_is_ok_false() {
        let h = hasher();
        let roots = reference_roots(&h, 10);
        let sizes = node_sizes(10);
        let mmr = mmr_with(10, 7);
        let proof = mmr
            .consistency_proof(sizes[6])
            .expect("consistency proof must generate");
        assert!(proof.path.len() >= 2, "fixture must exercise the path");

        // Swap two path values.
        let mut swapped = proof.clone();
        let last = swapped.path.len() - 1;
        swapped.path.swap(0, last);
        assert!(matches!(
            verify_consistency_proof(&h, &swapped, roots[6], roots[10]),
            Ok(false)
        ));

        // Duplicate one path value over another (count stays right).
        let mut duplicated = proof.clone();
        let last = *duplicated.path.last().expect("non-empty path");
        duplicated.path[0] = last;
        assert!(matches!(
            verify_consistency_proof(&h, &duplicated, roots[6], roots[10]),
            Ok(false)
        ));

        // Zeroed path.
        let mut zeroed = proof.clone();
        zeroed.path = vec![Hash::from_u64(0); zeroed.path.len()];
        assert!(matches!(
            verify_consistency_proof(&h, &zeroed, roots[6], roots[10]),
            Ok(false)
        ));

        // Earlier peaks from a different history (different elements).
        let other_elements: Vec<Vec<u8>> = (0..10_u64)
            .map(|i| format!("other-{i}").into_bytes())
            .collect();
        let mut other: TestMmr = Mmr::create(h, InMemoryStore::new(), id(16)).expect("create");
        for other_element in &other_elements {
            other.append(other_element).expect("append must succeed");
        }
        let other_proof = other
            .consistency_proof(sizes[6])
            .expect("consistency proof must generate");
        let mut foreign = proof.clone();
        foreign.prev_peaks = other_proof.prev_peaks;
        assert!(matches!(
            verify_consistency_proof(&h, &foreign, roots[6], roots[10]),
            Ok(false)
        ));

        // Path from a proof of a different pair.
        let proof3 = mmr
            .consistency_proof(sizes[3])
            .expect("consistency proof must generate");
        let mut mixed = proof;
        mixed.path = proof3.path;
        assert!(matches!(
            verify_consistency_proof(&h, &mixed, roots[6], roots[10]),
            Ok(false) | Err(VerifyError::Inconsistent(_))
        ));
    }
}

// ------------------------------------------------------------ handles

mod handles {
    use super::*;

    /// Peaks-only provenance: provable from the seed floor up, the empty
    /// prefix always, and nothing in between or beyond.
    #[test]
    fn withpeaks_floor_is_enforced() {
        let h = hasher();
        let sizes = node_sizes(10);
        let base = mmr_with(6, 9);
        let seed = base.size();
        let mut mmr: Mmr<KeccakSolHasher, InMemoryStore, WithPeaks> =
            Mmr::from_peaks(h, InMemoryStore::new(), id(10), seed, base.peaks())
                .expect("seed succeeds");
        for i in 6..10_usize {
            mmr.append(&element(i as u64)).expect("append must succeed");
        }
        let roots = reference_roots(&h, 10);

        // From the floor and above: works.
        for n in 6..=10_usize {
            let proof = mmr
                .consistency_proof(sizes[n])
                .expect("floor-or-above must generate");
            assert!(matches!(
                verify_consistency_proof(&h, &proof, roots[n], roots[10]),
                Ok(true)
            ));
        }
        // The empty prefix: always servable.
        let proof = mmr
            .consistency_proof(MmrSize::ZERO)
            .expect("empty prefix must generate");
        let empty_root = root_of_hashes(&h, &[]);
        assert!(matches!(
            verify_consistency_proof(&h, &proof, empty_root, roots[10]),
            Ok(true)
        ));
        // Below the floor (but nonzero): typed rejection.
        let below = mmr
            .consistency_proof(sizes[3])
            .expect_err("below the floor must be rejected");
        assert!(matches!(below, MmrError::InvalidPrevSize { .. }));
        // Beyond the current size.
        let beyond = mmr
            .consistency_proof(size_of(LeafCount::new(11)))
            .expect_err("beyond the size must be rejected");
        assert!(matches!(beyond, MmrError::InvalidPrevSize { .. }));
        // Malformed size.
        let malformed = mmr
            .consistency_proof(MmrSize::new_unchecked(3))
            .expect_err("malformed size must be rejected");
        assert!(matches!(malformed, MmrError::InvalidPrevSize { .. }));
    }

    /// Generation is exactly one batched read for a general pair, and zero
    /// reads for the degenerate sizes served from cache.
    #[test]
    fn generation_is_one_batched_read() {
        let h = hasher();
        let sizes = node_sizes(40);
        let store = FaultyStore::new(InMemoryStore::new());
        let probe = store.clone();
        let mut mmr: Mmr<KeccakSolHasher, FaultyStore<InMemoryStore>> =
            Mmr::create(h, store, id(11)).expect("create");
        for i in 0..40_usize {
            mmr.append(&element(i as u64)).expect("append must succeed");
        }

        let _ = mmr
            .consistency_proof(sizes[17])
            .expect("general pair must generate");
        assert_eq!(
            probe.fault().read_calls(),
            1,
            "a general consistency proof is exactly one batched read"
        );

        let _ = mmr
            .consistency_proof(sizes[40])
            .expect("trivial prefix must generate");
        let _ = mmr
            .consistency_proof(MmrSize::ZERO)
            .expect("empty prefix must generate");
        assert_eq!(
            probe.fault().read_calls(),
            1,
            "degenerate sizes are served from the cached peaks: no reads"
        );
    }

    /// Proofs are self-contained commitments: a reopened handle at the same
    /// history generates a byte-identical proof, and the proof verifies
    /// independently of any handle.
    #[test]
    fn proof_survives_reopen() {
        let h = hasher();
        let roots = reference_roots(&h, 12);
        let sizes = node_sizes(12);
        let store = InMemoryStore::new();
        let mut mmr: TestMmr = Mmr::create(h, store.clone(), id(12)).expect("create");
        for i in 0..12_usize {
            mmr.append(&element(i as u64)).expect("append must succeed");
        }
        let proof = mmr
            .consistency_proof(sizes[5])
            .expect("consistency proof must generate");
        drop(mmr);

        let reopened = TestMmr::open(h, store, id(12)).expect("reopen");
        let regenerated = reopened
            .consistency_proof(sizes[5])
            .expect("consistency proof must generate");
        assert_eq!(
            proof, regenerated,
            "reopened history generates the same proof"
        );
        assert!(matches!(
            verify_consistency_proof(&h, &proof, roots[5], roots[12]),
            Ok(true)
        ));
    }
}

// --------------------------------------------------------------- serde

#[cfg(feature = "serde")]
mod serde_round_trip {
    use super::*;

    /// Round-trip through JSON keeps the proof verifiable, and the hex
    /// hashes are text-inspectable.
    #[test]
    fn consistency_proof_round_trips_through_json() {
        let h = hasher();
        let roots = reference_roots(&h, 9);
        let sizes = node_sizes(9);
        let mmr = mmr_with(9, 14);
        let proof = mmr
            .consistency_proof(sizes[4])
            .expect("consistency proof must generate");

        let json = serde_json::to_string(&proof).expect("serialize");
        let round_tripped: ConsistencyProof<Hash> =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_tripped, proof);
        assert!(matches!(
            verify_consistency_proof(&h, &round_tripped, roots[4], roots[9]),
            Ok(true)
        ));
        assert!(json.contains("\"prev_size\""));
        assert!(json.contains("\"path\""));
    }

    /// Deserialization validates the sizes: a malformed MMR size is a serde
    /// error, never a state that later panics the verifier.
    #[test]
    fn malformed_sizes_are_deserialization_errors() {
        let json = r#"{"prev_size":2,"size":7,"prev_peaks":[],"path":[]}"#;
        let result = serde_json::from_str::<ConsistencyProof<Hash>>(json);
        assert!(result.is_err(), "size 2 is not a well-formed MMR size");
    }
}

// --------------------------------------------------------------- async

#[cfg(all(feature = "sqlite", not(target_family = "wasm")))]
mod async_sqlite {
    use super::*;
    use accumulators::mmr::AsyncMmr;
    use accumulators::store::AsyncStore as _;
    use accumulators::store::Batch;
    use accumulators::store::keys::{self, Table};
    use accumulators::store::sqlite::SqliteStore;

    use common::TempDb;

    type AsyncTestMmr = AsyncMmr<KeccakSolHasher, SqliteStore>;

    /// The async twin over sqlite verifies against the reference roots and
    /// rejects a corrupted bridge node — mirroring the sync contract.
    #[tokio::test]
    async fn async_twin_verifies_and_rejects_corruption() {
        let h = hasher();
        let roots = reference_roots(&h, 20);
        let sizes = node_sizes(20);
        let db = TempDb::new("consistency");
        let path = db.path();
        let store = SqliteStore::connect(&path).await.expect("connect");
        let id = id(20);
        let mut mmr = AsyncTestMmr::create(h, store.clone(), id)
            .await
            .expect("create");
        for i in 0..20_usize {
            mmr.append(&element(i as u64))
                .await
                .expect("append must succeed");
        }

        for n in [0_usize, 1, 5, 15, 20] {
            let proof = mmr
                .consistency_proof(sizes[n])
                .await
                .expect("async consistency proof must generate");
            let prev_root = if n == 0 {
                root_of_hashes(&h, &[])
            } else {
                roots[n]
            };
            assert!(
                matches!(
                    verify_consistency_proof(&h, &proof, prev_root, roots[20]),
                    Ok(true)
                ),
                "async consistency ({n}, 20) must verify"
            );
        }

        // Corrupt one of the earlier MMR's peak nodes straight through the
        // store: generation still succeeds (the value exists), verification
        // fails at the earlier-root check.
        let prev_peak_node = accumulators::mmr::peaks_of(sizes[5])
            .first()
            .copied()
            .expect("a non-empty MMR has peaks")
            .get();
        let mut batch = Batch::new();
        batch.put_owned(
            keys::encode(&id, Table::Nodes, prev_peak_node),
            vec![0_u8; 32],
        );
        store
            .write(batch)
            .await
            .expect("sqlite writes only fail on I/O");
        let tampered = mmr
            .consistency_proof(sizes[5])
            .await
            .expect("generation succeeds with a present-but-wrong node");
        assert!(
            matches!(
                verify_consistency_proof(&h, &tampered, roots[5], roots[20]),
                Ok(false)
            ),
            "a tampered earlier peak must not verify"
        );
    }
}

// -------------------------------------------------------------- stacked

#[cfg(feature = "stacked_mmr")]
mod stacked {
    use super::*;
    use accumulators::mmr::{Plain, Stacked};

    /// A stacked MMR's root equals the reference root, so a
    /// consistency proof across the stack must verify the same way — and
    /// generation routes through the shared planner.
    #[test]
    fn stacked_consistency_verifies_against_the_reference() {
        let h = hasher();
        let roots = reference_roots(&h, 30);
        let sizes = node_sizes(30);

        let mut base: Mmr<KeccakSolHasher, InMemoryStore, Plain> =
            Mmr::create(h, InMemoryStore::new(), id(21)).expect("create");
        for i in 0..12_usize {
            base.append(&element(i as u64))
                .expect("append must succeed");
        }
        let pin = base.pin();

        let mut stacked: Mmr<KeccakSolHasher, InMemoryStore, Stacked> =
            Mmr::stack(h, InMemoryStore::new(), id(22), [pin]).expect("stack succeeds");
        for i in 12..30_usize {
            stacked
                .append(&element(i as u64))
                .expect("append must succeed");
        }
        assert_eq!(stacked.root(), roots[30], "stack root equals the reference");

        for n in [0_usize, 1, 5, 12, 20, 30] {
            let proof = stacked
                .consistency_proof(sizes[n])
                .expect("stacked consistency proof must generate");
            let prev_root = if n == 0 {
                root_of_hashes(&h, &[])
            } else {
                roots[n]
            };
            assert!(
                matches!(
                    verify_consistency_proof(&h, &proof, prev_root, roots[30]),
                    Ok(true)
                ),
                "stacked consistency ({n}, 30) must verify"
            );
        }
    }
}
