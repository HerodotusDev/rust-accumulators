//! Field hashers and custom hashers driving full MMR flows: the
//! reference-root tracking oracle run parameterized over Poseidon / Pedersen
//! / Blake2s — exercising the *bytes* of `Felt` and `Hash` outputs end-to-end
//! through append/proof paths, where a byte-order bug in a field hasher
//! changes the root — plus a custom hasher's metadata round trip.
//!
//! The golden-vector hasher behavior lives in `hashers.rs`; this suite pins
//! that each hasher produces the *same MMR structure* (peaks, sizes, proof
//! shape) while producing hasher-specific roots.

#![expect(
    clippy::expect_used,
    reason = "tests and benches fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(feature = "mmr", feature = "memory"))]

#[path = "common/mod.rs"]
mod common;

use std::borrow::Cow;

use accumulators::hashers::{Blake2sStarkHasher, Hasher, HasherError, HasherId};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::{Corrupted, Mmr, MmrError};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::store::memory::InMemoryStore;

use common::{id, leaf_hashes, peaks_of_hashes, reference_root, root_of_hashes, slices};

fn id_of(byte: u8) -> AccumulatorId {
    id(byte)
}

/// Elements valid for every hasher in this suite: Blake2s hashes whole
/// 4-byte words, so the fixtures are 4-byte aligned (unlike the 9-byte
/// `element-{i}` used in keccak-only suites).
fn element(index: u64) -> Vec<u8> {
    format!("element-{index:08}").into_bytes()
}

fn elements(count: u64) -> Vec<Vec<u8>> {
    (0..count).map(element).collect()
}

/// The generic reference-tracking flow: root/peaks/size against the
/// brute-force oracle at every size, batch-vs-sequential equality, and proof
/// verification for a 31-leaf tree. Any `Hasher` is first-class — one generic
/// body covers every implementation.
fn roots_track_the_reference<H: Hasher + Copy>(hasher: H, id_byte: u8) {
    let mut mmr = Mmr::<H, InMemoryStore>::create(hasher, InMemoryStore::new(), id_of(id_byte))
        .expect("create must succeed");
    let mut all: Vec<Vec<u8>> = Vec::new();
    for i in 0..=40_u64 {
        let expected_hashes = leaf_hashes(&hasher, &slices(&all));
        assert_eq!(
            mmr.root(),
            root_of_hashes(&hasher, &expected_hashes),
            "root must equal the brute-force reference at {i} leaves"
        );
        assert_eq!(
            mmr.peaks(),
            peaks_of_hashes(&hasher, &expected_hashes),
            "peaks must equal the brute-force reference at {i} leaves"
        );
        if i < 40 {
            let el = element(i);
            mmr.append(&el).expect("append must succeed");
            all.push(el);
        }
    }

    // Batch append and sequential appends land on the same (reference) root.
    let els = elements(17);
    let mut batched =
        Mmr::<H, InMemoryStore>::create(hasher, InMemoryStore::new(), id_of(id_byte + 1))
            .expect("create must succeed");
    batched
        .append_batch(&slices(&els))
        .expect("batch append must succeed");
    assert_eq!(
        batched.root(),
        reference_root(&hasher, &slices(&els)),
        "the batch root must track the reference"
    );

    // Proofs verify for their own elements only — the sibling-path fold runs
    // on this hasher's bytes.
    let mut proven =
        Mmr::<H, InMemoryStore>::create(hasher, InMemoryStore::new(), id_of(id_byte + 2))
            .expect("create must succeed");
    let els = elements(31);
    for el in &els {
        proven.append(el).expect("append must succeed");
    }
    for (index, el) in els.iter().enumerate() {
        let proof = proven.proof(LeafIndex::new(index as u64)).expect("proof");
        assert_eq!(
            proof.siblings.len(),
            accumulators::utils::mmr::sibling_path(LeafIndex::new(index as u64), proven.size())
                .len(),
            "the sibling count is the proven node's peak height"
        );
        assert!(
            proven.verify(&proof, el).expect("verify"),
            "leaf {index} must verify"
        );
        assert!(
            !proven.verify(&proof, b"not-the-element!").expect("verify"),
            "a foreign element must not verify for leaf {index}"
        );
    }

    // A multiproof spanning shared subtrees verifies and dedups.
    let subset = [LeafIndex::new(0), LeafIndex::new(1), LeafIndex::new(9)];
    let multi = proven.multiproof(subset).expect("multiproof");
    assert!(
        multi.sibling_pool.len() < multi.sibling_refs.len(),
        "adjacent leaves must share pooled siblings"
    );
    assert!(
        proven
            .verify_multi(&multi, [&els[0], &els[1], &els[9]])
            .expect("verify"),
        "the multiproof must verify"
    );
}

#[cfg(feature = "blake2s_stark")]
#[test]
fn blake2s_stark_roots_track_the_reference() {
    roots_track_the_reference(Blake2sStarkHasher { truncate: false }, 4);
    roots_track_the_reference(Blake2sStarkHasher { truncate: true }, 5);
}

#[cfg(feature = "poseidon_stark")]
#[test]
fn poseidon_stark_roots_track_the_reference() {
    use accumulators::hashers::PoseidonStarkHasher;
    roots_track_the_reference(PoseidonStarkHasher { pad: false }, 7);
    roots_track_the_reference(PoseidonStarkHasher { pad: true }, 8);
}

#[cfg(feature = "pedersen_stark")]
#[test]
fn pedersen_stark_roots_track_the_reference() {
    use accumulators::hashers::PedersenStarkHasher;
    roots_track_the_reference(PedersenStarkHasher, 10);
}

// ------------------------------------------------------------ custom hasher

/// A minimal custom hasher: `Copy`, [`Hash`] output, an
/// **owned** `Cow` config (the runtime-computed-config shape built-ins
/// don't exercise), and a real combining function so MMR behavior is
/// meaningful. XOR is symmetric — allowed by the `hash_pair` contract
/// ("need not equal" is permissive) — and the variant byte makes configs
/// observable in every digest.
#[derive(Clone, Copy, Debug)]
struct XorHasher {
    variant: u8,
}

impl XorHasher {
    fn mix(self, parts: &[&[u8]]) -> Hash {
        let mut out = [0_u8; 32];
        for part in parts {
            for (index, byte) in part.iter().enumerate() {
                out[index % 32] ^= *byte;
            }
            // Rotate after each part: a pure XOR fold is linear, so a variant
            // byte XORed once per pair would cancel on even pair counts and
            // two configs could collide on the same root.
            out.rotate_left((usize::from(self.variant) % 32) + 1);
        }
        Hash::from_bytes(out)
    }
}

impl Hasher for XorHasher {
    type Output = Hash;

    fn id(&self) -> HasherId {
        HasherId::Custom("xor")
    }

    fn config(&self) -> Cow<'static, str> {
        Cow::Owned(format!("variant={}", self.variant))
    }

    fn hash_pair(&self, left: Hash, right: Hash) -> Hash {
        self.mix(&[left.as_bytes(), right.as_bytes()])
    }

    fn hash_leaf(&self, element: &[u8]) -> Result<Hash, HasherError> {
        Ok(self.mix(&[element]))
    }

    fn genesis(&self) -> Hash {
        Hash::from_bytes([self.variant; 32])
    }
}

mod custom_hasher {
    use super::*;

    type XorMmr = Mmr<XorHasher, InMemoryStore>;

    #[test]
    fn create_append_open_round_trips_the_custom_hasher() {
        let h = XorHasher { variant: 1 };
        let store = InMemoryStore::new();
        let mut mmr = XorMmr::create(h, store.clone(), id_of(1)).expect("create must succeed");
        for el in elements(6) {
            mmr.append(&el).expect("append must succeed");
        }
        let root = mmr.root();
        let peaks = mmr.peaks().to_vec();
        assert_eq!(mmr.leaf_count().get(), 6);

        let reopened = XorMmr::open(h, store, id_of(1)).expect("open must succeed");
        assert_eq!(reopened.root(), root, "the root survives the reopen");
        assert_eq!(reopened.peaks(), &peaks, "the peaks survive the reopen");
        let proof = reopened.proof(LeafIndex::new(3)).expect("proof");
        assert!(
            reopened.verify(&proof, &element(3)).expect("verify"),
            "a custom hasher's proofs verify"
        );
    }

    /// The custom hasher's identity+config is persisted and validated
    /// byte-for-byte: a different config (variant) is a `HasherMismatch`
    /// naming the *stored* config — a config silently ignored on reopen is
    /// unrepresentable for user hashers.
    #[test]
    fn a_config_change_is_a_hasher_mismatch_naming_the_stored_config() {
        let h = XorHasher { variant: 1 };
        let store = InMemoryStore::new();
        XorMmr::create(h, store.clone(), id_of(1)).expect("create must succeed");

        match XorMmr::open(XorHasher { variant: 2 }, store.clone(), id_of(1)) {
            Err(MmrError::Corrupted(Corrupted::HasherMismatch { stored, .. })) => {
                assert!(
                    stored.contains("xor") && stored.contains("variant=1"),
                    "the stored identity must name the custom hasher and its config, got {stored}"
                );
            }
            Err(other) => panic!("expected HasherMismatch, got {other:?}"),
            Ok(_) => panic!("expected HasherMismatch, but the MMR opened"),
        }

        // The same config reopens fine — the record round-trips.
        let reopened = XorMmr::open(h, store, id_of(1)).expect("same-config reopen");
        assert_eq!(reopened.leaf_count().get(), 0);
    }

    /// The config actually changes output bytes: two variants of the custom
    /// hasher produce different roots over identical elements — a config that
    /// only *claims* to matter would break the persisted-metadata contract.
    #[test]
    fn the_config_changes_the_output_bytes() {
        let owned = elements(5);
        let els = slices(&owned);
        let a = Mmr::<XorHasher, InMemoryStore>::create(
            XorHasher { variant: 1 },
            InMemoryStore::new(),
            id_of(1),
        )
        .map(|mut mmr| {
            mmr.append_batch(&els).expect("append");
            mmr.root()
        })
        .expect("create");
        let b = Mmr::<XorHasher, InMemoryStore>::create(
            XorHasher { variant: 2 },
            InMemoryStore::new(),
            id_of(1),
        )
        .map(|mut mmr| {
            mmr.append_batch(&els).expect("append");
            mmr.root()
        })
        .expect("create");
        assert_ne!(a, b, "the config must affect the hash output");
    }
}
