//! Fuzz target: MMR proof verification against arbitrary bytes.
//!
//! Both attacker-facing seams of the standalone verify path share one
//! target:
//!
//! - **JSON decode** — the serde proof format is the untrusted wire
//!   encoding; a malformed document must be a typed error, never a panic
//!   or a hang. Decoded proofs go straight into verification, the way an
//!   untrusting peer would drive them.
//! - **Direct construction** — `Proof`/`MultiProof` fields are public, so
//!   `verify_proof`/`verify_multi_proof` (and their `*_hashed` variants)
//!   accept fully attacker-chosen structs. The bytes are split into
//!   indexes, counts, and raw 32-byte hashes; counts are capped so a
//!   single input stays bounded.
//!
//! The only contract asserted: no panic, no hang. Verification outcomes
//! are free — `Ok(false)` and a typed `Err` are both acceptable
//! rejections; `Ok(true)` on self-consistent garbage is by design
//! (standalone verification is relative to a trusted root).
//!
//! Max input cost per run: a few thousand hash-pair calls (counts ≤ 64
//! per list, path lengths ≤ 64 by MMR height) — no hang is reachable.

#![no_main]

use libfuzzer_sys::fuzz_target;

use accumulators::hashers::KeccakSolHasher;
use accumulators::mmr::{
    LeafCount, MultiProof, Proof, verify_multi_proof, verify_multi_proof_hashed, verify_proof,
    verify_proof_hashed,
};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::utils::mmr::size_of;

/// The raw element fed to the non-hashed verify variants. Its content is
/// irrelevant to panic-safety; a fixed constant keeps the target minimal.
const ELEMENT: &[u8] = b"fuzz-target-element";

/// Byte cursor over the fuzz input: every read is zero-padded past the
/// end, so short inputs still produce structured (not crashing) proofs.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn u64(&mut self) -> u64 {
        let mut raw = [0; 8];
        let end = self.pos.saturating_add(8).min(self.data.len());
        raw[..end - self.pos].copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        u64::from_le_bytes(raw)
    }

    fn byte(&mut self) -> u8 {
        let Some(&byte) = self.data.get(self.pos) else {
            return 0;
        };
        self.pos += 1;
        byte
    }

    /// One raw 32-byte hash, zero-padded past the end of the input.
    fn hash(&mut self) -> Hash {
        let mut raw = [0; 32];
        let end = self.pos.saturating_add(32).min(self.data.len());
        raw[..end - self.pos].copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
        Hash::from_bytes(raw)
    }

    fn hashes(&mut self, count: usize) -> Vec<Hash> {
        (0..count).map(|_| self.hash()).collect()
    }
}

/// List length caps: one byte mod 65, so every count is reachable and no
/// list exceeds 64 entries.
fn count_from(byte: u8) -> usize {
    usize::from(byte % 65)
}

fn run(data: &[u8]) {
    let hasher = KeccakSolHasher;

    // Seam 1: the serde wire format. Rejections (decode failures) and
    // verification outcomes are both free; only panics/hangs are bugs.
    if let Ok(proof) = serde_json::from_slice::<Proof<Hash>>(data) {
        let _ = verify_proof(&hasher, &proof, ELEMENT);
    } else if let Ok(multi) = serde_json::from_slice::<MultiProof<Hash>>(data) {
        let elements = core::iter::repeat_n(ELEMENT, multi.leaves.len());
        let _ = verify_multi_proof(&hasher, &multi, elements);
    }

    // Seam 2: hand-built proofs, every field attacker-chosen. Leaf and
    // leaf-count ranges are masked into the representable leaf space
    // (`LeafIndex::new`/`LeafCount` beyond 2^63 - 1 is a documented
    // precondition panic, not a bug — the fuzzer must not trip it).
    let mut reader = Reader::new(data);
    let leaf = LeafIndex::new(reader.u64() & ((1 << 40) - 1));
    let leaf_count = LeafCount::new(reader.u64() & ((1 << 40) - 1));
    let size = size_of(leaf_count);

    let element_hash = reader.hash();
    let sibling_count = count_from(reader.byte());
    let siblings = reader.hashes(sibling_count);
    let peak_count = count_from(reader.byte());
    let peaks = reader.hashes(peak_count);
    let root = reader.hash();
    let proof = Proof {
        leaf,
        element_hash,
        siblings,
        peaks,
        root,
        size,
    };
    let _ = verify_proof_hashed(&hasher, &proof, element_hash);
    let _ = verify_proof(&hasher, &proof, ELEMENT);

    let leaf_count = count_from(reader.byte());
    let leaves: Vec<LeafIndex> = (0..leaf_count)
        .map(|i| LeafIndex::new(leaf.get().saturating_add(i as u64)))
        .collect();
    let element_hashes = reader.hashes(leaves.len());
    let pool_count = count_from(reader.byte());
    let sibling_pool = reader.hashes(pool_count);
    let ref_count = count_from(reader.byte());
    let sibling_refs: Vec<u32> = (0..ref_count).map(|_| u32::from(reader.byte())).collect();
    let multi_peak_count = count_from(reader.byte());
    let multi_peaks = reader.hashes(multi_peak_count);
    let multi = MultiProof {
        leaves,
        element_hashes: element_hashes.clone(),
        sibling_pool,
        sibling_refs,
        peaks: multi_peaks,
        root: reader.hash(),
        size,
    };
    let _ = verify_multi_proof_hashed(&hasher, &multi, element_hashes);
    let elements = core::iter::repeat_n(ELEMENT, multi.leaves.len());
    let _ = verify_multi_proof(&hasher, &multi, elements);
}

fuzz_target!(|data: &[u8]| {
    run(data);
});
