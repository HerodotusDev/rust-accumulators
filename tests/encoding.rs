//! Golden tests for the fixed-width proof encodings ([`FixedWidth`] and its
//! presets): the pinned rendering contract — `0x`-prefixed padded
//! `bytes32` words for Solidity, bare minimal felt hex for cairo — plus list
//! padding with the zero placeholder, `ListTooLong`, and round-trip shape.
//! Changing any rendered output is a breaking change for every deployed
//! accumulator.
//!
//! The proofs here are hand-built from controlled hash values so the golden
//! strings are deterministic, not derived from the implementation under
//! test's own hasher pipeline.

#![expect(
    clippy::expect_used,
    reason = "tests fail loudly by design: expect on fixtures is the contract"
)]
#![cfg(all(feature = "mmr", feature = "memory", feature = "keccak_sol"))]

use accumulators::mmr::proof::encoding::{EncodedMultiProof, EncodedProof, HexStyle};
use accumulators::mmr::{FixedWidth, MmrSize, MultiProof, Proof, ProofEncoding};
use accumulators::primitives::{Hash, HashValue, LeafIndex};

/// `0x0000…01` — a hash with enough leading zeros to exercise felt
/// stripping.
fn low_hash() -> Hash {
    let mut bytes = [0_u8; 32];
    bytes[31] = 1;
    Hash::from_bytes(bytes)
}

fn high_hash() -> Hash {
    Hash::from_bytes([0xff; 32])
}

fn fixed_proof() -> Proof<Hash> {
    Proof {
        leaf: LeafIndex::new(7),
        element_hash: low_hash(),
        siblings: vec![Hash::ZERO, high_hash()],
        peaks: vec![low_hash(), high_hash()],
        root: high_hash(),
        size: MmrSize::new_unchecked(15),
    }
}

#[test]
fn solidity_preset_is_0x_prefixed_padded_words() {
    let encoded: EncodedProof = FixedWidth::solidity()
        .encode(&fixed_proof())
        .expect("encodes");

    // Pinned golden format: `0x` + 64 lowercase hex chars; changing this
    // rendering is a breaking change for every deployed accumulator.
    assert_eq!(
        encoded.element_hash,
        "0x0000000000000000000000000000000000000000000000000000000000000001"
    );
    assert_eq!(encoded.element_hash.len(), 66);
    assert_eq!(encoded.root, "0x".to_string() + &"ff".repeat(32));
    assert_eq!(
        encoded.siblings,
        vec![
            "0x".to_string() + &"00".repeat(32),
            "0x".to_string() + &"ff".repeat(32),
        ],
        "siblings render as-is when no output size is set"
    );
    assert_eq!(encoded.size, "15", "sizes are minimal decimal");
    assert_eq!(encoded.leaf, "7");
}

#[test]
fn cairo_preset_is_bare_minimal_felt_hex() {
    let encoded: EncodedProof = FixedWidth::cairo().encode(&fixed_proof()).expect("encodes");

    // Bare (no `0x`), leading zeros stripped — the felt convention; zero
    // renders as `"0"`.
    assert_eq!(encoded.element_hash, "1");
    assert_eq!(
        encoded.siblings[0], "0",
        "the zero hash renders as a bare zero felt"
    );
    assert_eq!(encoded.siblings[1], "f".repeat(64), "bare full-width hex");
    assert_eq!(encoded.root, "f".repeat(64));

    // The two presets must be genuinely different renderings.
    let solidity: EncodedProof = FixedWidth::solidity()
        .encode(&fixed_proof())
        .expect("encodes");
    assert_ne!(solidity.element_hash, encoded.element_hash);
}

#[test]
fn lists_are_null_padded_to_the_output_size() {
    let preset = FixedWidth {
        hash_width: Some(64),
        size_width: None,
        peaks_size: Some(4),
        siblings_size: Some(3),
        style: HexStyle::Word,
    };
    let encoded: EncodedProof = preset.encode(&fixed_proof()).expect("encodes");

    // Padded with the zero placeholder, rendered through the same style —
    // `0x` + 64 zeros (the placeholder width tracks the hash value's own
    // `LEN`, here 32 bytes).
    let null = "0x".to_string() + &"00".repeat(32);
    assert_eq!(
        encoded.peaks,
        vec![
            "0x".to_string() + &"00".repeat(31) + "01",
            "0x".to_string() + &"ff".repeat(32),
            null.clone(),
            null.clone(),
        ]
    );
    let mut expected_siblings = encoded.siblings.clone();
    expected_siblings.resize(3, null);
    assert_eq!(encoded.siblings, expected_siblings);
}

#[test]
fn overlong_lists_are_rejected() {
    let preset = FixedWidth {
        hash_width: Some(64),
        size_width: None,
        peaks_size: Some(1),
        siblings_size: None,
        style: HexStyle::Word,
    };
    match preset.encode(&fixed_proof()) {
        Err(accumulators::mmr::EncodingError::ListTooLong { len, output_size }) => {
            assert_eq!(len, 2);
            assert_eq!(output_size, 1);
        }
        other => panic!("expected ListTooLong, got {other:?}"),
    }
}

#[test]
fn multi_proofs_round_trip_their_shape() {
    let mut proof = fixed_proof();
    let pool = vec![Hash::ZERO, high_hash()];
    let multi = MultiProof {
        leaves: vec![LeafIndex::new(0), LeafIndex::new(7)],
        element_hashes: vec![low_hash(), high_hash()],
        sibling_pool: pool,
        sibling_refs: vec![0, 1, 0],
        peaks: std::mem::take(&mut proof.peaks),
        root: high_hash(),
        size: MmrSize::new_unchecked(15),
    };

    let encoded: EncodedMultiProof = FixedWidth::solidity()
        .encode_multi(&multi)
        .expect("encodes");
    assert_eq!(encoded.sibling_pool.len(), 2);
    assert_eq!(encoded.leaves, vec!["0", "7"]);
    assert_eq!(
        encoded.element_hashes,
        vec![
            "0x".to_string() + &"00".repeat(31) + "01",
            "0x".to_string() + &"ff".repeat(32),
        ]
    );
    assert_eq!(encoded.sibling_refs, vec![0, 1, 0], "refs stay numeric");

    // Byte-comparability: the same proof encodes identically.
    let again: EncodedMultiProof = FixedWidth::solidity()
        .encode_multi(&multi)
        .expect("encodes");
    assert_eq!(encoded, again);

    // The cairo preset renders the same structure bare.
    let felt: EncodedMultiProof = FixedWidth::cairo().encode_multi(&multi).expect("encodes");
    assert_eq!(felt.sibling_pool[0], "0");
    assert_eq!(felt.sibling_pool[1], "f".repeat(64));
}

/// A 4-byte hash value proves the zero placeholder tracks
/// [`HashValue::LEN`] (never a hardcoded 32-byte width).
#[test]
fn placeholder_width_tracks_the_value_length() {
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    struct Tiny([u8; 4]);

    impl HashValue for Tiny {
        const LEN: usize = 4;
        fn from_u64(value: u64) -> Self {
            Self(
                value.to_be_bytes()[4..]
                    .try_into()
                    .expect("low 32 bits fit Tiny"),
            )
        }
        fn write_bytes(&self, out: &mut [u8]) {
            out.copy_from_slice(&self.0);
        }
        fn from_bytes(bytes: &[u8]) -> Option<Self> {
            let array: [u8; 4] = bytes.try_into().ok()?;
            Some(Self(array))
        }
    }

    let proof = Proof::<Tiny> {
        leaf: LeafIndex::new(0),
        element_hash: Tiny([0, 0, 0, 1]),
        siblings: vec![Tiny([0; 4])],
        peaks: vec![Tiny([0; 4])],
        root: Tiny([0; 4]),
        size: MmrSize::new_unchecked(1),
    };

    // A natural-width word preset (`hash_width: None` — render at the
    // value's own canonical width): both the values and the zero placeholder
    // are Tiny-wide, proving the width tracks `HashValue::LEN`, never a
    // hardcoded 32.
    let tiny_word = FixedWidth {
        hash_width: None,
        size_width: None,
        peaks_size: None,
        siblings_size: None,
        style: HexStyle::Word,
    };
    let encoded: EncodedProof = tiny_word.encode(&proof).expect("encodes");
    assert_eq!(
        encoded.element_hash, "0x00000001",
        "word rendering pads to the value's own width"
    );
    assert_eq!(
        encoded.siblings,
        vec!["0x00000000"],
        "the zero placeholder is Tiny-wide, not 32-byte"
    );

    let felt: EncodedProof = FixedWidth::cairo().encode(&proof).expect("encodes");
    assert_eq!(felt.element_hash, "1");
    assert_eq!(felt.siblings, vec!["0"]);
}
