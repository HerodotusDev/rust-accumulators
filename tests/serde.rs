//! Serde round-trip and rejection tests for the `serde` feature: hex-string
//! hashes and ids, plain-number indexes, checked felt deserialization, and
//! structural (never cryptographic) proof deserialization.

#![cfg(feature = "serde")]
#![expect(
    clippy::expect_used,
    reason = "tests fail loudly by design: expect on fixtures is the contract"
)]

use accumulators::hashers::{Hasher, KeccakSolHasher};
use accumulators::ids::AccumulatorId;
use accumulators::mmr::{Mmr, MultiProof, NullifierRecord, Proof};
use accumulators::primitives::{Hash, LeafIndex};
use accumulators::serde_impls::HexHash;
use accumulators::store::memory::InMemoryStore;
use serde_json::from_str;
use serde_json::to_string;
use starknet_crypto::Felt;

const HASH_HEX: &str = "0x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

fn fixture_proof() -> Proof<Hash> {
    let mut mmr: Mmr<KeccakSolHasher, _> =
        Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO)
            .expect("fixture MMR creation");
    for element in ["a", "b", "c"] {
        mmr.append(element.as_bytes()).expect("fixture append");
    }
    mmr.proof(LeafIndex::new(1)).expect("fixture proof")
}

fn fixture_multiproof() -> MultiProof<Hash> {
    let mut mmr: Mmr<KeccakSolHasher, _> =
        Mmr::create(KeccakSolHasher, InMemoryStore::new(), AccumulatorId::ZERO)
            .expect("fixture MMR creation");
    for element in ["a", "b", "c", "d"] {
        mmr.append(element.as_bytes()).expect("fixture append");
    }
    mmr.multiproof([LeafIndex::new(0), LeafIndex::new(3)])
        .expect("fixture multiproof")
}

#[test]
fn hash_round_trip() {
    let hash = Hash::from_u64(0xdead_beef);
    let json = to_string(&hash).expect("serialize Hash");
    assert_eq!(json, format!("\"0x{hash}\""));
    let round_tripped: Hash = from_str(&json).expect("deserialize Hash");
    assert_eq!(round_tripped, hash);
}

#[test]
fn hash_deserializes_from_str_and_unprefixed() {
    let quoted = format!("\"{HASH_HEX}\"");
    let hash: Hash = from_str(&quoted).expect("0x-prefixed");
    assert_eq!(
        from_str::<Hash>(&format!("\"{}\"", &HASH_HEX[2..])).expect("bare hex"),
        hash
    );
}

#[test]
fn hash_rejects_malformed() {
    // Wrong length.
    assert!(from_str::<Hash>("0xaabb").is_err());
    // Not hex.
    assert!(
        from_str::<Hash>("0xzz02030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0")
            .is_err()
    );
}

#[test]
fn accumulator_id_round_trip() {
    let id = AccumulatorId::from_bytes([7; 16]);
    let json = to_string(&id).expect("serialize AccumulatorId");
    assert_eq!(json, format!("\"0x{id}\""));
    let round_tripped: AccumulatorId = from_str(&json).expect("deserialize AccumulatorId");
    assert_eq!(round_tripped, id);
    // Wrong length and garbage are rejected.
    assert!(from_str::<AccumulatorId>("0x00").is_err());
    assert!(from_str::<AccumulatorId>("0xzz0102030405060708090a0b0c0d0e0f0").is_err());
}

#[test]
fn hex_hash_round_trip() {
    let hash = HexHash(Hash::from_u64(42));
    let json = to_string(&hash).expect("serialize HexHash");
    let round_tripped: HexHash<Hash> = from_str(&json).expect("deserialize HexHash");
    assert_eq!(round_tripped, hash);
}

#[test]
fn hex_hash_felt_round_trip_and_checked_deserialization() {
    // The checked conversion: the field modulus (and anything above it) is a
    // serde error, never a panic, never a wrapped value.
    let modulus_hex = "0x0800000000000011000000000000000000000000000000000000000000000001";
    assert!(from_str::<HexHash<Felt>>(modulus_hex).is_err());

    let genesis = HexHash(<Felt as accumulators::primitives::HashValue>::from_u64(
        0x1234,
    ));
    let json = to_string(&genesis).expect("serialize HexHash<Felt>");
    let round_tripped: HexHash<Felt> = from_str(&json).expect("deserialize HexHash<Felt>");
    assert_eq!(round_tripped, genesis);
}

#[test]
fn nullifier_record_round_trip() {
    let shallow = NullifierRecord::Shallow {
        at: accumulators::mmr::MmrSize::try_new(11).expect("well-formed size"),
    };
    assert_eq!(
        to_string(&shallow).expect("serialize shallow"),
        r#"{"Shallow":{"at":11}}"#
    );
    assert_eq!(
        to_string(&NullifierRecord::Deep).expect("serialize deep"),
        r#""Deep""#
    );

    let round_tripped: NullifierRecord =
        from_str(&to_string(&shallow).expect("serialize shallow")).expect("deserialize shallow");
    assert_eq!(round_tripped, shallow);
    let deep: NullifierRecord = from_str(r#""Deep""#).expect("deserialize deep");
    assert_eq!(deep, NullifierRecord::Deep);
}

#[test]
fn nullifier_record_rejects_deep_marker_and_bad_sizes() {
    // Size 0 is the wire's deep marker — not a valid shallow record.
    assert!(from_str::<NullifierRecord>(r#"{"Shallow":{"at":0}}"#).is_err());
    // Not a well-formed MMR size (leftover right spine).
    assert!(from_str::<NullifierRecord>(r#"{"Shallow":{"at":2}}"#).is_err());
    // Unknown variant.
    assert!(from_str::<NullifierRecord>(r#"{"Deepish":{}}"#).is_err());
}

#[test]
fn proof_round_trip_and_verification() {
    let proof = fixture_proof();
    let json = to_string(&proof).expect("serialize Proof");
    let round_tripped: Proof<Hash> = from_str(&json).expect("deserialize Proof");
    assert_eq!(round_tripped, proof);

    // The deserialized proof is still a standalone commitment: it verifies
    // against the element it commits to.
    assert!(
        accumulators::mmr::verify_proof_hashed(
            &KeccakSolHasher,
            &round_tripped,
            KeccakSolHasher.hash_leaf(b"b").expect("leaf hash"),
        )
        .expect("verification runs")
    );
}

#[test]
fn multiproof_round_trip_and_verification() {
    let proof = fixture_multiproof();
    let json = to_string(&proof).expect("serialize MultiProof");
    let round_tripped: MultiProof<Hash> = from_str(&json).expect("deserialize MultiProof");
    assert_eq!(round_tripped, proof);

    let hashes: Vec<_> = ["a", "d"]
        .iter()
        .map(|element| {
            KeccakSolHasher
                .hash_leaf(element.as_bytes())
                .expect("leaf hash")
        })
        .collect();
    assert!(
        accumulators::mmr::verify_multi_proof_hashed(&KeccakSolHasher, &round_tripped, hashes)
            .expect("verification runs")
    );
}

#[test]
fn proofs_reject_malformed_hashes_and_sizes() {
    let json = to_string(&fixture_proof()).expect("serialize Proof");
    let mutate = |field: &str, value: serde_json::Value| {
        let mut parsed: serde_json::Value = from_str(&json).expect("fixture JSON");
        parsed[field] = value;
        parsed.to_string()
    };
    // Corrupt one hash: wrong hex length must be a deserialization error,
    // never a shortened/zero-filled hash.
    assert!(from_str::<Proof<Hash>>(&mutate("element_hash", serde_json::json!("0xaabb"))).is_err());
    // A leaf index beyond the layout bound is rejected at deserialization
    // time (no panic on the way in).
    assert!(
        from_str::<Proof<Hash>>(&mutate(
            "leaf",
            serde_json::json!(9_223_372_036_854_775_808_u64)
        ))
        .is_err()
    );
    // A size that is not a well-formed MMR size is rejected.
    assert!(from_str::<Proof<Hash>>(&mutate("size", serde_json::json!(2))).is_err());
}

#[test]
fn multiproof_corruption_surfaces_at_verification() {
    // A sibling reference past the pool is deliberately *not* a serde error
    // — structural validation is `verify`'s job. Deserialization accepts it;
    // verification rejects it with `RefOutOfBounds`.
    let json = to_string(&fixture_multiproof()).expect("serialize MultiProof");
    let mut parsed: serde_json::Value = from_str(&json).expect("fixture JSON");
    parsed["sibling_refs"][0] = serde_json::json!(999);
    let corrupted: MultiProof<Hash> = from_str(&parsed.to_string()).expect("deserialize");

    let hashes: Vec<_> = ["a", "d"]
        .iter()
        .map(|element| {
            KeccakSolHasher
                .hash_leaf(element.as_bytes())
                .expect("leaf hash")
        })
        .collect();
    let result = accumulators::mmr::verify_multi_proof_hashed(&KeccakSolHasher, &corrupted, hashes)
        .expect_err("out-of-range reference is a verification error");
    assert!(
        matches!(
            result,
            accumulators::mmr::VerifyError::Inconsistent(
                accumulators::mmr::proof::ProofInconsistency::RefOutOfBounds { .. }
            )
        ),
        "unexpected error: {result}"
    );
}
