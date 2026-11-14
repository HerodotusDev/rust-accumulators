//! Golden-value and behavior tests for the built-in hashers and the hash
//! primitives they produce.
//!
//! Keccak vectors are pinned from the v0.5 test suite (the semantics are
//! byte-identical). The Blake2s genesis vectors are derived independently
//! from the reference BLAKE2s digest with Cairo 4-byte word reversal.

use std::borrow::Cow;

use accumulators::hashers::{
    Blake2sHasher, Hasher, HasherError, HasherId, Keccak256Hasher, PedersenHasher, PoseidonHasher,
    SolKeccak,
};
use accumulators::primitives::{Hash, HashValue};
use starknet_crypto::Felt;

/// Decodes 64 hex characters into the 32 digest bytes they encode.
fn digest_bytes(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64, "golden digests must encode 32 bytes: {hex}");
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[2 * index..2 * index + 2], 16)
            .expect("golden digests must be valid hex");
    }
    bytes
}

/// Decodes a hex string (optional `0x` prefix, any case) into raw bytes.
fn hex_bytes(hex: &str) -> Vec<u8> {
    let body = hex.strip_prefix("0x").unwrap_or(hex);
    assert_eq!(
        body.len() % 2,
        0,
        "hex strings must have even length: {hex}"
    );
    (0..body.len() / 2)
        .map(|index| {
            u8::from_str_radix(&body[2 * index..2 * index + 2], 16).expect("hex must be valid")
        })
        .collect()
}

/// Wraps a 64-char hex string as a [`Hash`].
fn hash_from_hex(hex: &str) -> Hash {
    Hash::from_bytes(digest_bytes(hex))
}

/// Big-endian bytes of the Starknet field modulus `2^251 + 17·2^192 + 1`.
const STARK_MODULUS_HEX: &str = "0800000000000011000000000000000000000000000000000000000000000001";

/// The golden keccak element shared by the pair/leaf vectors.
const LEAF_VECTOR: &str = "a4b1d5793b631de611c922ea3ec938b359b3a49e687316d9a79c27be8ce84590";
/// First operand of the distinct-element pair vector.
const PAIR_LEFT_VECTOR: &str = "bd946409a993b84d18be8dc09081a9cdcecedfedf3a1ff984175e5f3667af887";
/// Second operand of the distinct-element pair vector.
const PAIR_RIGHT_VECTOR: &str = "9cfabdfca79eb1ae44266614b731aa30d2aed697fa01d83b933498f1095f0941";

mod hash_value {
    use super::*;

    #[test]
    fn zero_is_thirty_two_zero_bytes() {
        assert_eq!(Hash::ZERO.as_bytes(), &[0; 32]);
        assert_eq!(Hash::ZERO.to_bytes(), [0; 32]);
    }

    #[test]
    fn bytes_round_trip() {
        let bytes = digest_bytes(LEAF_VECTOR);
        let hash = Hash::from_bytes(bytes);
        assert_eq!(
            hash.as_bytes(),
            &bytes,
            "as_bytes borrows the wrapped bytes"
        );
        assert_eq!(hash.to_bytes(), bytes, "to_bytes converts back");
        assert_eq!(
            Hash::from(bytes),
            hash,
            "From<[u8; 32]> wraps the same bytes"
        );
        let converted: [u8; 32] = hash.into();
        assert_eq!(converted, bytes, "Into<[u8; 32]> converts back");
    }

    #[test]
    fn from_u64_encodes_big_endian() {
        assert!(
            Hash::from_u64(1).as_bytes()[..31]
                .iter()
                .all(|byte| *byte == 0),
            "small counts occupy only the tail"
        );
        assert_eq!(
            Hash::from_u64(1).as_bytes()[31],
            1,
            "the value sits in the last byte"
        );
        assert_eq!(
            &Hash::from_u64(0x0102_0304_0506_0708).as_bytes()[24..],
            &[1, 2, 3, 4, 5, 6, 7, 8],
            "counts enter hashing as 32-byte big-endian integers"
        );
        assert_eq!(&Hash::from_u64(u64::MAX).as_bytes()[24..], &[0xff; 8]);
    }

    #[test]
    fn display_is_plain_lowercase_hex() {
        assert_eq!(hash_from_hex(LEAF_VECTOR).to_string(), LEAF_VECTOR);
    }

    #[test]
    fn debug_is_shortened() {
        let hash = hash_from_hex(LEAF_VECTOR);
        assert_eq!(
            format!("{hash:?}"),
            "Hash(0xa4b1d579…)",
            "Debug keeps only a prefix"
        );
    }

    #[test]
    fn from_bytes_rejects_wrong_lengths() {
        assert!(<Hash as HashValue>::from_bytes(&[0; 31]).is_none());
        assert!(<Hash as HashValue>::from_bytes(&[0; 33]).is_none());
        assert!(<Hash as HashValue>::from_bytes(&[0; 32]).is_some());
    }

    #[test]
    fn to_vec_is_the_canonical_encoding() {
        assert_eq!(<Hash as HashValue>::LEN, 32);
        let hash = hash_from_hex(LEAF_VECTOR);
        assert_eq!(hash.to_vec(), hash.as_bytes().to_vec());
    }
}

mod felt_value {
    use super::*;

    #[test]
    fn felts_are_thirty_two_byte_values() {
        assert_eq!(<Felt as HashValue>::LEN, 32);
    }

    #[test]
    fn felt_from_u64_is_big_endian() {
        let felt = <Felt as HashValue>::from_u64(0x1234);
        let mut bytes = [0; 32];
        felt.write_bytes(&mut bytes);
        assert!(bytes[..30].iter().all(|byte| *byte == 0));
        assert_eq!(
            &bytes[30..],
            &[0x12, 0x34],
            "counts enter hashing big-endian"
        );
    }

    #[test]
    fn felt_bytes_round_trip() {
        let felt = <Felt as HashValue>::from_u64(0xdead_beef);
        let encoded = felt.to_vec();
        assert_eq!(encoded.len(), 32);
        assert_eq!(<Felt as HashValue>::from_bytes(&encoded), Some(felt));
    }

    #[test]
    fn felt_from_bytes_rejects_the_modulus_and_beyond() {
        let mut modulus = hex_bytes(STARK_MODULUS_HEX);
        assert_eq!(
            <Felt as HashValue>::from_bytes(&modulus),
            None,
            "the modulus itself is out of range"
        );

        modulus[31] += 1;
        assert_eq!(
            <Felt as HashValue>::from_bytes(&modulus),
            None,
            "values above the modulus are out of range"
        );

        let mut below = hex_bytes(STARK_MODULUS_HEX);
        below[31] -= 1;
        assert!(
            <Felt as HashValue>::from_bytes(&below).is_some(),
            "values below the modulus are valid field elements"
        );
    }

    #[test]
    fn felt_from_bytes_rejects_wrong_lengths() {
        assert_eq!(<Felt as HashValue>::from_bytes(&[0; 31]), None);
        assert_eq!(<Felt as HashValue>::from_bytes(&[0; 33]), None);
    }
}

mod keccak256 {
    use super::*;

    #[test]
    fn genesis_matches_the_v0_5_golden() {
        assert_eq!(
            Keccak256Hasher.genesis(),
            hash_from_hex("ce92cc894a17c107be8788b58092c22cd0634d1489ca0ce5b4a045a1ce31b168"),
            "genesis = keccak(b\"brave new world\")"
        );
    }

    #[test]
    fn pair_of_equal_elements_matches_the_v0_5_golden() {
        let hasher = Keccak256Hasher;
        let element = hash_from_hex(LEAF_VECTOR);
        assert_eq!(
            hasher.hash_pair(element, element),
            hash_from_hex("a960dc82e45665d5b1340ee84f6c3f27abaac8235a1a3b7e954001c1bc682268"),
            "hash_pair is keccak over the concatenated operands"
        );
    }

    #[test]
    fn leaf_hash_matches_the_v0_5_golden() {
        let hasher = Keccak256Hasher;
        let element = hex_bytes(LEAF_VECTOR);
        assert_eq!(
            hasher
                .hash_leaf(&element)
                .expect("32-byte elements are always valid"),
            hash_from_hex("ee8c63253612ab4d2d00a272712aab9877a4bf43023e5cb1b41087bc1ccff6d9"),
            "hash_leaf is plain keccak over the element bytes"
        );
    }

    #[test]
    fn pair_of_distinct_elements_matches_the_v0_5_golden() {
        let hasher = Keccak256Hasher;
        let left = hash_from_hex(PAIR_LEFT_VECTOR);
        let right = hash_from_hex(PAIR_RIGHT_VECTOR);
        assert_eq!(
            hasher.hash_pair(left, right),
            hash_from_hex("ead5d1fa438c36f2c341756e97b2327214f21fee27aaeae4c91238c2c76374f5"),
        );
    }

    #[test]
    fn node_count_enters_pairs_as_a_big_endian_integer() {
        let hasher = Keccak256Hasher;
        let inner = hasher.hash_pair(
            hash_from_hex(PAIR_LEFT_VECTOR),
            hash_from_hex(PAIR_RIGHT_VECTOR),
        );
        assert_eq!(
            hasher.hash_pair(Hash::from_u64(10), inner),
            hash_from_hex("70c01463d822d2205868c5a46eefc55658828015b83e4553c8462d2c6711d0e0"),
            "v0.5 hashed [\"10\", result]: the count enters as a 32-byte BE integer"
        );
    }

    #[test]
    fn empty_leaves_hash_to_keccak_of_nothing() {
        assert_eq!(
            Keccak256Hasher
                .hash_leaf(b"")
                .expect("empty elements are valid for keccak"),
            hash_from_hex("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            "the well-known keccak256 of the empty byte string"
        );
    }

    #[test]
    fn large_leaves_are_accepted_without_size_limits() {
        // RLP encoding of Ethereum block 9877095 — a v0.5 golden pinning
        // keccak's deliberately unlimited leaf ingestion.
        let rlp = hex_bytes(
            "F90236A0B4147A5CA877AA084F4AF2FA2B22C72230EA7601CF97ECE9F11E1E0DA9A2A8BEA01D\
             CC4DE8DEC75D7AAB85B567B6CCD41AD312451B948A7413F0A142FD40D49347949029C772DDE8\
             47622DF1553ED9D9BDB7812E4F93A06B4FDB0BECCCB76D13D048657A1AA20BA82B0F002E685D\
             76ECADCF559668A947A02BC3BFD4CAC1EB2468012BF2ACB24740ED7623E7D193AF6293042835\
             D03DC232A0B7E2A4E26D596590F14B7F67249CE1B9CA08134879BF1945267C9C616248C81BB9\
             01006268004261112281700006258DA100EAD20081200C00110001884E108016190808108808\
             602628835878E20040222040C1001410A284202A8000A644902830020B13419C4E68229A51A0\
             3B0D022002A4968006C050462022004114448028510200082190020245400302188494000B13\
             8642A4A04801240A1E20483004280308884CA318000648002C060020142B1024580440098940\
             001800C84152342004941A0C10E10920003808B01608994C08042441642E802C044A460A005A\
             522082580901486B012002413205901A22049E402442E40609608214302444C60B8020A44810\
             0019200479210046810449000050C80B5A02D009E056000BA30643C046A0808396B6678401C9\
             C38083A78A8784652D4EA099D883010C00846765746888676F312E32302E37856C696E7578A0\
             45B5A59855191A6F7BC51333057ED664A1F506DB86CA86BA7F1B8B22ED09F155880000000000\
             0000000CA04A6437B1534900F6AA5B27BF0F8B817494C4895860B513E6DB94B715AEB4A014",
        );
        assert_eq!(
            Keccak256Hasher
                .hash_leaf(&rlp)
                .expect("keccak accepts arbitrarily large leaves"),
            hash_from_hex("fc9515e185a5a1b88dfb1708d397339019ce947083fc7ad64b048f885d48a9cc"),
            "keccak of the RLP of block 9877095"
        );
    }

    #[test]
    fn pair_hashing_cross_checks_against_tiny_keccak() {
        use tiny_keccak::Hasher as _;

        let hasher = Keccak256Hasher;
        let first = hash_from_hex(LEAF_VECTOR);
        let second = hash_from_hex(PAIR_LEFT_VECTOR);

        let mut input = [0; 64];
        input[..32].copy_from_slice(first.as_bytes());
        input[32..].copy_from_slice(second.as_bytes());
        let mut keccak = tiny_keccak::Keccak::v256();
        keccak.update(&input);
        let mut expected = [0; 32];
        keccak.finalize(&mut expected);

        assert_eq!(
            hasher.hash_pair(first, second),
            Hash::from_bytes(expected),
            "hash_pair is flat keccak over left || right"
        );
    }

    #[test]
    fn pair_hashing_is_order_sensitive() {
        let hasher = Keccak256Hasher;
        let left = hash_from_hex(LEAF_VECTOR);
        let right = hash_from_hex(PAIR_LEFT_VECTOR);
        assert_ne!(
            hasher.hash_pair(left, right),
            hasher.hash_pair(right, left),
            "hash_pair(a, b) must differ from hash_pair(b, a)"
        );
    }

    #[test]
    fn sol_keccak_is_an_alias_of_keccak256_hasher() {
        fn assert_same_type<T>(_: T, _: T) {}
        assert_same_type(Keccak256Hasher, Keccak256Hasher);
        let alias: SolKeccak = Keccak256Hasher;
        let _: Keccak256Hasher = alias;
    }

    #[test]
    fn keccak_metadata_reports_id_and_empty_config() {
        assert_eq!(Keccak256Hasher.id(), HasherId::Keccak256);
        assert_eq!(Keccak256Hasher.id().to_string(), "keccak256");
        assert_eq!(Keccak256Hasher.config(), Cow::Borrowed(""));
    }
}

mod poseidon {
    use super::*;

    #[test]
    fn genesis_is_the_leaf_hash_of_the_seed() {
        let hasher = PoseidonHasher { pad: false };
        let seed_leaf = hasher
            .hash_leaf(b"brave new world")
            .expect("the seed is a valid element");
        assert_eq!(
            hasher.genesis(),
            seed_leaf,
            "genesis = poseidon_hash_single(seed)"
        );
        assert_ne!(
            hasher.genesis(),
            Felt::ZERO,
            "genesis must not collapse to zero"
        );
    }

    #[test]
    fn genesis_is_deterministic() {
        let hasher = PoseidonHasher { pad: true };
        assert_eq!(hasher.genesis(), hasher.genesis());
    }

    #[test]
    fn short_leaves_are_left_padded_to_a_field_element() {
        let hasher = PoseidonHasher { pad: false };
        let mut padded = [0; 32];
        padded[30..].copy_from_slice(&[0x01, 0x23]);
        assert_eq!(
            hasher
                .hash_leaf(&[0x01, 0x23])
                .expect("short elements are valid"),
            hasher
                .hash_leaf(&padded)
                .expect("32-byte elements below the modulus are valid"),
            "element bytes are a left-padded big-endian integer"
        );
    }

    #[test]
    fn oversize_leaves_are_rejected() {
        let hasher = PoseidonHasher::default();
        let element = [7; 33];
        match hasher.hash_leaf(&element) {
            Err(HasherError::InvalidElementSize {
                element_size,
                block_size_bytes,
                block_size_bits,
            }) => {
                assert_eq!(element_size, 33, "the error carries the element size");
                assert_eq!(block_size_bytes, 32, "the limit is 32 bytes");
                assert_eq!(block_size_bits, 252, "the limit is 252 bits");
            }
            other => panic!("a 33-byte element must be rejected, got {other:?}"),
        }
    }

    #[test]
    fn field_modulus_leaves_are_rejected() {
        let hasher = PoseidonHasher::default();
        let modulus = hex_bytes(STARK_MODULUS_HEX);
        assert!(
            matches!(
                hasher.hash_leaf(&modulus),
                Err(HasherError::InvalidFieldElement)
            ),
            "values at or above the Starknet modulus are not field elements"
        );
    }

    #[test]
    fn sub_modulus_full_width_leaves_are_accepted() {
        let hasher = PoseidonHasher::default();
        let element = [0x01; 32];
        assert!(
            hasher.hash_leaf(&element).is_ok(),
            "32-byte values below the modulus are valid field elements"
        );
    }

    #[test]
    fn pair_hashing_is_order_sensitive() {
        let hasher = PoseidonHasher::default();
        let left = <Felt as HashValue>::from_u64(0x13a);
        let right = <Felt as HashValue>::from_u64(0x9f);
        assert_ne!(
            hasher.hash_pair(left, right),
            hasher.hash_pair(right, left),
            "poseidon_hash(l, r) must differ from poseidon_hash(r, l)"
        );
    }

    #[test]
    fn pad_flag_does_not_change_hashes() {
        let plain = PoseidonHasher { pad: false };
        let padded = PoseidonHasher { pad: true };
        let left = <Felt as HashValue>::from_u64(0x13a);
        let right = <Felt as HashValue>::from_u64(0x9f);
        assert_eq!(
            plain.hash_pair(left, right),
            padded.hash_pair(left, right),
            "pad only affects rendering width, not the stored 32-byte form"
        );
    }

    #[test]
    fn poseidon_metadata_reports_id_and_pad_config() {
        let plain = PoseidonHasher { pad: false };
        let padded = PoseidonHasher { pad: true };
        assert_eq!(plain.id(), HasherId::Poseidon);
        assert_eq!(padded.id(), HasherId::Poseidon);
        assert_eq!(plain.id().to_string(), "poseidon");
        assert_eq!(plain.config(), Cow::Borrowed("pad=false"));
        assert_eq!(padded.config(), Cow::Borrowed("pad=true"));
    }
}

mod pedersen {
    use super::*;

    #[test]
    fn pair_hashing_matches_the_golden_vector() {
        let hasher = PedersenHasher;
        let left = <Felt as HashValue>::from_u64(0x13a);
        let right = <Felt as HashValue>::from_u64(0x9f);
        let expected = Felt::from_bytes_be(&digest_bytes(
            "00ae4c67cf8deb4f68f6bad0ce61be81097cf082b4bfa83c637af99a978fa9bd",
        ));
        assert_eq!(
            hasher.hash_pair(left, right),
            expected,
            "hash_pair = pedersen_hash(left, right)"
        );
    }

    #[test]
    fn leaf_hashing_hashes_the_element_against_zero() {
        let hasher = PedersenHasher;
        let element = [0x01, 0x3a];
        let expected = starknet_crypto::pedersen_hash(&Felt::from(0x13a_u64), &Felt::ZERO);
        assert_eq!(
            hasher
                .hash_leaf(&element)
                .expect("short elements are valid"),
            expected,
            "hash_leaf = pedersen(element_as_felt, 0)"
        );
    }

    #[test]
    fn genesis_is_the_leaf_hash_of_the_seed() {
        let hasher = PedersenHasher;
        let seed_leaf = hasher
            .hash_leaf(b"brave new world")
            .expect("the seed is a valid element");
        assert_eq!(hasher.genesis(), seed_leaf, "genesis = pedersen(seed, 0)");
        assert_ne!(hasher.genesis(), Felt::ZERO);
    }

    #[test]
    fn oversize_and_non_field_leaves_are_rejected() {
        let hasher = PedersenHasher;
        assert!(
            matches!(
                hasher.hash_leaf(&[7; 33]),
                Err(HasherError::InvalidElementSize {
                    element_size: 33,
                    ..
                })
            ),
            "elements above 32 bytes must be rejected"
        );
        let modulus = hex_bytes(STARK_MODULUS_HEX);
        assert!(
            matches!(
                hasher.hash_leaf(&modulus),
                Err(HasherError::InvalidFieldElement)
            ),
            "values at or above the modulus must be rejected"
        );
    }

    #[test]
    fn pedersen_metadata_reports_id_and_empty_config() {
        assert_eq!(PedersenHasher.id(), HasherId::Pedersen);
        assert_eq!(PedersenHasher.id().to_string(), "pedersen");
        assert_eq!(PedersenHasher.config(), Cow::Borrowed(""));
    }
}

mod blake2s {
    use super::*;
    use blake2::Digest;

    /// The v0.5 genesis seed (52 bytes — a multiple of the 4-byte word).
    const GENESIS_SEED: &[u8] = b"Chancellor on the brink of second bailout for banks.";

    /// Reference Cairo-flavored digest: BLAKE2s-256 with each 4-byte output
    /// word byte-reversed, optional 252-bit truncation of the top nibble.
    fn reference_digest(input: &[u8], truncate: bool) -> Hash {
        let mut digest: [u8; 32] = blake2::Blake2s256::digest(input).into();
        for word in digest.as_chunks_mut::<4>().0 {
            word.reverse();
        }
        if truncate {
            digest[0] &= 0x0f;
        }
        Hash::from_bytes(digest)
    }

    #[test]
    fn genesis_matches_the_reference_digest() {
        let hasher = Blake2sHasher { truncate: false };
        assert_eq!(
            hasher.genesis(),
            hash_from_hex("fb47194ef3c98ee1b296e1b5ca4d8f33dbbb9aebb6e64008cb71088f14c3c191"),
            "genesis = blake2s of the seed with word-reversed output"
        );
        assert_eq!(hasher.genesis(), reference_digest(GENESIS_SEED, false));
    }

    #[test]
    fn truncated_genesis_matches_the_reference_digest() {
        let hasher = Blake2sHasher { truncate: true };
        let genesis = hasher.genesis();
        assert_eq!(
            genesis,
            hash_from_hex("0b47194ef3c98ee1b296e1b5ca4d8f33dbbb9aebb6e64008cb71088f14c3c191"),
            "truncation masks the top nibble of the untruncated genesis"
        );
        assert_eq!(genesis, reference_digest(GENESIS_SEED, true));
        assert_eq!(
            genesis.as_bytes()[0] & 0xf0,
            0,
            "the top nibble must be zero"
        );
    }

    #[test]
    fn empty_leaf_matches_the_golden_vector() {
        let hasher = Blake2sHasher { truncate: false };
        assert_eq!(
            hasher
                .hash_leaf(b"")
                .expect("empty elements are word-aligned"),
            hash_from_hex("307a216994809079d02111e17c4a354248b6551f1ea5a12cfd0d251bf9eed01e"),
            "v0.5 golden for the empty element"
        );
    }

    #[test]
    fn zero_word_leaf_matches_the_golden_vectors() {
        let plain = Blake2sHasher { truncate: false };
        let truncating = Blake2sHasher { truncate: true };
        let zeros = [0; 32];
        assert_eq!(
            plain
                .hash_leaf(&zeros)
                .expect("32-byte elements are word-aligned"),
            hash_from_hex("a95e0b32c23b659e41db93b54e0ad1304c0b3afd67a6e1c2718d672bad33bddf"),
            "v0.5 golden without truncation"
        );
        assert_eq!(
            truncating
                .hash_leaf(&zeros)
                .expect("32-byte elements are word-aligned"),
            hash_from_hex("095e0b32c23b659e41db93b54e0ad1304c0b3afd67a6e1c2718d672bad33bddf"),
            "v0.5 golden with truncation"
        );
    }

    #[test]
    fn misaligned_leaves_are_rejected() {
        let hasher = Blake2sHasher { truncate: false };
        let misaligned: [&[u8]; 4] = [b"x", b"xy", b"xyz", b"abcde"];
        for element in misaligned {
            match hasher.hash_leaf(element) {
                Err(HasherError::InvalidElementAlignment {
                    element_size,
                    alignment,
                }) => {
                    assert_eq!(element_size, element.len(), "the error carries the size");
                    assert_eq!(alignment, 4, "the word alignment is 4 bytes");
                }
                other => panic!(
                    "a {}-byte element must be rejected as misaligned, got {other:?}",
                    element.len()
                ),
            }
        }
    }

    #[test]
    fn pair_matches_the_reference_digest() {
        for truncate in [false, true] {
            let hasher = Blake2sHasher { truncate };
            let left = hash_from_hex(LEAF_VECTOR);
            let right = hash_from_hex(PAIR_LEFT_VECTOR);

            let mut input = [0; 64];
            input[..32].copy_from_slice(left.as_bytes());
            input[32..].copy_from_slice(right.as_bytes());
            for word in input.as_chunks_mut::<4>().0 {
                word.reverse();
            }

            assert_eq!(
                hasher.hash_pair(left, right),
                reference_digest(&input, truncate),
                "hash_pair word-reverses both operands before hashing"
            );
        }
    }

    #[test]
    fn aligned_leaves_match_the_reference_digest() {
        for truncate in [false, true] {
            let hasher = Blake2sHasher { truncate };
            let element = [0xa5; 8];
            assert_eq!(
                hasher
                    .hash_leaf(&element)
                    .expect("8-byte elements are word-aligned"),
                reference_digest(&element, truncate),
                "hash_leaf word-reverses the element before hashing"
            );
        }
    }

    #[test]
    fn truncation_zeroes_only_the_top_nibble() {
        let plain = Blake2sHasher { truncate: false };
        let truncating = Blake2sHasher { truncate: true };
        let element = [0x5a; 16];
        let untruncated = plain
            .hash_leaf(&element)
            .expect("16 bytes are word-aligned");
        let truncated = truncating
            .hash_leaf(&element)
            .expect("16 bytes are word-aligned");
        assert_eq!(
            truncated.as_bytes()[0] & 0xf0,
            0,
            "the top nibble is zeroed"
        );
        assert_eq!(
            truncated.as_bytes()[0] & 0x0f,
            untruncated.as_bytes()[0] & 0x0f,
            "the low nibble survives truncation"
        );
        assert_eq!(
            &truncated.as_bytes()[1..],
            &untruncated.as_bytes()[1..],
            "truncation touches nothing but the first byte's top nibble"
        );
    }

    #[test]
    fn blake2s_metadata_reports_id_and_truncate_config() {
        let plain = Blake2sHasher { truncate: false };
        let truncating = Blake2sHasher { truncate: true };
        assert_eq!(plain.id(), HasherId::Blake2s);
        assert_eq!(truncating.id(), HasherId::Blake2s);
        assert_eq!(plain.id().to_string(), "blake2s");
        assert_eq!(plain.config(), Cow::Borrowed("truncate=false"));
        assert_eq!(truncating.config(), Cow::Borrowed("truncate=true"));
    }
}
