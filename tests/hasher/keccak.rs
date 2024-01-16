use accumulators::hasher::{keccak::KeccakHasher, Hasher};

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn genesis() {
        let hasher = KeccakHasher::default();

        assert_eq!(
            hasher.get_genesis().unwrap(),
            "0xce92cc894a17c107be8788b58092c22cd0634d1489ca0ce5b4a045a1ce31b168".to_string()
        );
    }

    #[test]
    fn should_compute_a_hash() {
        let hasher = KeccakHasher::new();

        let a = "0xa4b1d5793b631de611c922ea3ec938b359b3a49e687316d9a79c27be8ce84590".to_string();
        let b = "0xa4b1d5793b631de611c922ea3ec938b359b3a49e687316d9a79c27be8ce84590".to_string();

        assert!(hasher.is_element_size_valid(&a).unwrap());
        assert!(hasher.is_element_size_valid(&b).unwrap());

        let result = hasher.hash(vec![a.to_string(), b.to_string()]).unwrap();

        assert_eq!(
            result,
            "0xa960dc82e45665d5b1340ee84f6c3f27abaac8235a1a3b7e954001c1bc682268".to_string()
        );
    }

    #[test]
    fn should_compute_a_hash_for_non_hex() {
        let hasher = KeccakHasher::new();

        let a = "0xbd946409a993b84d18be8dc09081a9cdcecedfedf3a1ff984175e5f3667af887".to_string();
        let b = "0x9cfabdfca79eb1ae44266614b731aa30d2aed697fa01d83b933498f1095f0941".to_string();

        assert!(hasher.is_element_size_valid(&a).unwrap());
        assert!(hasher.is_element_size_valid(&b).unwrap());

        let result = hasher.hash(vec![a.to_string(), b.to_string()]).unwrap();

        assert_eq!(
            result,
            "0xead5d1fa438c36f2c341756e97b2327214f21fee27aaeae4c91238c2c76374f5".to_string()
        );

        let final_result: String = hasher.hash(vec!["10".to_string(), result]).unwrap();

        assert_eq!(
            final_result,
            "0x1a0a347398081822baeed647ee46c1a50e406133341a0de3f33bb7805092d20d".to_string()
        );
    }

    #[test]
    fn should_correctly_compute_a_hash_of_a_single_element() {
        let hasher = KeccakHasher::new();

        let a = "0xa4b1d5793b631de611c922ea3ec938b359b3a49e687316d9a79c27be8ce84590".to_string();
        let result = hasher.hash(vec![a]).unwrap();

        assert_eq!(
            result,
            "0xee8c63253612ab4d2d00a272712aab9877a4bf43023e5cb1b41087bc1ccff6d9"
        )
    }

    #[test]
    fn should_compute_block_hash() {
        let hasher = KeccakHasher::new();

        // RLP of block number 9877095
        let raw_hex_rlp = "0xF90236A0B4147A5CA877AA084F4AF2FA2B22C72230EA7601CF97ECE9F11E1E0DA9A2A8BEA01DCC4DE8DEC75D7AAB85B567B6CCD41AD312451B948A7413F0A142FD40D49347949029C772DDE847622DF1553ED9D9BDB7812E4F93A06B4FDB0BECCCB76D13D048657A1AA20BA82B0F002E685D76ECADCF559668A947A02BC3BFD4CAC1EB2468012BF2ACB24740ED7623E7D193AF6293042835D03DC232A0B7E2A4E26D596590F14B7F67249CE1B9CA08134879BF1945267C9C616248C81BB901006268004261112281700006258DA100EAD20081200C00110001884E108016190808108808602628835878E20040222040C1001410A284202A8000A644902830020B13419C4E68229A51A03B0D022002A4968006C050462022004114448028510200082190020245400302188494000B138642A4A04801240A1E20483004280308884CA318000648002C060020142B1024580440098940001800C84152342004941A0C10E10920003808B01608994C08042441642E802C044A460A005A522082580901486B012002413205901A22049E402442E40609608214302444C60B8020A448100019200479210046810449000050C80B5A02D009E056000BA30643C046A0808396B6678401C9C38083A78A8784652D4EA099D883010C00846765746888676F312E32302E37856C696E7578A045B5A59855191A6F7BC51333057ED664A1F506DB86CA86BA7F1B8B22ED09F1558800000000000000000CA04A6437B1534900F6AA5B27BF0F8B817494C4895860B513E6DB94B715AEB4A014".to_lowercase().to_string();
        let new_block_hash = hasher.hash(vec![raw_hex_rlp]).unwrap();

        assert_eq!(
            new_block_hash,
            // Hash of block number 9877095
            "0xfc9515e185a5a1b88dfb1708d397339019ce947083fc7ad64b048f885d48a9cc".to_string()
        )
    }

    #[test]
    fn should_fail_on_non_hex_encoded_string_of_single_value_as_ts_implementation() {
        let hasher = KeccakHasher::new();
        let a = "3";

        assert!(hasher.hash(vec![a.to_string()]).is_err());
    }

    #[test]
    fn should_handle_empty_array_like_the_ts_implementation() {
        let hasher = KeccakHasher::new();

        let hash = hasher.hash(vec![]).unwrap();

        let ts_implementation_hash_from_empty_array =
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";

        assert_eq!(hash, ts_implementation_hash_from_empty_array);
    }

    #[test]
    fn should_correctly_apply_padding() {
        let hasher = KeccakHasher::new();

        let a = "3";
        let b = "4";

        let hash = hasher.hash(vec![a.to_string(), b.to_string()]).unwrap();

        let expected_hash_taken_from_old_implementation =
            "0x2e174c10e159ea99b867ce3205125c24a42d128804e4070ed6fcc8cc98166aa0";

        assert_eq!(hash.len(), "0x".len() + 64);
        assert_eq!(hash, expected_hash_taken_from_old_implementation);
    }

    #[test]
    fn should_apply_padding() {
        let hasher = KeccakHasher::new();
        let a = hex::encode("131");
        let b = hex::encode("10");
        let hash = hasher.hash(vec![a, b]).unwrap();

        print!("{}", hash);

        assert_eq!(hash.len(), 64 + 2)
    }

    #[test]
    fn hashes_a_combination_of_hex_number_as_string() {
        let hasher = KeccakHasher::new();

        let values_to_hash: Vec<String> = ["0x1", "1", "0x2", "2", "0x3", "3", "0x4", "4"]
            .iter()
            .map(|&s| s.to_string())
            .collect();

        let hash = hasher.hash(values_to_hash).unwrap();

        assert_eq!(
            hash,
            "0xf6770da1453b562908e206793d4b1f99237e8177d7a4403dfdb8012972912b61".to_string()
        );
    }
}
