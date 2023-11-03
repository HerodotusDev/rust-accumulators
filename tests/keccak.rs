#[cfg(test)]
mod tests {
    use accumulators::hash::{keccak::KeccakHasher, IHasher};

    #[test]
    fn genesis() {
        let hasher = KeccakHasher::new();

        assert_eq!(
            hasher.get_genesis(),
            "0xce92cc894a17c107be8788b58092c22cd0634d1489ca0ce5b4a045a1ce31b168".to_string()
        );
    }

    #[test]
    fn should_compute_a_hash() {
        let hasher = KeccakHasher::new();

        let a = "0xa4b1d5793b631de611c922ea3ec938b359b3a49e687316d9a79c27be8ce84590".to_string();
        let b = "0xa4b1d5793b631de611c922ea3ec938b359b3a49e687316d9a79c27be8ce84590".to_string();

        assert_eq!(hasher.is_element_size_valid(&a), true);
        assert_eq!(hasher.is_element_size_valid(&b), true);

        let result = hasher.hash(vec![a, b]).unwrap();

        assert_eq!(
            result,
            "0xa960dc82e45665d5b1340ee84f6c3f27abaac8235a1a3b7e954001c1bc682268".to_string()
        );

        let raw_hex_rlp = "0xf9022ca0b8ac881ac6d93bb79b9610fefecfcdfa4716a31ab1c2c63e9a0acd007efe91fda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794000095e79eac4d76aab57cb2c1f091d553b36ca0a05ab953427f125b96a466204e7611ab2aa5dd1f38106776406061a7bc0d99ec4aa0cdd691b4418ba6e18aa8c28420185c77dccbbb7b74bc5a15a612f00fa8bf70aca00a3c0feb385283236f840d09bb11322cb7ccd38d9435b0110352b89a157eb30cb9010000fd48c020a0644402118038855d20c410ad10102a40599c20f98850d873110d32231461d31002310090c8089d044cd742421236020238749110de1690240660c0f26032df72038d5b10130bb20a936e2c059a302060f4898450c1e4a08888a96b411104b6064020084809bd10110db011189004402867c008e26e134800140b1f8322708084902a01440248ca000426326d5005431d2e88290785483042c0c6060518963460121100a008620191430072400a07a0862314010b1d2f003a0206993150131150a008104263498d136404ad8c908c18802230230f3e324c82b5281c10b92d30308e75b0392b2020011404841130564a3106c04802410007805ba38083883dcb8401c9c38083cbd94a846450fab08a4e65746865726d696e64a00d14206369368fdacbdb2035f756fffa2c32fb37fdd6acc2ad87e0f5e634e23f880000000000000000850213e9b610a039286c1612bea6175976e164b69f02850406743b60cc67a0a902892689472b27".to_string();
        hasher.hash(vec![raw_hex_rlp]);
    }

    #[test]
    fn should_apply_padding() {
        let hasher = KeccakHasher::new();
        let a = "3".to_string();
        let b = "4".to_string();
        hasher.hash(vec![a, b]).unwrap();
    }
}
