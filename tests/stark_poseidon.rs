#[cfg(test)]
mod tests {
    use mmr::hash::{stark_poseidon::StarkPoseidonHasher, IHasher};

    #[test]
    fn should_compute_a_hash() {
        let hasher = StarkPoseidonHasher::new(Some(false));
        let a = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d17761".to_string();
        let b = "0x0194791558611599fe4ae0fcfa48f095659c90db18e54de86f2d2f547f7369bf".to_string();

        assert_eq!(hasher.is_element_size_valid(&a), true);
        assert_eq!(hasher.is_element_size_valid(&b), true);

        let result = hasher.hash(vec![a, b]).unwrap();

        assert_eq!(
            result,
            "0x7b8180db85fa1e0b5041f38f57926743905702c498576991f04998b5d9476b4".to_string()
        );
    }

    // #[test]
    // fn should_compute_a_hash_2() {
    //     let hasher = StarkPedersenHasher::new();
    //     let a = "1".to_string();
    //     let b = "0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804".to_string();

    //     assert_eq!(hasher.is_element_size_valid(&a), true);
    //     assert_eq!(hasher.is_element_size_valid(&b), true);

    //     let result = hasher.hash(vec![a, b]);

    //     assert_eq!(
    //         result,
    //         "0x049ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804".to_string()
    //     );
    // }

    #[test]
    fn should_throw() {
        let hasher = StarkPoseidonHasher::new(Some(false));
        let a = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf40x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4".to_string();
        let b = "0x0194791558611599fe4ae0fcfa48f095659c90db18e54de86f2d2f547f7369bf".to_string();

        assert_eq!(hasher.is_element_size_valid(&a), false);
    }
}
