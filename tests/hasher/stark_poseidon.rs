use accumulators::hasher::{stark_poseidon::StarkPoseidonHasher, Hasher};

#[test]
fn should_compute_a_hash() {
    let hasher = StarkPoseidonHasher::new(Some(false));

    let a = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d17761".to_string();
    let b = "0x0194791558611599fe4ae0fcfa48f095659c90db18e54de86f2d2f547f7369bf".to_string();

    assert!(hasher.is_element_size_valid(&a));
    assert!(hasher.is_element_size_valid(&b));

    let result = hasher.hash(vec![a, b]).unwrap();

    assert_eq!(
        result,
        "0x7b8180db85fa1e0b5041f38f57926743905702c498576991f04998b5d9476b4".to_string()
    );
}

#[test]
fn check_genesis_hash() {
    let hasher = StarkPoseidonHasher::new(Some(false));

    assert_eq!(
        hasher.get_genesis(),
        "0x2241b3b7f1c4b9cf63e670785891de91f7237b1388f6635c1898ae397ad32dd".to_string()
    );
}

// #[test]
// fn try_one() {
//     let hasher = StarkPoseidonHasher::new(Some(false));

//     assert_eq!(
//         hasher
//             .hash(vec!["0x0".to_string(), "1".to_string()])
//             .unwrap(),
//         "0x293d3e8a80f400daaaffdd5932e2bcc8814bab8f414a75dcacf87318f8b14c5".to_string()
//     );
// }

#[test]
fn should_throw() {
    let hasher = StarkPoseidonHasher::new(Some(false));
    let a = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf40x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4".to_string();

    assert!(!hasher.is_element_size_valid(&a));
}
