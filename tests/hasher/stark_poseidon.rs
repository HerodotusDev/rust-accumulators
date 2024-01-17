use accumulators::hasher::{stark_poseidon::StarkPoseidonHasher, Hasher};

#[test]
fn should_compute_a_hash() {
    let hasher = StarkPoseidonHasher::default();

    let a = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d17761".to_string();
    let b = "0x0194791558611599fe4ae0fcfa48f095659c90db18e54de86f2d2f547f7369bf".to_string();

    assert!(hasher.is_element_size_valid(&a).unwrap());
    assert!(hasher.is_element_size_valid(&b).unwrap());

    let result = hasher.hash(vec![a, b]).unwrap();

    assert_eq!(
        result,
        "0x7b8180db85fa1e0b5041f38f57926743905702c498576991f04998b5d9476b4".to_string()
    );
}

#[test]
fn should_compute_single_element() {
    let hasher = StarkPoseidonHasher::default();
    let a = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d17761".to_string();

    assert!(hasher.is_element_size_valid(&a).unwrap());

    let result = hasher.hash(vec![a]).unwrap();

    assert_eq!(
        result,
        "0x5d685fd03936a3f5151bb39d8ff837ad8874306d191fc58a044521da1d30fad".to_string()
    );

    let b = "0x0194791558611599fe4ae0fcfa48f095659c90db18e54de86f2d2f547f7369bf".to_string();

    assert!(hasher.is_element_size_valid(&b).unwrap());

    let result = hasher.hash(vec![b]).unwrap();

    assert_eq!(
        result,
        "0x4ef2629853adf5f5377deba20f7cc4e3e37b5a5aa9f989c2020ac2d15693e7".to_string()
    );
}

#[test]
fn check_correctly_apply_padding_two_elements() {
    let hasher = StarkPoseidonHasher::default();

    let a = "3".to_string();
    let b = "4".to_string();

    assert!(hasher.is_element_size_valid(&a).unwrap());
    assert!(hasher.is_element_size_valid(&b).unwrap());

    let result = hasher.hash(vec![a, b]).unwrap();

    assert_eq!(
        result,
        "0x508c780b8cd26ffaa0ba03933770a02987d3d94870e70bc388f9bef69af180d".to_string()
    );

    let a = "0x3".to_string();
    let b = "0x4".to_string();

    assert!(hasher.is_element_size_valid(&a).unwrap());
    assert!(hasher.is_element_size_valid(&b).unwrap());

    let result = hasher.hash(vec![a, b]).unwrap();

    assert_eq!(
        result,
        "0x508c780b8cd26ffaa0ba03933770a02987d3d94870e70bc388f9bef69af180d".to_string()
    );

    let a = "0x000000003".to_string();
    let b = "0x000000004".to_string();

    assert!(hasher.is_element_size_valid(&a).unwrap());
    assert!(hasher.is_element_size_valid(&b).unwrap());

    let result = hasher.hash(vec![a, b]).unwrap();

    assert_eq!(
        result,
        "0x508c780b8cd26ffaa0ba03933770a02987d3d94870e70bc388f9bef69af180d".to_string()
    );
}

#[test]
fn check_correctly_apply_padding_one_element() {
    let hasher = StarkPoseidonHasher::default();

    let a = "3".to_string();

    assert!(hasher.is_element_size_valid(&a).unwrap());

    let result = hasher.hash_single(&a).unwrap();

    assert_eq!(
        result,
        "0x522ce35ecb769b5017959d77720ea484b8b8929314a678f2b1b363e4a75bbe1".to_string()
    );

    let a = "0x3".to_string();

    assert!(hasher.is_element_size_valid(&a).unwrap());

    let result = hasher.hash_single(&a).unwrap();

    assert_eq!(
        result,
        "0x522ce35ecb769b5017959d77720ea484b8b8929314a678f2b1b363e4a75bbe1".to_string()
    );

    let a = "0x000000003".to_string();
    let b = "0x000000004".to_string();

    assert!(hasher.is_element_size_valid(&a).unwrap());
    assert!(hasher.is_element_size_valid(&b).unwrap());

    let result = hasher.hash(vec![a, b]).unwrap();

    assert_eq!(
        result,
        "0x508c780b8cd26ffaa0ba03933770a02987d3d94870e70bc388f9bef69af180d".to_string()
    );
}

#[test]
fn check_genesis_hash() {
    let hasher = StarkPoseidonHasher::default();

    assert_eq!(
        hasher.get_genesis().unwrap(),
        "0x2241b3b7f1c4b9cf63e670785891de91f7237b1388f6635c1898ae397ad32dd".to_string()
    );
}

#[test]
fn hash_combination_hex_and_numbers() {
    let hasher = StarkPoseidonHasher::default();

    assert_eq!(
        hasher
            .hash(vec![
                "0x1".to_string(),
                "1".to_string(),
                "0x2".to_string(),
                "2".to_string(),
                "0x3".to_string(),
                "3".to_string(),
                "0x4".to_string(),
                "4".to_string()
            ])
            .unwrap(),
        "0x2de470542009171446e0c9964111c7efdd61db18e5e10b0a507b1c2352e6458".to_string()
    );
}

#[test]
fn should_throw() {
    //? it should throw if the element size is not valid either for single or multiple elements
    let hasher = StarkPoseidonHasher::default();
    let a: String = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf40x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4".to_string();
    let b = "0x508c780b8cd26ffaa0ba03933770a02987d3d94870e70bc388f9bef69af180d".to_string();

    assert!(hasher.is_element_size_valid(&a).is_err());
    assert!(hasher.is_element_size_valid(&b).unwrap());

    assert!(hasher.hash(vec![a, b]).is_err());

    let a: String = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf40x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4".to_string();

    assert!(hasher.is_element_size_valid(&a).is_err());
    assert!(hasher.hash_single(&a).is_err());
}

#[test]
fn should_throw_on_empty_array() {
    let hasher = StarkPoseidonHasher::default();

    assert!(hasher.hash(vec![]).is_err());
}
