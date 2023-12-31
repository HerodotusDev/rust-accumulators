use accumulators::hasher::{stark_pedersen::StarkPedersenHasher, Hasher};

#[test]
fn should_compute_a_hash() {
    let hasher = StarkPedersenHasher::default();
    let a = "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d17761".to_string();
    let b = "0x0194791558611599fe4ae0fcfa48f095659c90db18e54de86f2d2f547f7369bf".to_string();

    assert!(hasher.is_element_size_valid(&a).is_ok());
    assert!(hasher.is_element_size_valid(&b).is_ok());

    let result = hasher.hash(vec![a, b]).unwrap();

    assert_eq!(
        result,
        "0x02a3725ff7b6ad90f9429132de22a875b842522f568f201972502185d77d4d33".to_string()
    );
}

#[test]
#[should_panic]
fn should_throw() {
    let hasher = StarkPedersenHasher::default();
    let a =
        "0x6109f1949f6a7555eccf4e15ce1f10fbd78091dfe715cc2e0c5a244d9d177610x6109f1949f6a7555eccf4"
            .to_string();
    let b = "0x0194791558611599fe4ae0fcfa48f095659c90db18e54de86f2d2f547f7369bf".to_string();

    assert!(hasher.is_element_size_valid(&a).is_err());
    hasher.hash(vec![a, b]).unwrap();
}
