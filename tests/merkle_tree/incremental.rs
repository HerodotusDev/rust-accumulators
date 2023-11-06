use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, merkle_tree::incremental::IncrementalMerkleTree,
    store::sqlite::SQLiteStore,
};

#[test]
fn initialize() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    store.init().expect("Failed to init store");

    let tree = IncrementalMerkleTree::initialize(1024, "0x0".to_string(), hasher, store, None);
    assert_eq!(
        tree.get_root(),
        "0x4a21358c3e754766216b4c93ecfae222e86822f746e706e563f3a05ef398959"
    );
}

#[test]
fn get_path() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    store.init().expect("Failed to init store");
    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None);

    let path = tree.get_inclusion_proof(10).unwrap();
    let expected_nodes = vec![
        "4:11".to_string(),
        "3:4".to_string(),
        "2:3".to_string(),
        "1:0".to_string(),
    ];

    let expected_path: Vec<String> = expected_nodes
        .iter()
        .filter_map(|idx| {
            tree.nodes
                .get_many(expected_nodes.clone())
                .get(&idx.to_string())
                .cloned()
        })
        .collect();
    assert_eq!(path, expected_path);
}

#[test]
fn verify_proof() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    store.init().expect("Failed to init store");
    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None);

    let path = tree.get_inclusion_proof(10).unwrap();
    let valid_proof = tree.verify_proof(10, "0x0", &path).unwrap();
    assert_eq!(valid_proof, true);

    let invalid_proof = tree.verify_proof(10, "0x1", &path).unwrap();
    assert_eq!(invalid_proof, false);
}

#[test]
fn update() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    store.init().expect("Failed to init store");
    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None);

    let path = tree.get_inclusion_proof(7).unwrap();
    let valid_proof = tree.verify_proof(7, "0x0", &path).unwrap();
    assert_eq!(valid_proof, true);

    tree.update(7, "0x0".to_string(), "0x1".to_string(), path.clone())
        .unwrap();

    let invalid_proof = tree.verify_proof(7, "0x0", &path).unwrap();
    assert_eq!(invalid_proof, false);

    let updated_proof = tree.verify_proof(7, "0x1", &path).unwrap();
    assert_eq!(updated_proof, true);

    assert_eq!(
        tree.get_root(),
        "0x53228c039bc23bffa7a0ba7a864088f98c92dbc41c3737b681cdd7b1bcfe1f2"
    );
}
