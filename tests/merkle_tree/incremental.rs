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
