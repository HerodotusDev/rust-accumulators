use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, merkle_tree::incremental::IncrementalMerkleTree,
    store::sqlite::SQLiteStore,
};

#[test]
fn initialize_incremental() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    let tree = IncrementalMerkleTree::initialize(1024, "0x0".to_string(), hasher, store, None);
    assert_eq!(tree.size, 1024);
}
