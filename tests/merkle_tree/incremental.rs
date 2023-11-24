use std::sync::Arc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher,
    merkle_tree::incremental::IncrementalMerkleTree,
    store::{sqlite::SQLiteStore, SubKey},
};

#[tokio::test]
async fn initialize() {
    let store = SQLiteStore::new(":memory:").await.unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = Arc::new(store);

    let tree =
        IncrementalMerkleTree::initialize(1024, "0x0".to_string(), hasher, store, None).await;
    assert_eq!(
        tree.get_root().await,
        "0x4a21358c3e754766216b4c93ecfae222e86822f746e706e563f3a05ef398959"
    );
}

#[tokio::test]
async fn get_path() {
    let store = SQLiteStore::new(":memory:").await.unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = Arc::new(store);
    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None).await;

    let path = tree.get_inclusion_proof(10).await.unwrap();
    let expected_nodes = vec![
        SubKey::String("4:11".to_string()),
        SubKey::String("3:4".to_string()),
        SubKey::String("2:3".to_string()),
        SubKey::String("1:0".to_string()),
    ];

    // Await the async call and store the result
    let node_map = tree.nodes.get_many(expected_nodes.clone()).await;

    // Now use the resulting HashMap
    let expected_path: Vec<String> = expected_nodes
        .iter()
        .filter_map(|idx| node_map.get(&idx.to_string()).cloned())
        .collect();

    assert_eq!(path, expected_path);
}

#[tokio::test]
async fn verify_proof() {
    let store = SQLiteStore::new(":memory:").await.unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = Arc::new(store);
    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None).await;

    let path = tree.get_inclusion_proof(10).await.unwrap();
    let valid_proof = tree.verify_proof(10, "0x0", &path).await.unwrap();
    assert!(valid_proof);

    let invalid_proof = tree.verify_proof(10, "0x1", &path).await.unwrap();
    assert!(!invalid_proof);
}

#[tokio::test]
async fn update() {
    let store = SQLiteStore::new(":memory:").await.unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = Arc::new(store);
    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None).await;

    let path = tree.get_inclusion_proof(7).await.unwrap();
    let valid_proof = tree.verify_proof(7, "0x0", &path).await.unwrap();
    assert!(valid_proof);

    tree.update(7, "0x0".to_string(), "0x1".to_string(), path.clone())
        .await
        .unwrap();

    let invalid_proof = tree.verify_proof(7, "0x0", &path).await.unwrap();
    assert!(!invalid_proof);

    let updated_proof = tree.verify_proof(7, "0x1", &path).await.unwrap();
    assert!(updated_proof);

    assert_eq!(
        tree.get_root().await,
        "0x53228c039bc23bffa7a0ba7a864088f98c92dbc41c3737b681cdd7b1bcfe1f2"
    );
}

#[tokio::test]
async fn invalid_update() {
    let store = SQLiteStore::new(":memory:").await.unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = Arc::new(store);
    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None).await;
    let path = tree.get_inclusion_proof(7).await.unwrap();
    let empty_root = tree.get_root().await;
    let result = tree
        .update(7, "0x1".to_string(), "0x2".to_string(), path.clone())
        .await;
    assert!(result.is_err());
    assert_eq!(tree.get_root().await, empty_root);
}

#[tokio::test]
async fn generate_and_verify_multi_proof() {
    let store = SQLiteStore::new(":memory:").await.unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));

    let store = Arc::new(store);

    let tree_size = 64;
    let default_hash = "0x0".to_string();
    let tree =
        IncrementalMerkleTree::initialize(tree_size, default_hash.clone(), hasher, store, None)
            .await;

    for i in 0..tree_size {
        let path = tree.get_inclusion_proof(i).await.unwrap();
        let new_value = format!("0x{}", i);
        let _ = tree.update(i, default_hash.clone(), new_value, path).await;
    }

    let mut test = vec![0, 2, 7, 14, 31, 63];
    let mut test_values = test.iter().map(|x| format!("0x{}", x)).collect::<Vec<_>>();

    let mut multiproof = tree.get_inclusion_multi_proof(test.clone()).await.unwrap();

    assert_eq!(
        multiproof,
        vec![
            "0x1",
            "0x3",
            "0x6",
            "0x15",
            "0x30",
            "0x62",
            "0x384f427301be8e1113e6dd91088cb46e25a8f6426a997b2f842a39596bf45f4",
            "0x12fc9d00e26e0a80b4d430d2346e3ee5f9b0744a12bde36f888cc334492d73e",
            "0x439821452efbe677b70e63130730f7d0bf0e30c3c037f42982d13cff1ccc6af",
            "0x5c4350af24dc2738090681354fa258f18c78a64c1fd9cf0724d504f1a2035c7",
            "0x23276b7f6c1f939788cf65bd03b2ed795ffeb566833e280fe6bcd67e1d5c825",
            "0x74f149518beb51f2f1e92ec5cabefc8c3c2981a41a27474993c5d6d59428ec4",
            "0x259bcdd083bf01f556cb1b35ff6853d6fcffb947bbce2b55e370bd20f7fef3a",
            "0x5c978bd2fd9afb398230e295e1672793918ade2970c017059d66c727a648858",
            "0x1afa27419b39701ccc2d4efae574ff711eeb2c3ef4aa527e1eb9c6e390e13ef",
            "0x6daedd1626c776eadcd90f017bb95ce29d14975425257907ef2ec8b67f960eb"
        ]
    );

    let is_valid = tree
        .verify_multi_proof(&mut test, &mut test_values, &mut multiproof)
        .await;

    assert!(is_valid);
}

#[tokio::test]
async fn example() {
    use accumulators::{
        hasher::stark_poseidon::StarkPoseidonHasher,
        merkle_tree::incremental::IncrementalMerkleTree, store::memory::InMemoryStore,
    };

    let store = InMemoryStore::new();
    let store = Arc::new(store);
    let hasher = StarkPoseidonHasher::new(Some(false));

    let tree = IncrementalMerkleTree::initialize(16, "0x0".to_string(), hasher, store, None).await;

    let path = tree.get_inclusion_proof(10).await.unwrap();
    let valid_proof = tree.verify_proof(10, "0x0", &path).await.unwrap();
    assert!(valid_proof);

    let invalid_proof = tree.verify_proof(10, "0x1", &path).await.unwrap();
    assert!(!invalid_proof);
}
