// use std::sync::{Arc, Mutex};

// use mmr::{
//     core::CoreMMR,
//     hash::{stark_pedersen::StarkPedersenHasher, IHasher},
//     store::sqlite::SQLiteStore,
//     utils::AppendResult,
// };

#[tokio::test]
async fn test_new() {
    // let leaves = vec!["1", "2", "3", "4", "5"];

    // // Arrange
    // let store = SQLiteStore::new(":memory:").unwrap();
    // let store2 = SQLiteStore::new(":memory:").unwrap(); // Clone the store
    // let hasher = Box::new(StarkPedersenHasher::new());
    // let _ = store.init();
    // let _ = store2.init();
    // let store_input = Arc::new(Mutex::new(store));
    // let store2_input = Arc::new(Mutex::new(store2));
    // // Act
    // let mut core_mmr = CoreMMR::new(store_input, hasher, Some("test".to_string()));
    // let mut appends_results: Vec<AppendResult> = Vec::new();
    // for leaf in &leaves {
    //     let result = core_mmr.append(leaf.to_string()).await;
    //     match result {
    //         Ok(r) => appends_results.push(r),
    //         Err(e) => panic!("Append failed: {}", e),
    //     }
    // }

    // let new_hasher = Box::new(StarkPedersenHasher::new()); // Create a new hasher
    // let mmr = CoreMMR::create_with_genesis(store2_input, new_hasher, None)
    //     .await
    //     .unwrap();

    // // Assert
    // let assert_hasher = Box::new(StarkPedersenHasher::new()); // Create yet another new hasher for the assertion
    // assert_eq!(
    //     mmr.root_hash.get(None).await.unwrap(),
    //     assert_hasher.hash(vec!["1".to_string(), assert_hasher.get_genesis()])
    // );
}

// const leaves = ["1", "2", "3", "4", "5"]; // Elements data for this test suite (do not modify).

// let mmr: CoreMMR;
// let appendsResults: AppendResult[];

// beforeEach(async () => {
//   const store = new MemoryStore();
//   const hasher = new StarkPedersenHasher();

//   mmr = new CoreMMR(store, hasher);
//   appendsResults = [];

//   for (const leaf of leaves) {
//     appendsResults.push(await mmr.append(leaf));
//   }
// });
// //   it("should generate mmr with genesis for keccak hasher", async () => {
//     const hasher = new KeccakHasher();
//     const mmr = await CoreMMR.createWithGenesis(new MemoryStore(), hasher);
//     expect(await mmr.rootHash.get()).toEqual(hasher.hash(["1", hasher.getGenesis()]));
//   });
