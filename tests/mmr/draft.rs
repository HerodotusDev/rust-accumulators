use std::sync::Arc;

use accumulators::{
    hasher::{keccak::KeccakHasher, stark_poseidon::StarkPoseidonHasher},
    mmr::MMR,
    store::memory::InMemoryStore,
};

#[tokio::test]
async fn should_discard_properly() {
    let store = InMemoryStore::default();
    let store = Arc::new(store);
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let mut ref_mmr = MMR::new(store.clone(), hasher.clone(), None);
    ref_mmr
        .append("1".to_string())
        .await
        .expect("Failed to append");
    ref_mmr
        .append("2".to_string())
        .await
        .expect("Failed to append");
    ref_mmr
        .append("3".to_string())
        .await
        .expect("Failed to append");
    ref_mmr
        .append("4".to_string())
        .await
        .expect("Failed to append");
    ref_mmr
        .append("5".to_string())
        .await
        .expect("Failed to append");
    let _ref_eg_for_proving = ref_mmr
        .append("6".to_string())
        .await
        .expect("Failed to append");
    ref_mmr
        .append("7".to_string())
        .await
        .expect("Failed to append");
    ref_mmr
        .append("8".to_string())
        .await
        .expect("Failed to append");
    let ref_bag = ref_mmr.bag_the_peaks(None).await.unwrap();
    let ref_root = ref_mmr
        .calculate_root_hash(&ref_bag, ref_mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

    let mut draft = ref_mmr.start_draft().await.unwrap();
    draft
        .mmr
        .append("9".to_string())
        .await
        .expect("Failed to append");
    let draft_bag = draft.mmr.bag_the_peaks(None).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    draft.discard();

    let ref_after_bag = ref_mmr.bag_the_peaks(None).await.unwrap();
    let ref_after_root = ref_mmr
        .calculate_root_hash(&ref_after_bag, ref_mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    assert_eq!(ref_root, ref_after_root);

    ref_mmr
        .append("9".to_string())
        .await
        .expect("Failed to append");
    let ref_after_bag = ref_mmr.bag_the_peaks(None).await.unwrap();
    let ref_after_root = ref_mmr
        .calculate_root_hash(&ref_after_bag, ref_mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    assert_eq!(draft_root, ref_after_root);
}

#[tokio::test]
async fn should_apply() {
    let store = InMemoryStore::default();
    let store = Arc::new(store);
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);
    mmr.append("1".to_string()).await.expect("Failed to append");
    mmr.append("2".to_string()).await.expect("Failed to append");
    mmr.append("3".to_string()).await.expect("Failed to append");
    mmr.append("4".to_string()).await.expect("Failed to append");
    mmr.append("5".to_string()).await.expect("Failed to append");
    mmr.append("6".to_string()).await.expect("Failed to append");
    mmr.append("7".to_string()).await.expect("Failed to append");
    mmr.append("8".to_string()).await.expect("Failed to append");

    let mut draft = mmr.start_draft().await.unwrap();
    let eg_value = "9".to_string();
    let eg_append = draft
        .mmr
        .append(eg_value.clone())
        .await
        .expect("Failed to append");
    let draft_bag = draft.mmr.bag_the_peaks(None).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    draft.commit().await.unwrap();

    let bag = mmr.bag_the_peaks(None).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    assert_eq!(draft_root, root);

    mmr.append("10".to_string())
        .await
        .expect("Failed to append");

    let proof = mmr
        .get_proof(eg_append.element_index, None)
        .await
        .expect("Failed to get proof");
    assert!(mmr
        .verify_proof(proof, eg_value, None)
        .await
        .expect("Failed to verify proof"));
}

#[tokio::test]
async fn example() {
    use accumulators::{
        hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
    };

    let store = InMemoryStore::new();
    let store = Arc::new(store);
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    mmr.append("1".to_string()).await.expect("Failed to append");
    mmr.append("2".to_string()).await.expect("Failed to append");

    let mut draft = mmr.start_draft().await.unwrap();
    draft
        .mmr
        .append("3".to_string())
        .await
        .expect("Failed to append");
    draft
        .mmr
        .append("4".to_string())
        .await
        .expect("Failed to append");

    let draft_bag = draft.mmr.bag_the_peaks(None).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

    draft.commit().await.unwrap();

    let bag = mmr.bag_the_peaks(None).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

    assert_eq!(draft_root, root);

    let mut draft = mmr.start_draft().await.unwrap();
    draft
        .mmr
        .append("5".to_string())
        .await
        .expect("Failed to append");
    draft
        .mmr
        .append("6".to_string())
        .await
        .expect("Failed to append");

    draft.discard();

    let after_discard_bag = mmr.bag_the_peaks(None).await.unwrap();
    let after_discard_root = mmr
        .calculate_root_hash(&after_discard_bag, mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

    assert_eq!(after_discard_root, root);
}

#[tokio::test]
async fn append_block_range_poseidon() {
    use accumulators::{
        hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
    };

    let store = InMemoryStore::new();
    let store = Arc::new(store);
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    let mut draft = mmr.start_draft().await.unwrap();
    // block 9734438
    draft
        .mmr
        .append("0x07b8996d5b585da92efa32a57223dfb28fa12e6c04d36d7edb03690f03bec56".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        1,
        "leaves_count  should be 1"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        1,
        "elements_count  should be 1"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root, "0x6a276abac77c58ddc28e87135620a45b6d06ea5de494ed9eabd0699ac12392a",
        "draft_root "
    );
    // block 9734439
    draft
        .mmr
        .append("0x312134454804550b4a38e1d60dc1f0be80ff62dfea8f3c6be0c257efce3b833".to_string())
        .await
        .expect("Failed to append");

    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        2,
        "leaves_count  should be 2"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        3,
        "elements_count  should be 3"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root, "0xbb04c027ae6df73a33010d9b29237d3535994599801265cafc51e42dca9570",
        "draft_root "
    );
    // block 9734440
    draft
        .mmr
        .append("0x6f0b4ef760469262221de032372c2a6b47b304a48b632af80611fc2e2e10b56".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        3,
        "leaves_count  should be 3"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        4,
        "elements_count  should be 4"
    );
    // block 9734441
    draft
        .mmr
        .append("0x7f6d47c24e8723a6d6cf4ef089df0bd3ec710d5448b696e47b037109a1d04ce".to_string())
        .await
        .expect("Failed to append");

    // block 9734442
    draft
        .mmr
        .append("0x38e557fbc306cbcb5964a503014b375db68a0c6786fd9c6ffc5cdd14b6c9dfc".to_string())
        .await
        .expect("Failed to append");
    // block 9734443
    draft
        .mmr
        .append("0x54aa6067e8c4f6bcd7c47cf7900df1d960098177e186f0c15b6a7544491b539".to_string())
        .await
        .expect("Failed to append");
    // block 9734444
    draft
        .mmr
        .append("0x2f185aa16419cad043ddb0b75a7ba0c4233d51b7fee31f1ad6680f5c2b53677".to_string())
        .await
        .expect("Failed to append");
    // block 9734445
    draft
        .mmr
        .append("0x3ff20a1d65c24d07ebedb2de39c0a27e67808b49d1544e8ef972da1d24da302".to_string())
        .await
        .expect("Failed to append");
    // block 9734446
    draft
        .mmr
        .append("0x437048beb7e0b3f95fb670e34ac4bd2f32acf6a8ad3eb5fc08682f285ad805b".to_string())
        .await
        .expect("Failed to append");
    // block 9734447
    draft
        .mmr
        .append("0x3cd2cd10c8fedcccab3691f9852b25936ef838e0c826e39ecba3354f23664cd".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        10,
        "leaves_count  should be 10"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        18,
        "elements_count  should be 18"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

    //TODO: onchain root should be 0x06bdd6350f4f5600876f13fb1ee9be09565e37f4ab97971268bc0eb2df5ed6b9
    assert_eq!(
        draft_root,
        "0x60cd9ba780f766b4292bfad77c2b98258da56c0a333707a5f9c9041af027434"
    );
}

#[tokio::test]
async fn append_block_range_keccak() {
    use accumulators::{mmr::MMR, store::memory::InMemoryStore};

    let store = InMemoryStore::new();
    let store = Arc::new(store);
    let hasher = Arc::new(KeccakHasher::new());

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    let mut draft = mmr.start_draft().await.unwrap();
    // block 9734438
    draft
        .mmr
        .append("0xcd5631a363d4c9bfc86d3504102595c39d7cd90a940fd165e1bdd911aa504d0a".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        1,
        "leaves_count  should be 1"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        1,
        "elements_count  should be 1"
    );

    // block 9734439
    draft
        .mmr
        .append("0x62154309a502f33764c4ec3267e2cabf561dc9e428b0607f6f458942bbe0e02d".to_string())
        .await
        .expect("Failed to append");

    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        2,
        "leaves_count  should be 2"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        3,
        "elements_count  should be 3"
    );

    // block 9734440
    draft
        .mmr
        .append("0x5104aee2cb3cc519cca3580144624c197a0e8b80ef080fe29698221f9963207d".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        3,
        "leaves_count  should be 3"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        4,
        "elements_count  should be 4"
    );
    // block 9734441
    draft
        .mmr
        .append("0x09ab9ad1513282a5c1e1b4c15436aee479e9759712ebe6e5dbb02411537633e1".to_string())
        .await
        .expect("Failed to append");

    // block 9734442
    draft
        .mmr
        .append("0x5cb8bb916e22e6ab4c0fca4bebc13b05dcaaa7eccacd7636b755d944de4e9217".to_string())
        .await
        .expect("Failed to append");
    // block 9734443
    draft
        .mmr
        .append("0x0b756461f355b8fb1a6dfdfe5d943f7c037c62b99e806a579500a8a73821e250".to_string())
        .await
        .expect("Failed to append");
    // block 9734444
    draft
        .mmr
        .append("0x3965b0ccf016b56564129ab0f96400c3a84a8e6fa5d25327a6a1762901ee00e9".to_string())
        .await
        .expect("Failed to append");
    // block 9734445
    draft
        .mmr
        .append("0xbe9e359d2632091546be983f8b6488012d607d56c05599c9347fdfdbd86c1b3f".to_string())
        .await
        .expect("Failed to append");
    // block 9734446
    draft
        .mmr
        .append("0xe9112c401620687b34b0fc6108f35242d32ff37914e302c423e9134851573f65".to_string())
        .await
        .expect("Failed to append");
    // block 9734447
    draft
        .mmr
        .append("0xd6b12b6b12b253be08a02293261f71383d6159b6339d6aeab45d91643df19bd0".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        10,
        "leaves_count  should be 10"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        18,
        "elements_count  should be 18"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

    //TODO: onchain root should be 0xc87c3ba0942e428ad5432078aa7bb0b9d423616a3a1c8c7fc27b546a81465aaf
    assert_eq!(
        draft_root,
        "0xfa6b3a43dda261466fe3197ade3d0585f612b9b958d2edc7481c9a257265bb99"
    );
}
