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
async fn append_block_range_poseidon_aggregator() {
    use accumulators::{
        hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
    };

    let store = InMemoryStore::new();
    let store = Arc::new(store);
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let mut mmr = MMR::create_with_genesis(store.clone(), hasher.clone(), Some("mmr".to_string()))
        .await
        .unwrap();

    let mut draft = mmr.start_draft().await.unwrap();

    // block 9734438
    draft
        .mmr
        .append("0x07b8996d5b585da92efa32a57223dfb28fa12e6c04d36d7edb03690f03bec56".to_string())
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
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root, "0x1070995027591e1b97c73c0e59933ee1a4227781434dd94b2d4dc87fd94cf92",
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
        3,
        "leaves_count  should be 3"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        4,
        "elements_count  should be 4"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x1a2be63d0560708d3eb87319be0442016ba8757557da8009096e95c4b0682d9"
    );

    // block 9734440
    draft
        .mmr
        .append("0x6f0b4ef760469262221de032372c2a6b47b304a48b632af80611fc2e2e10b56".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        4,
        "leaves_count  should be 4"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        7,
        "elements_count  should be 7"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x1006c333b41230ee484977b481e0e4e530f454a6d14902ce593ed2dbf649a25"
    );

    // block 9734441
    draft
        .mmr
        .append("0x7f6d47c24e8723a6d6cf4ef089df0bd3ec710d5448b696e47b037109a1d04ce".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        5,
        "leaves_count  should be 5"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        8,
        "elements_count  should be 8"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x4f05ebf1a932fdc481d43eb577ad326e5a8c743fbc8624eb98010b65f8c5b89"
    );

    // block 9734442
    draft
        .mmr
        .append("0x38e557fbc306cbcb5964a503014b375db68a0c6786fd9c6ffc5cdd14b6c9dfc".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        6,
        "leaves_count  should be 6"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        10,
        "elements_count  should be 10"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x13bdeaf86b66a03cb316c62d475a7e8d037d30ee7b5d52ff1b13f2fb951b527"
    );

    // block 9734443
    draft
        .mmr
        .append("0x54aa6067e8c4f6bcd7c47cf7900df1d960098177e186f0c15b6a7544491b539".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        7,
        "leaves_count  should be 7"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        11,
        "elements_count  should be 11"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x763a6f33c8cf7b1411cf23910ddba74841dc4b52c73ecfb57ddc40160c78fc6"
    );

    // block 9734444
    draft
        .mmr
        .append("0x2f185aa16419cad043ddb0b75a7ba0c4233d51b7fee31f1ad6680f5c2b53677".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        8,
        "leaves_count  should be 8"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        15,
        "elements_count  should be 15"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x7abaf3802dee5c46f80d30101a3882645070d0968758b2a9b7a3bc5e1a059fa"
    );

    // block 9734445
    draft
        .mmr
        .append("0x3ff20a1d65c24d07ebedb2de39c0a27e67808b49d1544e8ef972da1d24da302".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        9,
        "leaves_count  should be 9"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        16,
        "elements_count  should be 16"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x27f8b7a2ed6d1290833c6fa587d564a8810ee1925b1b2cdfde8da1cefdee57b"
    );

    // block 9734446
    draft
        .mmr
        .append("0x437048beb7e0b3f95fb670e34ac4bd2f32acf6a8ad3eb5fc08682f285ad805b".to_string())
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
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x2c02006787d05a482e0a19771a82c353d65a8eff7e69e1be9ae2219d0400951"
    );

    // block 9734447
    draft
        .mmr
        .append("0x3cd2cd10c8fedcccab3691f9852b25936ef838e0c826e39ecba3354f23664cd".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        11,
        "leaves_count  should be 11"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        19,
        "elements_count  should be 19"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");

    //TODO: onchain root should be 0x06bdd6350f4f5600876f13fb1ee9be09565e37f4ab97971268bc0eb2df5ed6b9
    assert_eq!(
        draft_root,
        "0x2ca29d4ac90ce8715232f2af120c77a4d647771d76e0720afc1fd330aa64577"
    );
}

#[tokio::test]
async fn append_block_range_keccak_aggregator() {
    use accumulators::{mmr::MMR, store::memory::InMemoryStore};

    let store = InMemoryStore::new();
    let store = Arc::new(store);
    let hasher = Arc::new(KeccakHasher::new());

    let mut mmr = MMR::create_with_genesis(store.clone(), hasher.clone(), Some("mmr".to_string()))
        .await
        .unwrap();

    let mut draft = mmr.start_draft().await.unwrap();
    // block 9734438
    draft
        .mmr
        .append("0xcd5631a363d4c9bfc86d3504102595c39d7cd90a940fd165e1bdd911aa504d0a".to_string())
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
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0xffbb02de013f6837d8e0da5f4215c53634c32a4f5eb2520f26a1d6d2f615db72"
    );

    // block 9734439
    draft
        .mmr
        .append("0x62154309a502f33764c4ec3267e2cabf561dc9e428b0607f6f458942bbe0e02d".to_string())
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
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0xaeb642d0f47f806382c66494ccf42c7d37eb3e09ba507a3b842e2a080c745200"
    );

    // block 9734440
    draft
        .mmr
        .append("0x5104aee2cb3cc519cca3580144624c197a0e8b80ef080fe29698221f9963207d".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        4,
        "leaves_count  should be 4"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        7,
        "elements_count  should be 7"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0xdae951c569985cea6033958972846338710ba372aef365053428d1eccfe5e5ce"
    );

    // block 9734441
    draft
        .mmr
        .append("0x09ab9ad1513282a5c1e1b4c15436aee479e9759712ebe6e5dbb02411537633e1".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        5,
        "leaves_count  should be 5"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        8,
        "elements_count  should be 8"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0xd4675f556d04ea6828165e6ad778f3162978588890061692189a55002d93572a"
    );

    // block 9734442
    draft
        .mmr
        .append("0x5cb8bb916e22e6ab4c0fca4bebc13b05dcaaa7eccacd7636b755d944de4e9217".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        6,
        "leaves_count  should be 6"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        10,
        "elements_count  should be 10"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x70c01463d822d2205868c5a46eefc55658828015b83e4553c8462d2c6711d0e0"
    );

    // block 9734443
    draft
        .mmr
        .append("0x0b756461f355b8fb1a6dfdfe5d943f7c037c62b99e806a579500a8a73821e250".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        7,
        "leaves_count  should be 7"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        11,
        "elements_count  should be 11"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x7d0011a4256839263340fb483eb9fe3f6ce8506c9cc39699d8c1a65d8f34257a"
    );

    // block 9734444
    draft
        .mmr
        .append("0x3965b0ccf016b56564129ab0f96400c3a84a8e6fa5d25327a6a1762901ee00e9".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        8,
        "leaves_count  should be 8"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        15,
        "elements_count  should be 15"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x961d2a731654c2d9027c787a9296c66f841d1ee4a13abfdf7a83b70fd7217060"
    );

    // block 9734445
    draft
        .mmr
        .append("0xbe9e359d2632091546be983f8b6488012d607d56c05599c9347fdfdbd86c1b3f".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        9,
        "leaves_count  should be 9"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        16,
        "elements_count  should be 16"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0x4226038dc6fba77fa92ce5d63a49945266065914571c59ef85bdf184eee6dc36"
    );

    // block 9734446
    draft
        .mmr
        .append("0xe9112c401620687b34b0fc6108f35242d32ff37914e302c423e9134851573f65".to_string())
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
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");
    assert_eq!(
        draft_root,
        "0xc5cce3ec5640e0165df5cf8aa5897eb7b9b54b6c4a17d13e0a007b12cfc223cd"
    );

    // block 9734447
    draft
        .mmr
        .append("0xd6b12b6b12b253be08a02293261f71383d6159b6339d6aeab45d91643df19bd0".to_string())
        .await
        .expect("Failed to append");
    assert_eq!(
        draft.mmr.leaves_count.get().await.unwrap(),
        11,
        "leaves_count  should be 11"
    );
    assert_eq!(
        draft.mmr.elements_count.get().await.unwrap(),
        19,
        "elements_count  should be 19"
    );
    let elements_count = draft.mmr.elements_count.get().await.unwrap();
    let draft_bag = draft.mmr.bag_the_peaks(Some(elements_count)).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, elements_count)
        .expect("Failed to calculate root hash");

    //TODO: onchain root should be 0xc87c3ba0942e428ad5432078aa7bb0b9d423616a3a1c8c7fc27b546a81465aaf
    assert_eq!(
        draft_root,
        "0x4654b1a9b7311b0b896ada391a9481db2c0756d9c0f32658facff9eec32cd18b"
    );
}
