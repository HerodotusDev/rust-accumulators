use std::sync::Arc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::sqlite::SQLiteStore,
};

#[tokio::test]
async fn should_stack_two_mmrs() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = Arc::new(store);

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    //? Append element 1
    let append_1 = mmr.append("1".to_string()).await.unwrap();
    assert_eq!(append_1.leaves_count, 1);
    let bag_1 = mmr.bag_the_peaks(None).await.unwrap();
    let root_1 = mmr
        .calculate_root_hash(&bag_1, mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    assert_eq!(root_1, append_1.root_hash);

    //? Append element 2
    let append_2 = mmr.append("2".to_string()).await.unwrap();
    assert_eq!(append_2.leaves_count, 2);
    let bag_2 = mmr.bag_the_peaks(None).await.unwrap();
    let root_2 = mmr
        .calculate_root_hash(&bag_2, mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    assert_eq!(root_2, append_2.root_hash);

    let mut i_s_mmr = MMR::new_stacked(
        store.clone(),
        hasher.clone(),
        Some("is".to_string()),
        vec![(mmr.elements_count.get().await.unwrap(), mmr.get_metadata())],
    )
    .await
    .unwrap();

    let i_s_bag = i_s_mmr.bag_the_peaks(None).await.unwrap();
    let i_s_root_2 = i_s_mmr
        .calculate_root_hash(&i_s_bag, i_s_mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");
    assert_eq!(i_s_root_2, root_2);

    //? Append element 3
    let append_3 = mmr.append("3".to_string()).await.unwrap();
    assert_eq!(append_3.leaves_count, 3);
    let bag_3 = mmr.bag_the_peaks(None).await.unwrap();
    let root_3 = mmr
        .calculate_root_hash(&bag_3, mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

    //? Append element 3 to i_s
    let i_s_append_3 = i_s_mmr.append("3".to_string()).await.unwrap();
    assert_eq!(i_s_append_3.leaves_count, 3);
    let i_s_bag_3 = i_s_mmr.bag_the_peaks(None).await.unwrap();
    let i_s_root_3 = i_s_mmr
        .calculate_root_hash(&i_s_bag_3, i_s_mmr.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

    assert_eq!(root_3, i_s_root_3);
}

#[tokio::test]
async fn should_stack_4_mmrs() {
    let store = SQLiteStore::new(":memory:", None).await.unwrap();
    let hasher = Arc::new(StarkPoseidonHasher::new(Some(false)));

    let store = Arc::new(store);

    //? First MMR
    let mut mmr_1 = MMR::new(store.clone(), hasher.clone(), None);
    mmr_1
        .append("1".to_string())
        .await
        .expect("Failed to append");
    mmr_1
        .append("2".to_string())
        .await
        .expect("Failed to append");

    //? Start gathering sub mmrs
    let mut sub_mmrs = vec![(
        mmr_1.elements_count.get().await.unwrap(),
        mmr_1.get_metadata(),
    )];

    //? Another mmr
    let mut mmr_2 = MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone())
        .await
        .unwrap();
    mmr_2
        .append("3".to_string())
        .await
        .expect("Failed to append");
    mmr_2
        .append("4".to_string())
        .await
        .expect("Failed to append");

    //? Add the new sub mmr
    sub_mmrs.push((
        mmr_2.elements_count.get().await.unwrap(),
        mmr_2.get_metadata(),
    ));

    //? Another mmr
    let mut mmr_3 = MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone())
        .await
        .unwrap();
    mmr_3
        .append("5".to_string())
        .await
        .expect("Failed to append");
    let eg_for_proving_value = "6".to_string();
    let eg_for_proving = mmr_3
        .append(eg_for_proving_value.clone())
        .await
        .expect("Failed to append");

    //? Add the new sub mmr
    sub_mmrs.push((
        mmr_3.elements_count.get().await.unwrap(),
        mmr_3.get_metadata(),
    ));
    //? Another mmr
    let mut mmr_4 = MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone())
        .await
        .unwrap();
    mmr_4
        .append("7".to_string())
        .await
        .expect("Failed to append");
    mmr_4
        .append("8".to_string())
        .await
        .expect("Failed to append");

    //? All MMRs are now stacked

    assert_eq!(mmr_4.leaves_count.get().await.unwrap(), 8);
    let mmr_4_bag = mmr_4.bag_the_peaks(None).await.unwrap();
    let mmr_4_root = mmr_4
        .calculate_root_hash(&mmr_4_bag, mmr_4.elements_count.get().await.unwrap())
        .expect("Failed to calculate root hash");

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
    let ref_eg_for_proving = ref_mmr
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

    assert_eq!(mmr_4_root, ref_root);

    let ref_proof = ref_mmr
        .get_proof(ref_eg_for_proving.element_index, None)
        .await
        .expect("Failed to get proof");

    let mmr_4_proof = mmr_4
        .get_proof(eg_for_proving.element_index, None)
        .await
        .expect("Failed to get proof");

    assert_eq!(ref_proof, mmr_4_proof);

    assert!(mmr_4
        .verify_proof(mmr_4_proof, eg_for_proving_value, None)
        .await
        .unwrap());
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

    let example_value = "1".to_string();
    let example_append = mmr
        .append(example_value.clone())
        .await
        .expect("Failed to append");

    let sub_mmrs = vec![(mmr.elements_count.get().await.unwrap(), mmr.get_metadata())];

    let mut stacked_mmr = MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone())
        .await
        .unwrap();
    stacked_mmr
        .append("2".to_string())
        .await
        .expect("Failed to append");

    let proof = stacked_mmr
        .get_proof(example_append.element_index, None)
        .await
        .expect("Failed to get proof");

    assert!(stacked_mmr
        .verify_proof(proof, example_value, None)
        .await
        .unwrap());
}
