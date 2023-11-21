use std::rc::Rc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher, mmr::MMR, store::memory::InMemoryStore,
};

#[tokio::test]
async fn should_discard_properly() {
    let store = InMemoryStore::default();
    let store = Rc::new(store);
    let hasher = StarkPoseidonHasher::new(Some(false));

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
        .calculate_root_hash(&ref_bag, ref_mmr.elements_count.get().await)
        .expect("Failed to calculate root hash");

    let mut draft = ref_mmr.start_draft().await;
    draft
        .mmr
        .append("9".to_string())
        .await
        .expect("Failed to append");
    let draft_bag = draft.mmr.bag_the_peaks(None).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await)
        .expect("Failed to calculate root hash");
    draft.discard().await;

    let ref_after_bag = ref_mmr.bag_the_peaks(None).await.unwrap();
    let ref_after_root = ref_mmr
        .calculate_root_hash(&ref_after_bag, ref_mmr.elements_count.get().await)
        .expect("Failed to calculate root hash");
    assert_eq!(ref_root, ref_after_root);

    ref_mmr
        .append("9".to_string())
        .await
        .expect("Failed to append");
    let ref_after_bag = ref_mmr.bag_the_peaks(None).await.unwrap();
    let ref_after_root = ref_mmr
        .calculate_root_hash(&ref_after_bag, ref_mmr.elements_count.get().await)
        .expect("Failed to calculate root hash");
    assert_eq!(draft_root, ref_after_root);
}

#[tokio::test]
async fn should_apply() {
    let store = InMemoryStore::default();
    let store = Rc::new(store);
    let hasher = StarkPoseidonHasher::new(Some(false));

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);
    mmr.append("1".to_string()).await.expect("Failed to append");
    mmr.append("2".to_string()).await.expect("Failed to append");
    mmr.append("3".to_string()).await.expect("Failed to append");
    mmr.append("4".to_string()).await.expect("Failed to append");
    mmr.append("5".to_string()).await.expect("Failed to append");
    mmr.append("6".to_string()).await.expect("Failed to append");
    mmr.append("7".to_string()).await.expect("Failed to append");
    mmr.append("8".to_string()).await.expect("Failed to append");

    let mut draft = mmr.start_draft().await;
    let eg_value = "9".to_string();
    let eg_append = draft
        .mmr
        .append(eg_value.clone())
        .await
        .expect("Failed to append");
    let draft_bag = draft.mmr.bag_the_peaks(None).await.unwrap();
    let draft_root = draft
        .mmr
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await)
        .expect("Failed to calculate root hash");
    draft.commit().await;

    let bag = mmr.bag_the_peaks(None).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, mmr.elements_count.get().await)
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
    let store = Rc::new(store);
    let hasher = StarkPoseidonHasher::new(Some(false));

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    mmr.append("1".to_string()).await.expect("Failed to append");
    mmr.append("2".to_string()).await.expect("Failed to append");

    let mut draft = mmr.start_draft().await;
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
        .calculate_root_hash(&draft_bag, draft.mmr.elements_count.get().await)
        .expect("Failed to calculate root hash");

    draft.commit().await;

    let bag = mmr.bag_the_peaks(None).await.unwrap();
    let root = mmr
        .calculate_root_hash(&bag, mmr.elements_count.get().await)
        .expect("Failed to calculate root hash");

    assert_eq!(draft_root, root);

    let mut draft = mmr.start_draft().await;
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

    draft.discard().await;

    let after_discard_bag = mmr.bag_the_peaks(None).await.unwrap();
    let after_discard_root = mmr
        .calculate_root_hash(&after_discard_bag, mmr.elements_count.get().await)
        .expect("Failed to calculate root hash");

    assert_eq!(after_discard_root, root);
}
