use std::rc::Rc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher,
    mmr::{helpers::ProofOptions, stacked::StackedMMR, CoreMMR, MMR},
    store::sqlite::SQLiteStore,
};

#[test]
fn should_stack_two_mmrs() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    store.init().expect("Failed to init store");
    let store = Rc::new(store);

    let mut mmr = MMR::new(store.clone(), hasher.clone(), None);

    //? Append element 1
    let append_1 = mmr.append("1".to_string()).unwrap();
    assert_eq!(append_1.leaves_count, 1);
    let bag_1 = mmr.bag_the_peaks(None).unwrap();
    let root_1 = mmr
        .calculate_root_hash(&bag_1, mmr.elements_count.get())
        .expect("Failed to calculate root hash");
    assert_eq!(root_1, append_1.root_hash);

    //? Append element 2
    let append_2 = mmr.append("2".to_string()).unwrap();
    assert_eq!(append_2.leaves_count, 2);
    let bag_2 = mmr.bag_the_peaks(None).unwrap();
    let root_2 = mmr
        .calculate_root_hash(&bag_2, mmr.elements_count.get())
        .expect("Failed to calculate root hash");
    assert_eq!(root_2, append_2.root_hash);

    let mut i_s_mmr = MMR::new_stacked(
        store.clone(),
        hasher.clone(),
        Some("is".to_string()),
        vec![(mmr.elements_count.get(), mmr.get_metadata())],
    );

    let i_s_bag = i_s_mmr.bag_the_peaks(None).unwrap();
    let i_s_root_2 = i_s_mmr
        .calculate_root_hash(&i_s_bag, i_s_mmr.elements_count.get())
        .expect("Failed to calculate root hash");
    assert_eq!(i_s_root_2, root_2);

    //? Append element 3
    let append_3 = mmr.append("3".to_string()).unwrap();
    assert_eq!(append_3.leaves_count, 3);
    let bag_3 = mmr.bag_the_peaks(None).unwrap();
    let root_3 = mmr
        .calculate_root_hash(&bag_3, mmr.elements_count.get())
        .expect("Failed to calculate root hash");

    //? Append element 3 to i_s
    let i_s_append_3 = i_s_mmr.append("3".to_string()).unwrap();
    assert_eq!(i_s_append_3.leaves_count, 3);
    let i_s_bag_3 = i_s_mmr.bag_the_peaks(None).unwrap();
    let i_s_root_3 = i_s_mmr
        .calculate_root_hash(&i_s_bag_3, i_s_mmr.elements_count.get())
        .expect("Failed to calculate root hash");

    assert_eq!(root_3, i_s_root_3);
}

#[test]
fn should_stack_3_mmrs() {
    let store = SQLiteStore::new(":memory:").unwrap();
    let hasher = StarkPoseidonHasher::new(Some(false));
    store.init().expect("Failed to init store");
    let store = Rc::new(store);

    //? First MMR
    let mut mmr_1 = MMR::new(store.clone(), hasher.clone(), None);
    mmr_1.append("1".to_string()).expect("Failed to append");
    mmr_1.append("2".to_string()).expect("Failed to append");

    //? Start gathering sub mmrs
    let mut sub_mmrs = vec![(mmr_1.elements_count.get(), mmr_1.get_metadata())];
    println!(
        "✅ Sub mmrs: {:?}",
        sub_mmrs.iter().map(|(a, _)| a).collect::<Vec<_>>()
    );
    //? Another mmr
    let mut mmr_2 = MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone());
    mmr_2.append("3".to_string()).expect("Failed to append");
    mmr_2.append("4".to_string()).expect("Failed to append");

    //? Add the new sub mmr
    sub_mmrs.push((mmr_2.elements_count.get(), mmr_2.get_metadata()));
    println!(
        "✅ Sub mmrs: {:?}",
        sub_mmrs.iter().map(|(a, _)| a).collect::<Vec<_>>()
    );
    //? Another mmr
    let mut mmr_3 = MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone());
    mmr_3.append("5".to_string()).expect("Failed to append");
    let eg_for_proving_value = "6".to_string();
    let eg_for_proving = mmr_3
        .append(eg_for_proving_value.clone())
        .expect("Failed to append");

    //? Add the new sub mmr
    sub_mmrs.push((mmr_3.elements_count.get(), mmr_3.get_metadata()));
    //? Another mmr
    let mut mmr_4 = MMR::new_stacked(store.clone(), hasher.clone(), None, sub_mmrs.clone());
    mmr_4.append("7".to_string()).expect("Failed to append");
    mmr_4.append("8".to_string()).expect("Failed to append");

    //? All MMRs are now stacked

    assert_eq!(mmr_4.leaves_count.get(), 8);
    let mmr_4_bag = mmr_4.bag_the_peaks(None).unwrap();
    let mmr_4_root = mmr_4
        .calculate_root_hash(&mmr_4_bag, mmr_4.elements_count.get())
        .expect("Failed to calculate root hash");

    let mut ref_mmr = MMR::new(store.clone(), hasher.clone(), None);
    ref_mmr.append("1".to_string()).expect("Failed to append");
    ref_mmr.append("2".to_string()).expect("Failed to append");
    ref_mmr.append("3".to_string()).expect("Failed to append");
    ref_mmr.append("4".to_string()).expect("Failed to append");
    ref_mmr.append("5".to_string()).expect("Failed to append");
    let ref_eg_for_proving = ref_mmr.append("6".to_string()).expect("Failed to append");
    ref_mmr.append("7".to_string()).expect("Failed to append");
    ref_mmr.append("8".to_string()).expect("Failed to append");
    let ref_bag = ref_mmr.bag_the_peaks(None).unwrap();
    let ref_root = ref_mmr
        .calculate_root_hash(&ref_bag, ref_mmr.elements_count.get())
        .expect("Failed to calculate root hash");

    assert_eq!(mmr_4_root, ref_root);

    let proof_options = ProofOptions {
        elements_count: None,
        formatting_opts: None,
    };

    let ref_proof = ref_mmr
        .get_proof(ref_eg_for_proving.element_index, proof_options.clone())
        .expect("Failed to get proof");

    let mmr_4_proof = mmr_4
        .get_proof(eg_for_proving.element_index, proof_options.clone())
        .expect("Failed to get proof");

    assert_eq!(ref_proof, mmr_4_proof);

    assert!(mmr_4
        .verify_proof(mmr_4_proof, eg_for_proving_value, proof_options.clone())
        .unwrap());
}
