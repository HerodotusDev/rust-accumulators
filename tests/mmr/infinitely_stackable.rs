use std::rc::Rc;

use accumulators::{
    hasher::stark_poseidon::StarkPoseidonHasher,
    mmr::{infinitely_stackable::InfinitelyStackableMMR, CoreMMR, MMR},
    store::sqlite::SQLiteStore,
};

#[test]
fn should_append_to_mmr() {
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

    let mut i_s_mmr = MMR::new_infinitely_stackable(
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
