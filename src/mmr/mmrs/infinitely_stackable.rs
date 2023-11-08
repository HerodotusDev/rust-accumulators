use std::rc::Rc;

use crate::{
    hasher::Hasher,
    mmr::{helpers::elements_count_to_leaf_count, MMR},
    store::{
        table::{InStoreTable, SubKey, SubMMR},
        Store,
    },
};

pub struct MmrMetadata<H> {
    pub mmr_id: String,
    pub store: Rc<dyn Store>,
    pub hasher: H,
}

/// A tuple of the size at which the MMR is stacked and the MMR itself.
pub type SizesToMMRs<H> = Vec<(usize, MmrMetadata<H>)>;

pub trait InfinitelyStackableMMR<H>
where
    H: Hasher,
{
    fn new_infinitely_stackable(
        store: Rc<dyn Store>,
        hasher: H,
        mmr_id: Option<String>,
        sub_mmrs_metadata: SizesToMMRs<H>,
    ) -> Self;
}

// TODO below
#[allow(unused)]
impl<H> MMR<H>
where
    H: Hasher,
{
    fn get_full_key_and_store(table: &InStoreTable, sub_key: SubKey) -> (Rc<dyn Store>, String) {
        panic!("Not implemented")
    }

    fn get_full_keys_and_stores(
        table: &InStoreTable,
        sub_keys: Vec<SubKey>,
    ) -> Vec<(Rc<dyn Store>, Vec<String>)> {
        panic!("Not implemented")
    }
}

impl<H> InfinitelyStackableMMR<H> for MMR<H>
where
    H: Hasher,
{
    fn new_infinitely_stackable(
        store: Rc<dyn Store>,
        hasher: H,
        mmr_id: Option<String>,
        sub_mmrs_metadata: SizesToMMRs<H>,
    ) -> Self {
        let mut mmr = MMR::new(store, hasher, mmr_id);
        let sub_mmrs_count = sub_mmrs_metadata.len();
        let mut sub_mmrs: Vec<SubMMR> = Vec::with_capacity(sub_mmrs_count);

        for (idx, (size, mmr_metadata)) in sub_mmrs_metadata.into_iter().enumerate() {
            let (_, _, _, hashes_table) =
                MMR::<H>::get_stores(&mmr_metadata.mmr_id, mmr_metadata.store.clone());

            sub_mmrs.push(SubMMR {
                size,
                hashes: hashes_table,
            });

            //? Last sub MMR gets special treatment
            if idx != sub_mmrs_count - 1 {
                continue;
            }

            let elements_count = size;
            let current_elements_count = mmr.elements_count.get();

            //? If the current MMR is already larger than the sub MMR, we don't need to do anything
            if current_elements_count >= elements_count {
                continue;
            }

            let leaves_count = elements_count_to_leaf_count(elements_count)
                .expect("Could not calculate leaves count");

            mmr.elements_count
                .set(elements_count)
                .expect("Could not set elements count");
            mmr.leaves_count
                .set(leaves_count)
                .expect("Could not set leaves count");
        }

        mmr.hashes.get_full_key_and_store = MMR::<H>::get_full_key_and_store;
        mmr.hashes.get_full_keys_and_stores = MMR::<H>::get_full_keys_and_stores;
        mmr.hashes.sub_mmrs = Some(sub_mmrs);

        mmr
    }
}
