use std::{collections::HashMap, rc::Rc};

use crate::{
    hasher::Hasher,
    mmr::{elements_count_to_leaf_count, SizesToMMRs, TreeMetadataKeys, MMR},
    store::{InStoreTable, Store, SubKey, SubMMR},
};

impl<H> MMR<H>
where
    H: Hasher + Clone,
{
    pub async fn new_stacked(
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
                store: mmr_metadata.store.clone(),
                key: hashes_table.key.clone(),
            });

            //? Last sub MMR gets special treatment
            if idx != sub_mmrs_count - 1 {
                continue;
            }

            let elements_count = size;
            let current_elements_count = mmr.elements_count.get().await;

            //? If the current MMR is already larger than the sub MMR, we don't need to do anything
            if current_elements_count >= elements_count {
                continue;
            }

            let leaves_count = elements_count_to_leaf_count(elements_count)
                .expect("Could not calculate leaves count");

            mmr.elements_count
                .set(elements_count)
                .await
                .expect("Could not set elements count");
            mmr.leaves_count
                .set(leaves_count)
                .await
                .expect("Could not set leaves count");
        }

        mmr.hashes.get_store_and_full_key = MMR::<H>::get_store_and_full_key;
        mmr.hashes.get_stores_and_full_keys = MMR::<H>::get_stores_and_full_keys;
        mmr.hashes.sub_mmrs = Some(sub_mmrs);

        mmr
    }

    pub fn get_store_and_full_key(
        table: &InStoreTable,
        sub_key: SubKey,
    ) -> (Rc<dyn Store>, String) {
        let (_, key, _) =
            MMR::<H>::decode_store_key(&table.key).expect("Could not decode store key");

        match key {
            TreeMetadataKeys::Hashes => {}
            //? If the key is not hashes, we don't need to do anything
            _ => return table.default_get_store_and_full_key(sub_key),
        }

        let element_index = match sub_key {
            SubKey::Usize(element_index) => element_index,
            //? If the sub_key is not an element index, we don't need to do anything
            _ => return table.default_get_store_and_full_key(sub_key),
        };

        let sub_mmrs = table
            .sub_mmrs
            .as_ref()
            .expect("Sub MMRs are not set")
            .iter();

        let this_mmr = SubMMR {
            size: usize::MAX,
            store: table.store.clone(),
            key: table.key.clone(),
        };
        let mut use_mmr = None;

        for sub_mmr in sub_mmrs {
            if element_index <= sub_mmr.size {
                use_mmr = Some(sub_mmr.clone());
                break;
            }
        }

        let use_mmr = use_mmr.unwrap_or(this_mmr.clone());

        (
            use_mmr.store.clone(),
            InStoreTable::get_full_key(&use_mmr.key, &sub_key.to_string()),
        )
    }

    pub fn get_stores_and_full_keys(
        table: &InStoreTable,
        sub_keys: Vec<SubKey>,
    ) -> Vec<(Rc<dyn Store>, Vec<String>)> {
        let (_, key, _) =
            MMR::<H>::decode_store_key(&table.key).expect("Could not decode store key");

        match key {
            TreeMetadataKeys::Hashes => {}
            //? If the key is not hashes, we don't need to do anything
            _ => return table.default_get_stores_and_full_keys(sub_keys),
        }

        let this_mmr = SubMMR {
            size: usize::MAX,
            key: table.key.clone(),
            store: table.store.clone(),
        };

        let mut stores_and_keys: HashMap<usize, (SubMMR, Vec<String>)> = HashMap::new();
        for sub_key in sub_keys.iter() {
            let element_index = match sub_key {
                SubKey::Usize(element_index) => element_index,
                //? If the sub_key is not an element index, we don't need to do anything
                _ => return table.default_get_stores_and_full_keys(sub_keys),
            };

            let mut use_mmr: Option<SubMMR> = None;
            for sub_mmr in table.sub_mmrs.as_ref().unwrap().iter() {
                if *element_index <= sub_mmr.size {
                    use_mmr = Some(sub_mmr.clone());
                    break;
                }
            }

            let use_mmr = use_mmr.unwrap_or(this_mmr.clone());
            let full_key = InStoreTable::get_full_key(&use_mmr.key, &sub_key.to_string());

            stores_and_keys
                .entry(use_mmr.size)
                .and_modify(|(_, keys)| keys.push(full_key.clone()))
                .or_insert((use_mmr, vec![full_key]));
        }

        stores_and_keys
            .into_iter()
            .map(|(_, (sub_mmr, keys))| (sub_mmr.store.clone(), keys))
            .collect()
    }
}
