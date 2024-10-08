use std::{collections::HashMap, sync::Arc};

use crate::{
    hasher::Hasher,
    mmr::{elements_count_to_leaf_count, MMRError, SizesToMMRs, TreeMetadataKeys, MMR},
    store::{InStoreTable, InStoreTableError, Store, SubKey, SubMMR},
};

type StoreArc = Arc<dyn Store>;
type KeyList = Vec<String>;
type StoreKeysPair = (StoreArc, KeyList);
type StoreKeysList = Vec<StoreKeysPair>;

impl MMR {
    pub async fn new_stacked(
        store: Arc<dyn Store>,
        hasher: Arc<dyn Hasher>,
        mmr_id: Option<String>,
        //? The sizes of the sub MMRs should be the stacks at size, not the actual current size
        sub_mmrs_metadata: SizesToMMRs,
    ) -> Result<Self, MMRError> {
        let mut mmr = MMR::new(store, hasher, mmr_id);
        let sub_mmrs_count = sub_mmrs_metadata.len();
        let mut sub_mmrs: Vec<SubMMR> = Vec::with_capacity(sub_mmrs_count);

        //? size here should be stacks at size
        for (idx, (size, mmr_metadata)) in sub_mmrs_metadata.iter().enumerate() {
            let (_, _, _, hashes_table) =
                MMR::get_stores(&mmr_metadata.mmr_id, mmr_metadata.store.clone());

            sub_mmrs.push(SubMMR {
                size: *size,
                store: mmr_metadata.store.clone(),
                key: hashes_table.key.clone(),
            });

            //? Last sub MMR gets special treatment
            if idx != sub_mmrs_count - 1 {
                continue;
            }

            let elements_count = size;
            let current_elements_count = mmr.elements_count.get().await?;

            //? If the current MMR is already larger than the sub MMR, we don't need to do anything
            if current_elements_count >= *elements_count {
                continue;
            }

            let leaves_count = elements_count_to_leaf_count(*elements_count)?;

            mmr.elements_count.set(*elements_count).await?;
            mmr.leaves_count.set(leaves_count).await?;
        }

        mmr.hashes.get_store_and_full_key = MMR::get_store_and_full_key;
        mmr.hashes.get_stores_and_full_keys = MMR::get_stores_and_full_keys;
        mmr.hashes.sub_mmrs = Some(sub_mmrs);
        mmr.sub_mmrs = sub_mmrs_metadata;

        Ok(mmr)
    }

    pub fn get_store_and_full_key(
        table: &InStoreTable,
        sub_key: SubKey,
    ) -> Result<(StoreArc, String), InStoreTableError> {
        let (_, key, _) = match MMR::decode_store_key(&table.key) {
            Ok((_, key, _)) => (table.store.clone(), key, table.key.clone()),
            Err(_) => return Err(InStoreTableError::CouldNotDecodeStoreKey),
        };

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
            .ok_or(InStoreTableError::SubMMRsNotSet)?
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

        Ok((
            use_mmr.store.clone(),
            InStoreTable::get_full_key(&use_mmr.key, &sub_key.to_string()),
        ))
    }

    pub fn get_stores_and_full_keys(
        table: &InStoreTable,
        sub_keys: Vec<SubKey>,
    ) -> Result<StoreKeysList, InStoreTableError> {
        let (_, key, _) = match MMR::decode_store_key(&table.key) {
            Ok((_, key, _)) => (table.store.clone(), key, table.key.clone()),
            Err(_) => return Err(InStoreTableError::CouldNotDecodeStoreKey),
        };

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

            //? Sort the sub MMRs by size in ascending order
            let mut sub_mmrs = table.sub_mmrs.as_ref().unwrap().clone();
            sub_mmrs.sort_by(|a, b| a.size.cmp(&b.size));

            let mut use_mmr: Option<SubMMR> = None;
            for sub_mmr in sub_mmrs.iter() {
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

        Ok(stores_and_keys
            .into_iter()
            .map(|(_, (sub_mmr, keys))| (sub_mmr.store.clone(), keys))
            .collect())
    }
}
