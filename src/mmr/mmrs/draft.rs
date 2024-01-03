use crate::{
    mmr::{MMRError, MMR},
    store::memory::InMemoryStore,
};
use std::{collections::HashMap, sync::Arc};

impl MMR {
    pub async fn start_draft(&mut self) -> Result<DraftMMR, MMRError> {
        let store = InMemoryStore::default();
        let store = Arc::new(store);
        let hasher = self.hasher.clone();

        let mut sub_mmrs = self.sub_mmrs.clone();
        sub_mmrs.push((self.elements_count.get().await?, self.get_metadata()));

        let draft_mmr = MMR::new_stacked(store.clone(), hasher, None, sub_mmrs).await?;

        Ok(DraftMMR {
            store,
            ref_mmr: self,
            mmr: draft_mmr,
        })
    }
}

pub struct DraftMMR<'a> {
    store: Arc<InMemoryStore>,
    ref_mmr: &'a mut MMR,
    pub mmr: MMR,
}

impl DraftMMR<'_> {
    pub fn discard(self) {
        self.store.clear();
    }

    pub async fn commit(self) -> Result<(), MMRError> {
        let mut to_set = HashMap::new();
        for (key, value) in self.store.store.read().iter() {
            let (_, key, sub_key) = MMR::decode_store_key(key)?;
            let full_key = MMR::encode_store_key(&self.ref_mmr.mmr_id, key, sub_key);

            to_set.insert(full_key, value.to_string());
        }

        self.ref_mmr.store.set_many(to_set).await?;

        self.store.clear();
        Ok(())
    }
}
