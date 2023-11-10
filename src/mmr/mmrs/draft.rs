use std::{collections::HashMap, rc::Rc};

use crate::{
    hasher::Hasher,
    mmr::{MmrMetadata, MMR},
    store::memory::InMemoryStore,
};

/// A tuple of the size at which the MMR is stacked and the MMR itself.
pub type SizesToMMRs<H> = Vec<(usize, MmrMetadata<H>)>;

impl<H> MMR<H>
where
    H: Hasher + Clone,
{
    pub fn start_draft(&mut self) -> DraftMMR<H> {
        let store = InMemoryStore::default();
        let store = Rc::new(store);
        let hasher = self.hasher.clone();

        let mut sub_mmrs = self.sub_mmrs.clone();
        sub_mmrs.push((self.elements_count.get(), self.get_metadata()));

        let draft_mmr = MMR::new_stacked(store.clone(), hasher, None, sub_mmrs);

        DraftMMR {
            store,
            ref_mmr: self,
            mmr: draft_mmr,
        }
    }
}

pub struct DraftMMR<'a, H>
where
    H: Hasher,
{
    store: Rc<InMemoryStore>,
    ref_mmr: &'a mut MMR<H>,
    pub mmr: MMR<H>,
}

impl<H> DraftMMR<'_, H>
where
    H: Hasher + Clone,
{
    pub fn discard(self) {
        self.store.clear();
    }

    pub fn commit(self) {
        let mut to_set = HashMap::new();
        for (key, value) in self.store.store.read().iter() {
            let (_, key, sub_key) =
                MMR::<H>::decode_store_key(key).expect("Could not decode store key");
            let full_key = MMR::<H>::encode_store_key(&self.ref_mmr.mmr_id, key, sub_key);

            to_set.insert(full_key, value.to_string());
        }

        self.ref_mmr
            .store
            .set_many(to_set)
            .expect("Could not apply draft to MMR");

        self.store.clear();
    }
}
