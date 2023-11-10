use std::rc::Rc;

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

// TODO finish below
#[allow(dead_code)]
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

    // TODO - implement this
    pub fn commit(self) {
        panic!("Not implemented")
    }
}
