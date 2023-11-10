use std::rc::Rc;

use uuid::Uuid;

use crate::{
    hasher::Hasher,
    mmr::{MmrMetadata, MMR},
    store::Store,
};

/// A tuple of the size at which the MMR is stacked and the MMR itself.
pub type SizesToMMRs<H> = Vec<(usize, MmrMetadata<H>)>;

impl<H> MMR<H>
where
    H: Hasher + Clone,
{
    pub fn new_draft(store: Rc<dyn Store>, hasher: H, sub_mmrs_metadata: SizesToMMRs<H>) -> Self {
        let mmr_id = format!("draft:{}", Uuid::new_v4());
        let mmr = MMR::new_stacked(store, hasher, Some(mmr_id), sub_mmrs_metadata);

        mmr
    }
}
