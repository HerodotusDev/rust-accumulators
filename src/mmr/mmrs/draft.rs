use crate::{
    mmr::{MMR, MMRError},
    store::memory::InMemoryStore,
};
use std::{collections::HashMap, sync::Arc};

impl MMR {
    /// Starts an in-memory draft of the MMR.
    ///
    /// Appends made through the returned `DraftMMR` are kept in memory and can
    /// later be committed to the reference MMR's store or discarded.
    ///
    /// # Errors
    ///
    /// Returns an `MMRError` if the current element count cannot be read from
    /// the store or the draft MMR cannot be created.
    pub async fn start_draft(&mut self) -> Result<DraftMMR<'_>, MMRError> {
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

/// An in-memory draft MMR whose changes can be committed to the reference
/// MMR's store or discarded.
pub struct DraftMMR<'a> {
    store: Arc<InMemoryStore>,
    ref_mmr: &'a mut MMR,
    /// The draft MMR to append elements to.
    pub mmr: MMR,
}

impl DraftMMR<'_> {
    /// Discards the draft, dropping all in-memory changes.
    pub fn discard(self) {
        self.store.clear();
    }

    /// Commits the draft's changes to the reference MMR's store.
    ///
    /// # Errors
    ///
    /// Returns an `MMRError` if a draft store key cannot be decoded or the new
    /// values cannot be written to the reference MMR's store.
    pub async fn commit(self) -> Result<(), MMRError> {
        let mut to_set = HashMap::new();
        for (key, value) in self.store.store.read().iter() {
            let (_, key, sub_key) = MMR::decode_store_key(key)?;
            let full_key = MMR::encode_store_key(&self.ref_mmr.mmr_id, key, &sub_key);

            to_set.insert(full_key, value.clone());
        }

        self.ref_mmr.store.set_many(to_set).await?;

        self.store.clear();
        Ok(())
    }
}
