use std::rc::Rc;

use uuid::Uuid;

use crate::{
    hasher::Hasher,
    store::{table::InStoreTable, Store},
};

#[derive(Debug)]
pub enum TreeMetadataKeys {
    RootHash,
}

pub struct IncrementalMerkleTree<S, H> {
    pub store: Rc<S>,
    pub mmr_id: String,
    pub nodes: InStoreTable<S>,
    pub root_hash: InStoreTable<S>,
    pub hasher: H,
    pub size: usize,
    pub null_value: String,
}

impl<S, H> IncrementalMerkleTree<S, H>
where
    S: Store,
    H: Hasher,
{
    pub fn initialize(
        size: usize,
        null_value: String,
        hasher: H,
        store: S,
        mmr_id: Option<String>,
    ) -> Self {
        let mmr_id = mmr_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let root_hash_key = format!("{}:{:?}", mmr_id, TreeMetadataKeys::RootHash);
        let nodes_key = format!("{}:nodes:", mmr_id);

        let store_rc = Rc::new(store);
        let root_hash = InStoreTable::new(store_rc.clone(), root_hash_key);
        let nodes = InStoreTable::new(store_rc.clone(), nodes_key);

        Self {
            store: store_rc,
            mmr_id,
            nodes,
            root_hash,
            hasher,
            size,
            null_value,
        }
    }
}
