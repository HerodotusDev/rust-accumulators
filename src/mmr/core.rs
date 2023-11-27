use anyhow::Result;
use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

use crate::hasher::{Hasher, HashingFunction};
use crate::store::{InStoreCounter, InStoreTable, Store, SubKey};

use crate::mmr::{
    formatting::{format_peaks, format_proof, PeaksFormattingOptions},
    helpers::{
        array_deduplicate, element_index_to_leaf_index, find_peaks, find_siblings, get_peak_info,
        leaf_count_to_append_no_merges, leaf_count_to_peaks_count, mmr_size_to_leaf_count,
        AppendResult, Proof, ProofOptions, TreeMetadataKeys,
    },
};

#[derive(Debug)]
pub struct MMR {
    pub store: Arc<dyn Store>,
    pub hasher: Arc<dyn Hasher>,
    pub mmr_id: String,
    pub leaves_count: InStoreCounter,
    pub elements_count: InStoreCounter,
    pub hashes: InStoreTable,
    pub root_hash: InStoreTable,
    #[cfg(feature = "stacked_mmr")]
    pub sub_mmrs: SizesToMMRs,
}

#[derive(Debug, Clone)]
pub struct MmrMetadata {
    pub mmr_id: String,
    pub store: Arc<dyn Store>,
    pub hasher: HashingFunction,
}

/// A tuple of the size at which the MMR is stacked and the MMR itself.
#[cfg(feature = "stacked_mmr")]
pub type SizesToMMRs = Vec<(usize, MmrMetadata)>;

impl MMR {
    pub fn new(store: Arc<dyn Store>, hasher: Arc<dyn Hasher>, mmr_id: Option<String>) -> Self {
        let mmr_id = mmr_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let (leaves_count, elements_count, root_hash, hashes) =
            MMR::get_stores(&mmr_id, store.clone());

        Self {
            leaves_count,
            elements_count,
            hashes,
            root_hash,
            store,
            hasher,
            mmr_id,
            #[cfg(feature = "stacked_mmr")]
            sub_mmrs: Vec::new(),
        }
    }

    pub async fn create_with_genesis(
        store: Arc<dyn Store>,
        hasher: Arc<dyn Hasher>,
        mmr_id: Option<String>,
    ) -> Result<Self> {
        let mut mmr = MMR::new(store, hasher, mmr_id);
        let elements_count: usize = mmr.elements_count.get().await;
        assert_eq!(elements_count, 0, "Cannot call create_with_genesis on a non-empty MMR. Please provide an empty store or change the MMR id.");
        let genesis = mmr.hasher.get_genesis();
        let _ = mmr.append(genesis).await;
        Ok(mmr)
    }

    pub fn get_metadata(&self) -> MmrMetadata {
        MmrMetadata {
            mmr_id: self.mmr_id.clone(),
            store: self.store.clone(),
            hasher: self.hasher.get_name(),
        }
    }

    pub fn get_store_keys(mmr_id: &str) -> (String, String, String, String) {
        (
            format!("{}:{}", mmr_id, TreeMetadataKeys::LeafCount),
            format!("{}:{}", mmr_id, TreeMetadataKeys::ElementCount),
            format!("{}:{}", mmr_id, TreeMetadataKeys::RootHash),
            format!("{}:{}:", mmr_id, TreeMetadataKeys::Hashes),
        )
    }

    pub fn decode_store_key(store_key: &str) -> Option<(String, TreeMetadataKeys, SubKey)> {
        let mut parts = store_key.split(':');
        let mmr_id = parts.next()?.to_string();
        let key = TreeMetadataKeys::from_str(parts.next()?).expect("Invalid tree metadata key");
        let sub_key = match parts.next() {
            Some(sub_key) => SubKey::String(sub_key.to_string()),
            None => SubKey::None,
        };

        Some((mmr_id, key, sub_key))
    }

    pub fn encode_store_key(mmr_id: &str, key: TreeMetadataKeys, sub_key: SubKey) -> String {
        let store_key = format!("{}:{}", mmr_id, key);
        match sub_key {
            SubKey::None => store_key,
            _ => format!("{}:{}", store_key, sub_key.to_string()),
        }
    }

    pub fn get_stores(
        mmr_id: &str,
        store_rc: Arc<dyn Store>,
    ) -> (InStoreCounter, InStoreCounter, InStoreTable, InStoreTable) {
        let (leaves_count_key, elements_count_key, root_hash_key, hashes_key) =
            MMR::get_store_keys(mmr_id);

        (
            InStoreCounter::new(store_rc.clone(), leaves_count_key),
            InStoreCounter::new(store_rc.clone(), elements_count_key),
            InStoreTable::new(store_rc.clone(), root_hash_key),
            InStoreTable::new(store_rc.clone(), hashes_key),
        )
    }

    pub async fn append(&mut self, value: String) -> Result<AppendResult> {
        assert!(
            self.hasher.is_element_size_valid(&value),
            "Element size is too big to hash with this hasher"
        );

        let elements_count = self.elements_count.get().await;

        let mut peaks = self
            .retrieve_peaks_hashes(find_peaks(elements_count), None)
            .await?;

        let mut last_element_idx = self.elements_count.increment().await?;
        let leaf_element_index = last_element_idx;

        //? Store the hash in the database
        self.hashes
            .set(&value, SubKey::Usize(last_element_idx))
            .await;

        peaks.push(value);

        let no_merges = leaf_count_to_append_no_merges(self.leaves_count.get().await);

        for _ in 0..no_merges {
            last_element_idx += 1;

            let right_hash = peaks.pop().expect("No right hash present");
            let left_hash = peaks.pop().expect("No left hash present");

            let parent_hash = self.hasher.hash(vec![left_hash, right_hash])?;

            self.hashes
                .set(&parent_hash, SubKey::Usize(last_element_idx))
                .await;
            peaks.push(parent_hash);
        }

        self.elements_count.set(last_element_idx).await?;

        let bag = self.bag_the_peaks(None).await?;

        // Compute the new root hash
        let root_hash = self.calculate_root_hash(&bag, last_element_idx)?;
        self.root_hash.set(&root_hash, SubKey::None).await;

        let leaves = self.leaves_count.increment().await?;

        Ok(AppendResult {
            leaves_count: leaves,
            elements_count: last_element_idx,
            element_index: leaf_element_index,
            root_hash,
        })
    }

    pub async fn get_proof(
        &self,
        element_index: usize,
        options: Option<ProofOptions>,
    ) -> Result<Proof> {
        assert_ne!(element_index, 0, "Index must be greater than 0");

        let options = options.unwrap_or_default();
        let element_count = self.elements_count.get().await;
        let tree_size = options.elements_count.unwrap_or(element_count);

        assert!(
            element_index <= tree_size,
            "Index must be less or equal to the tree size"
        );

        let peaks = find_peaks(tree_size);

        let siblings = find_siblings(element_index, tree_size).unwrap();

        let formatting_opts = options
            .formatting_opts
            .as_ref()
            .map(|opts| opts.peaks.clone());
        let peaks_hashes = self
            .retrieve_peaks_hashes(peaks, formatting_opts)
            .await
            .unwrap();

        let siblings_hashes = self
            .hashes
            .get_many(
                siblings
                    .clone()
                    .into_iter()
                    .map(SubKey::Usize)
                    .collect::<Vec<SubKey>>(),
            )
            .await;

        let mut siblings_hashes_vec: Vec<String> = siblings
            .iter()
            .filter_map(|&idx| siblings_hashes.get(&idx.to_string()).cloned())
            .collect();

        if let Some(formatting_opts) = options.formatting_opts.as_ref() {
            siblings_hashes_vec =
                format_proof(siblings_hashes_vec, formatting_opts.proof.clone()).unwrap();
        }

        let element_hash = self.hashes.get(SubKey::Usize(element_index)).await.unwrap();

        Ok(Proof {
            element_index,
            element_hash,
            siblings_hashes: siblings_hashes_vec,
            peaks_hashes,
            elements_count: tree_size,
        })
    }

    pub async fn get_proofs(
        &self,
        elements_indexes: Vec<usize>,
        options: Option<ProofOptions>,
    ) -> Result<Vec<Proof>> {
        let options = options.unwrap_or_default();
        let element_count = self.elements_count.get().await;
        let tree_size = options.elements_count.unwrap_or(element_count);

        for &element_index in &elements_indexes {
            assert_ne!(element_index, 0, "Index must be greater than 0");
            assert!(
                element_index <= tree_size,
                "Index must be less or equal to the tree size"
            )
        }

        let peaks = find_peaks(tree_size);
        let peaks_hashes = self.retrieve_peaks_hashes(peaks, None).await.unwrap();

        let mut siblings_per_element = HashMap::new();
        for &element_id in &elements_indexes {
            siblings_per_element.insert(element_id, find_siblings(element_id, tree_size).unwrap());
        }
        let sibling_hashes_to_get = array_deduplicate(
            siblings_per_element
                .values()
                .flat_map(|x| x.iter().cloned())
                .collect(),
        )
        .into_iter()
        .map(SubKey::Usize)
        .collect();
        let all_siblings_hashes = self.hashes.get_many(sibling_hashes_to_get).await;

        let elements_ids_str: Vec<SubKey> =
            elements_indexes.iter().map(|&x| SubKey::Usize(x)).collect();
        let element_hashes = self.hashes.get_many(elements_ids_str).await;

        let mut proofs: Vec<Proof> = Vec::new();
        for &element_id in &elements_indexes {
            let siblings = siblings_per_element.get(&element_id).unwrap();
            let mut siblings_hashes: Vec<String> = siblings
                .iter()
                .map(|s| all_siblings_hashes.get(&s.to_string()).unwrap().clone()) // Note the conversion here
                .collect();

            if let Some(formatting_opts) = &options.formatting_opts {
                siblings_hashes =
                    format_proof(siblings_hashes, formatting_opts.proof.clone()).unwrap();
            }

            proofs.push(Proof {
                element_index: element_id,
                element_hash: element_hashes.get(&element_id.to_string()).unwrap().clone(),
                siblings_hashes,
                peaks_hashes: peaks_hashes.clone(),
                elements_count: tree_size,
            });
        }

        Ok(proofs)
    }

    pub async fn verify_proof(
        &self,
        mut proof: Proof,
        element_value: String,
        options: Option<ProofOptions>,
    ) -> Result<bool> {
        let options = options.unwrap_or_default();
        let element_count = self.elements_count.get().await;
        let tree_size = options.elements_count.unwrap_or(element_count);

        let leaf_count = mmr_size_to_leaf_count(tree_size);
        let peaks_count = leaf_count_to_peaks_count(leaf_count);

        assert_eq!(
            peaks_count as usize,
            proof.peaks_hashes.len(),
            "Invalid peaks count"
        );

        if let Some(formatting_opts) = options.formatting_opts {
            let proof_format_null_value = &formatting_opts.proof.null_value;
            let peaks_format_null_value = &formatting_opts.peaks.null_value;

            let proof_null_values_count = proof
                .siblings_hashes
                .iter()
                .filter(|&s| s == proof_format_null_value)
                .count();
            proof
                .siblings_hashes
                .truncate(proof.siblings_hashes.len() - proof_null_values_count);

            let peaks_null_values_count = proof
                .peaks_hashes
                .iter()
                .filter(|&s| s == peaks_format_null_value)
                .count();
            proof
                .peaks_hashes
                .truncate(proof.peaks_hashes.len() - peaks_null_values_count);
        }
        let element_index = proof.element_index;

        assert_ne!(element_index, 0, "Index must be greater than 0");
        assert!(element_index <= tree_size, "Index must be in the tree");

        let (peak_index, peak_height) = get_peak_info(tree_size, element_index);
        if proof.siblings_hashes.len() != peak_height {
            return Ok(false);
        }

        let mut hash = element_value.clone();
        let mut leaf_index = element_index_to_leaf_index(element_index)?;

        for proof_hash in proof.siblings_hashes.iter() {
            let is_right = leaf_index % 2 == 1;
            leaf_index /= 2;

            hash = self
                .hasher
                .hash(if is_right {
                    vec![proof_hash.clone(), hash.clone()]
                } else {
                    vec![hash.clone(), proof_hash.clone()]
                })
                .unwrap();
        }

        let peak_hashes = self
            .retrieve_peaks_hashes(find_peaks(tree_size), None)
            .await?;

        Ok(peak_hashes[peak_index] == hash)
    }

    pub async fn retrieve_peaks_hashes(
        &self,
        peak_idxs: Vec<usize>,
        formatting_opts: Option<PeaksFormattingOptions>,
    ) -> Result<Vec<String>> {
        let hashes_result = self
            .hashes
            .get_many(peak_idxs.clone().into_iter().map(SubKey::Usize).collect())
            .await;
        // Assuming hashes_result is a HashMap<String, String>
        let hashes: Vec<String> = peak_idxs
            .iter()
            .filter_map(|&idx| hashes_result.get(&idx.to_string()).cloned())
            .collect();

        match formatting_opts {
            Some(opts) => format_peaks(hashes, &opts),
            None => Ok(hashes),
        }
    }

    pub async fn bag_the_peaks(&self, elements_count: Option<usize>) -> Result<String> {
        let element_count_result = self.elements_count.get().await;
        let tree_size = elements_count.unwrap_or(element_count_result);
        let peaks_idxs = find_peaks(tree_size);

        let peaks_hashes = self
            .retrieve_peaks_hashes(peaks_idxs.clone(), None)
            .await
            .unwrap();

        match peaks_idxs.len() {
            // Use original peaks_idxs here
            0 => Ok("0x0".to_string()),
            1 => Ok(peaks_hashes[0].clone()),
            _ => {
                let mut peaks_hashes: VecDeque<String> = peaks_hashes.into();
                let last = peaks_hashes.pop_back().unwrap();
                let second_last = peaks_hashes.pop_back().unwrap();
                let root0 = self.hasher.hash(vec![second_last, last]);

                peaks_hashes.into_iter().rev().fold(root0, |prev, cur| {
                    self.hasher.hash(vec![cur, prev.unwrap()])
                })
            }
        }
    }

    pub fn calculate_root_hash(&self, bag: &str, elements_count: usize) -> Result<String> {
        self.hasher
            .hash(vec![elements_count.to_string(), bag.to_string()])
    }
}
