use anyhow::{anyhow, Result};
use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};
use uuid::Uuid;

use crate::{
    formatting::{format_peaks, format_proof, PeaksFormattingOptions},
    hash::IHasher,
    proof::{Proof, ProofOptions},
    store::{counter::InStoreCounter, table::InStoreTable, IStore},
    utils::{
        array_deduplicate, element_index_to_leaf_index, find_peaks, find_siblings, get_peak_info,
        leaf_count_to_append_no_merges, AppendResult, TreeMetadataKeys,
    },
};

pub struct CoreMMR {
    store: Arc<dyn IStore>,
    hasher: Box<dyn IHasher>,
    mmr_id: Option<String>,
    leaves_count: InStoreCounter,
    elements_count: InStoreCounter,
    hashes: InStoreTable,
    pub root_hash: InStoreTable,
}

impl CoreMMR {
    pub fn new(store: Arc<dyn IStore>, hasher: Box<dyn IHasher>, mmr_id: Option<String>) -> Self {
        let mmr_id = mmr_id.unwrap_or_else(|| Uuid::new_v4().to_string());
        let leaves_count_key = format!("{}:{:?}", mmr_id, TreeMetadataKeys::LeafCount);
        let elements_count_key = format!("{}:{:?}", mmr_id, TreeMetadataKeys::ElementCount);
        let root_hash_key = format!("{}:{:?}", mmr_id, TreeMetadataKeys::RootHash);
        let hashes_key = format!("{}:hashes:", mmr_id);

        let leaves_count = InStoreCounter::new(&store, leaves_count_key);
        let elements_count = InStoreCounter::new(&store, elements_count_key);
        let root_hash = InStoreTable::new(&store, root_hash_key);
        let hashes = InStoreTable::new(&store, hashes_key);

        Self {
            leaves_count,
            elements_count,
            hashes,
            root_hash,
            store,
            hasher,
            mmr_id: Some(mmr_id),
        }
    }

    pub async fn create_with_genesis(
        store: Arc<dyn IStore>,
        hasher: Box<dyn IHasher>,
        mmr_id: Option<String>,
    ) -> Result<Self> {
        let mut mmr = CoreMMR::new(store, hasher, mmr_id);
        let elements_count: usize = mmr.elements_count.get().unwrap().parse().unwrap();
        if elements_count != 0 {
            return Err(anyhow!("Cannot call create_with_genesis on a non-empty MMR. Please provide an empty store or change the MMR id.".to_string()));
        }
        mmr.append(mmr.hasher.get_genesis()).await?;
        Ok(mmr)
    }

    pub async fn append(&mut self, value: String) -> Result<AppendResult> {
        if !self.hasher.is_element_size_valid(&value) {
            return Err(anyhow!("Element size is too big to hash with this hasher"));
        }

        let elements_count: usize = self.elements_count.get().unwrap().parse().unwrap();
        let mut peaks = self
            .retrieve_peaks_hashes(find_peaks(elements_count), None)
            .await
            .unwrap();
        let leaf_element_index = self.elements_count.increment().unwrap();

        self.hashes
            .set(&value, Some(leaf_element_index.to_string()));

        peaks.push(value);

        let leaves_count: usize = self.leaves_count.get().unwrap().parse().unwrap();

        let no_merges = leaf_count_to_append_no_merges(leaves_count);

        let mut last_element_idx = leaf_element_index;
        for _ in 0..no_merges {
            last_element_idx += 1;

            let right_hash = peaks.pop().unwrap();
            let left_hash = peaks.pop().unwrap();
            let parent_hash = self.hasher.hash(vec![left_hash, right_hash]);

            self.hashes
                .set(&parent_hash, Some(last_element_idx.to_string()));

            peaks.push(parent_hash);
        }

        self.elements_count.set(last_element_idx);

        let bag = self.bag_the_peaks(None).await;

        // Compute the new root hash
        let root_hash = self
            .calculate_root_hash(&bag.unwrap(), last_element_idx)
            .await
            .unwrap();
        self.root_hash.set(&root_hash, None);

        // Return the new total number of leaves
        let leaves = self.leaves_count.increment().unwrap();

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
        options: ProofOptions,
    ) -> Result<Proof, String> {
        if element_index == 0 {
            return Err("Index must be greater than 0".to_string());
        }

        let element_count = self.elements_count.get().unwrap().parse().unwrap();
        let tree_size = options.elements_count.unwrap_or(element_count);

        if element_index > tree_size {
            return Err("Index must be less or equal to the tree size".to_string());
        }

        let peaks = find_peaks(tree_size);
        let siblings = find_siblings(element_index, tree_size).unwrap();

        let formatting_opts = options
            .formatting_opts
            .as_ref()
            .map(|opts| opts.peaks.clone());
        let peaks_hashes = self.retrieve_peaks_hashes(peaks, formatting_opts).await?;

        let mut siblings_hashes = self.hashes.get_many(siblings).await;
        let mut siblings_hashes_vec: Vec<String> = siblings_hashes.values().cloned().collect();
        if let Some(formatting_opts) = options.formatting_opts.as_ref() {
            siblings_hashes_vec = format_proof(siblings_hashes_vec, formatting_opts.proof.clone())?;
        }

        let element_hash = self
            .hashes
            .get(Some(element_index.to_string()))
            .await
            .unwrap();

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
        elements_ids: Vec<usize>,
        options: ProofOptions,
    ) -> Result<Vec<Proof>, String> {
        let element_count = self.elements_count.get().unwrap().parse().unwrap();
        let tree_size = options.elements_count.unwrap_or(element_count);

        for &element_id in &elements_ids {
            if element_id < 1 {
                return Err("Index must be greater than 1".to_string());
            }
            if element_id > tree_size {
                return Err("Index must be less than the tree size".to_string());
            }
        }

        let peaks = find_peaks(tree_size);
        let mut siblings_per_element = HashMap::new();

        for &element_id in &elements_ids {
            siblings_per_element.insert(element_id, find_siblings(element_id, tree_size).unwrap());
        }

        let peaks_hashes = self.retrieve_peaks_hashes(peaks, None).await?;
        let sibling_hashes_to_get = array_deduplicate(
            siblings_per_element
                .values()
                .flat_map(|x| x.iter().cloned())
                .collect(),
        );

        let all_siblings_hashes = self.hashes.get_many(sibling_hashes_to_get).await;
        let element_hashes = self.hashes.get_many(elements_ids.clone()).await;

        let mut proofs: Vec<Proof> = Vec::new();
        for &element_id in &elements_ids {
            let siblings = siblings_per_element.get(&element_id).unwrap();
            let mut siblings_hashes: Vec<String> = siblings
                .iter()
                .map(|s| all_siblings_hashes.get(s).unwrap().clone())
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
        options: ProofOptions,
    ) -> Result<bool, String> {
        let element_count = self.elements_count.get().unwrap().parse().unwrap();
        let tree_size = options.elements_count.unwrap_or(element_count);

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
        if element_index <= 0 {
            return Err("Index must be greater than 0".to_string());
        }
        if element_index > tree_size {
            return Err("Index must be in the tree".to_string());
        }
        let (peak_index, peak_height) = get_peak_info(tree_size, element_index);
        if proof.siblings_hashes.len() != peak_height {
            return Ok(false);
        }

        let mut hash = element_value.clone();
        let mut leaf_index = element_index_to_leaf_index(element_index)?;

        for proof_hash in proof.siblings_hashes.iter() {
            let is_right = leaf_index % 2 == 1;
            leaf_index /= 2;

            hash = self.hasher.hash(if is_right {
                vec![proof_hash.clone(), hash.clone()]
            } else {
                vec![hash.clone(), proof_hash.clone()]
            });
        }

        let peak_hashes = self
            .retrieve_peaks_hashes(find_peaks(tree_size), None)
            .await?;

        Ok(peak_hashes[peak_index] == hash)
    }

    pub async fn retrieve_peaks_hashes(
        &self,
        peak_idxs: Vec<String>,
        formatting_opts: Option<PeaksFormattingOptions>,
    ) -> Result<Vec<String>, String> {
        let hashes_result = self.hashes.get_many(peak_idxs).await;
        let hashes: Vec<String> = hashes_result.values().cloned().collect();

        match formatting_opts {
            Some(opts) => format_peaks(hashes, &opts),
            None => Ok(hashes),
        }
    }

    pub async fn bag_the_peaks(&self, elements_count: Option<usize>) -> Result<String, String> {
        let element_count = self.elements_count.get().unwrap().parse().unwrap();
        let tree_size = elements_count.unwrap_or_else(|| element_count);
        let peaks_idxs = find_peaks(tree_size);
        let peaks_hashes = self.retrieve_peaks_hashes(peaks_idxs.clone(), None).await?;

        match peaks_idxs.len() {
            // Use original peaks_idxs here
            0 => Ok("0x0".to_string()),
            1 => Ok(peaks_hashes[0].clone()),
            _ => {
                let mut peaks_hashes: VecDeque<String> = peaks_hashes.into();
                let last = peaks_hashes.pop_back().unwrap();
                let second_last = peaks_hashes.pop_back().unwrap();
                let root0 = self.hasher.hash(vec![second_last, last]);

                let root = peaks_hashes
                    .into_iter()
                    .rev()
                    .fold(root0, |prev, cur| self.hasher.hash(vec![cur, prev]));

                Ok(root)
            }
        }
    }

    pub async fn calculate_root_hash(
        &self,
        bag: &str,
        leaf_count: usize,
    ) -> Result<String, String> {
        let leaf_count_str = leaf_count.to_string();
        let hash_result = self.hasher.hash(vec![leaf_count_str, bag.to_string()]);

        Ok(hash_result)
    }
}
