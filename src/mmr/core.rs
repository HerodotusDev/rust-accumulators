use std::collections::{HashMap, VecDeque};
use std::str::FromStr;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

use crate::hasher::{Hasher, HasherError, HashingFunction};
use crate::store::{InStoreCounter, InStoreTable, InStoreTableError, Store, StoreError, SubKey};

use crate::mmr::{
    formatting::{PeaksFormattingOptions, format_peaks, format_proof},
    helpers::{
        AppendResult, Proof, ProofOptions, TreeMetadataKeys, array_deduplicate,
        element_index_to_leaf_index, find_peaks, find_siblings, get_peak_info,
        leaf_count_to_append_no_merges, leaf_count_to_peaks_count, mmr_size_to_leaf_count,
    },
};

use super::{FormattingError, PeaksOptions, TreeMetadataKeysError};

/// An error that can occur when using an MMR
#[derive(Error, Debug)]
pub enum MMRError {
    /// An error propagated from the underlying key-value store.
    #[error("Store error: {0}")]
    Store(#[from] StoreError),
    /// An error propagated from the hasher implementation.
    #[error("Hasher error: {0}")]
    Hasher(#[from] HasherError),
    /// The store already holds data for the given MMR id, and the operation
    /// requires an empty one.
    #[error("Cannot do with non-empty MMR. Please provide an empty store or change the MMR id.")]
    NonEmptyMMR,
    /// The element count does not describe a valid MMR size.
    #[error("Invalid element count")]
    InvalidElementCount,
    /// The element index is zero or greater than the number of elements in the MMR.
    #[error("Invalid element index")]
    InvalidElementIndex,
    /// The number of peaks in the proof does not match the expected peak count
    /// for the MMR size the proof is verified against.
    #[error("Invalid peaks count")]
    InvalidPeaksCount,
    /// An error propagated from an `InStoreTable` operation.
    #[error("InStoreTable error: {0}")]
    InStoreTable(#[from] InStoreTableError),
    /// A store key could not be decoded into tree metadata.
    #[error("TreeMetadataKeys error: {0}")]
    TreeMetadataKeys(#[from] TreeMetadataKeysError),
    /// An error occurred while formatting peak or proof hashes.
    #[error("Formatting error: {0}")]
    Formatting(#[from] FormattingError),
    /// No hash is stored in the MMR under the given element index.
    #[error("No hash found for index {0}")]
    NoHashFoundForIndex(usize),
    /// The provided peaks do not match the provided element count.
    #[error("Invalid peaks count for the given element count")]
    InvalidPeaksCountForElements,
}

/// A Merkle Mountain Range (MMR) backed by a key-value store.
///
/// The MMR persists its hashes and metadata in the store under keys derived
/// from `mmr_id`, so multiple independent MMRs can share a single store.
#[derive(Debug)]
pub struct MMR {
    /// The store used to persist the MMR's data.
    pub store: Arc<dyn Store>,
    /// The hasher used to hash elements and merge peaks.
    pub hasher: Arc<dyn Hasher>,
    /// The unique id under which the MMR's data is stored.
    pub mmr_id: String,
    /// Counter holding the number of leaves currently in the MMR.
    pub leaves_count: InStoreCounter,
    /// Counter holding the total number of nodes currently in the MMR.
    pub elements_count: InStoreCounter,
    /// Table mapping element indices to their hashes.
    pub hashes: InStoreTable,
    /// Table holding the MMR's current root hash.
    pub root_hash: InStoreTable,
    /// Metadata of the sub MMRs this MMR is stacked on top of.
    #[cfg(feature = "stacked_mmr")]
    pub sub_mmrs: SizesToMMRs,
}

/// The identity and configuration data needed to reference an existing MMR
/// (e.g. when configuring a stacked MMR).
#[derive(Debug, Clone)]
pub struct MmrMetadata {
    /// The unique id under which the MMR's data is stored.
    pub mmr_id: String,
    /// The store the MMR's data lives in.
    pub store: Arc<dyn Store>,
    /// The hashing function the MMR was created with.
    pub hasher: HashingFunction,
}

/// A tuple of the size at which the MMR is stacked and the MMR itself.
#[cfg(feature = "stacked_mmr")]
pub type SizesToMMRs = Vec<(usize, MmrMetadata)>;

impl MMR {
    /// Creates a new MMR handle backed by the given store and hasher.
    ///
    /// If `mmr_id` is `None`, a random UUID is used as the id. Nothing is
    /// written to the store until the first append.
    pub fn new(store: Arc<dyn Store>, hasher: Arc<dyn Hasher>, mmr_id: Option<String>) -> Self {
        let mmr_id = mmr_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        let (leaves_count, elements_count, root_hash, hashes_table) =
            MMR::get_stores(&mmr_id, &store);

        Self {
            leaves_count,
            elements_count,
            hashes: hashes_table,
            root_hash,
            store,
            hasher,
            mmr_id,
            #[cfg(feature = "stacked_mmr")]
            sub_mmrs: Vec::new(),
        }
    }

    /// Creates an MMR instance from a pre-computed set of peaks and element count.
    ///
    /// This function initializes the MMR state based on the provided peaks, allowing
    /// subsequent appends. However, proofs for elements represented solely by these
    /// initial peaks cannot be generated as their constituent hashes are not stored.
    ///
    /// # Arguments
    ///
    /// * `store` - The storage backend.
    /// * `hasher` - The hashing implementation.
    /// * `mmr_id` - An optional ID for the MMR; a new UUID will be generated if None.
    /// * `peaks_hashes` - A vector of strings representing the hashes of the peaks.
    /// * `elements_count` - The total number of elements the MMR represented when these peaks were calculated.
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized `MMR` or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns `MMRError::NonEmptyMMR` if the store already holds an MMR under
    /// the given id, `MMRError::InvalidPeaksCountForElements` if the number of
    /// peaks does not match the element count, and an `MMRError` if the counts
    /// or hashes cannot be written to the store or hashing fails.
    pub async fn create_from_peaks(
        store: Arc<dyn Store>,
        hasher: Arc<dyn Hasher>,
        mmr_id: Option<String>,
        peaks_hashes: Vec<String>,
        elements_count: usize,
    ) -> Result<Self, MMRError> {
        let mmr = MMR::new(store, hasher, mmr_id);

        // Ensure the MMR is empty before initializing from peaks
        let current_elements_count: usize = mmr.elements_count.get().await?;
        if current_elements_count != 0 {
            return Err(MMRError::NonEmptyMMR);
        }

        let expected_peak_indices = find_peaks(elements_count);
        if expected_peak_indices.len() != peaks_hashes.len() {
            return Err(MMRError::InvalidPeaksCountForElements);
        }

        // Set counts
        let leaves_count_val = mmr_size_to_leaf_count(elements_count);
        mmr.leaves_count.set(leaves_count_val).await?;
        mmr.elements_count.set(elements_count).await?;

        // Store the peak hashes
        for (i, peak_hash) in peaks_hashes.iter().enumerate() {
            let peak_index = expected_peak_indices[i];
            mmr.hashes
                .set(peak_hash, &SubKey::Usize(peak_index))
                .await?;
        }

        // Calculate and store the root hash based on the provided peaks
        // Use the existing bag_the_peaks function, assuming store consistency.
        let bag = mmr.bag_the_peaks(Some(elements_count)).await?;

        let root_hash = mmr.calculate_root_hash(&bag, elements_count)?;
        mmr.root_hash.set(&root_hash, &SubKey::None).await?;

        Ok(mmr)
    }

    /// Creates a new MMR and appends the hasher's genesis element to it.
    ///
    /// # Arguments
    ///
    /// * `store` - The storage backend.
    /// * `hasher` - The hashing implementation.
    /// * `mmr_id` - An optional ID for the MMR; a new UUID will be generated if `None`.
    ///
    /// # Returns
    ///
    /// A `Result` containing the initialized `MMR` or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns `MMRError::NonEmptyMMR` if the store already holds an MMR under
    /// the given id, and an `MMRError` if the genesis element cannot be hashed
    /// or appended.
    pub async fn create_with_genesis(
        store: Arc<dyn Store>,
        hasher: Arc<dyn Hasher>,
        mmr_id: Option<String>,
    ) -> Result<Self, MMRError> {
        let mut mmr = MMR::new(store, hasher, mmr_id);
        let elements_count: usize = mmr.elements_count.get().await?;
        if elements_count != 0 {
            return Err(MMRError::NonEmptyMMR);
        }
        let genesis = mmr.hasher.get_genesis()?;
        mmr.append(genesis).await?;
        Ok(mmr)
    }

    /// Returns the metadata needed to reference this MMR later (e.g. when
    /// configuring a stacked MMR).
    #[must_use]
    pub fn get_metadata(&self) -> MmrMetadata {
        MmrMetadata {
            mmr_id: self.mmr_id.clone(),
            store: self.store.clone(),
            hasher: self.hasher.get_name(),
        }
    }

    /// Returns the four full store keys (leaf count, element count, root hash
    /// and hashes table prefix) under which the MMR with the given id stores
    /// its data.
    #[must_use]
    pub fn get_store_keys(mmr_id: &str) -> (String, String, String, String) {
        (
            format!("{}:{}", mmr_id, TreeMetadataKeys::LeafCount),
            format!("{}:{}", mmr_id, TreeMetadataKeys::ElementCount),
            format!("{}:{}", mmr_id, TreeMetadataKeys::RootHash),
            format!("{}:{}:", mmr_id, TreeMetadataKeys::Hashes),
        )
    }

    /// Decodes a full store key of the form `{mmr_id}:{key}:{sub_key}` into its parts.
    ///
    /// # Arguments
    ///
    /// * `store_key` - The full store key to decode.
    ///
    /// # Returns
    ///
    /// A `Result` containing a tuple of the MMR id, the tree metadata key and
    /// the sub key, or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns `MMRError::TreeMetadataKeys` if the key does not have the expected
    /// `{mmr_id}:{key}` form or the metadata key segment is not a known
    /// `TreeMetadataKeys` value.
    pub fn decode_store_key(
        store_key: &str,
    ) -> Result<(String, TreeMetadataKeys, SubKey), MMRError> {
        let invalid_key = || MMRError::TreeMetadataKeys(TreeMetadataKeysError::InvalidKey);
        let mut parts = store_key.split(':');
        let mmr_id = parts.next().ok_or_else(invalid_key)?.to_string();
        let key = TreeMetadataKeys::from_str(parts.next().ok_or_else(invalid_key)?)?;
        let sub_key = match parts.next() {
            Some(sub_key) => SubKey::String(sub_key.to_string()),
            None => SubKey::None,
        };

        Ok((mmr_id, key, sub_key))
    }

    /// Encodes an MMR id, a tree metadata key and a sub key into a full store key.
    #[must_use]
    pub fn encode_store_key(mmr_id: &str, key: TreeMetadataKeys, sub_key: &SubKey) -> String {
        let store_key = format!("{mmr_id}:{key}");
        match sub_key {
            SubKey::None => store_key,
            _ => format!("{store_key}:{sub_key}"),
        }
    }

    /// Creates the four store handles (leaf count, element count, root hash and
    /// hashes table) for the MMR with the given id.
    #[must_use]
    pub fn get_stores(
        mmr_id: &str,
        store: &Arc<dyn Store>,
    ) -> (InStoreCounter, InStoreCounter, InStoreTable, InStoreTable) {
        let (leaves_count_key, elements_count_key, root_hash_key, hashes_key) =
            MMR::get_store_keys(mmr_id);

        (
            InStoreCounter::new(store.clone(), leaves_count_key),
            InStoreCounter::new(store.clone(), elements_count_key),
            InStoreTable::new(store.clone(), root_hash_key),
            InStoreTable::new(store.clone(), hashes_key),
        )
    }

    /// Appends an element to the MMR, merging peaks as needed, and persists
    /// the new hashes, counts and root hash.
    ///
    /// # Arguments
    ///
    /// * `value` - The element to append.
    ///
    /// # Returns
    ///
    /// A `Result` containing an `AppendResult` describing the MMR's state after
    /// the append, or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns an `MMRError` if the element size is rejected by the hasher, the
    /// store cannot be read or written, a peak hash is missing while merging,
    /// or hashing the new root fails.
    pub async fn append(&mut self, value: String) -> Result<AppendResult, MMRError> {
        self.hasher.is_element_size_valid(&value)?;

        let elements_count = self.elements_count.get().await?;

        let mut peaks = self
            .retrieve_peaks_hashes(find_peaks(elements_count), None)
            .await?;

        let mut last_element_idx = self.elements_count.increment().await?;
        let leaf_element_index = last_element_idx;

        //? Store the hash in the database
        self.hashes
            .set(&value, &SubKey::Usize(last_element_idx))
            .await?;

        peaks.push(value);

        let no_merges = leaf_count_to_append_no_merges(self.leaves_count.get().await?);

        for _ in 0..no_merges {
            last_element_idx += 1;

            let Some(right_hash) = peaks.pop() else {
                return Err(MMRError::NoHashFoundForIndex(last_element_idx));
            };

            let Some(left_hash) = peaks.pop() else {
                return Err(MMRError::NoHashFoundForIndex(last_element_idx));
            };

            let parent_hash = self.hasher.hash(vec![left_hash, right_hash])?;

            self.hashes
                .set(&parent_hash, &SubKey::Usize(last_element_idx))
                .await?;
            peaks.push(parent_hash);
        }

        self.elements_count.set(last_element_idx).await?;

        let bag = self.bag_the_peaks(None).await?;

        // Compute the new root hash
        let root_hash = self.calculate_root_hash(&bag, last_element_idx)?;
        self.root_hash.set(&root_hash, &SubKey::None).await?;

        let leaves = self.leaves_count.increment().await?;

        Ok(AppendResult {
            leaves_count: leaves,
            elements_count: last_element_idx,
            element_index: leaf_element_index,
            root_hash,
        })
    }

    /// Generates an inclusion proof for a single element.
    ///
    /// # Arguments
    ///
    /// * `element_index` - The index of the element to prove (1-based).
    /// * `options` - Optional overrides: the element count to prove against and formatting options.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `Proof` or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns `MMRError::InvalidElementIndex` if the index is zero or greater
    /// than the tree size, and an `MMRError` if hashes cannot be retrieved from
    /// the store, formatting fails, or the element's hash is missing.
    pub async fn get_proof(
        &self,
        element_index: usize,
        options: Option<ProofOptions>,
    ) -> Result<Proof, MMRError> {
        if element_index == 0 {
            return Err(MMRError::InvalidElementIndex);
        }

        let options = options.unwrap_or_default();
        let tree_size = match options.elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        if element_index > tree_size {
            return Err(MMRError::InvalidElementIndex);
        }

        let peaks = find_peaks(tree_size);

        let siblings = find_siblings(element_index, tree_size)?;

        let formatting_opts = options
            .formatting_opts
            .as_ref()
            .map(|opts| opts.peaks.clone());
        let peaks_hashes = self.retrieve_peaks_hashes(peaks, formatting_opts).await?;

        let siblings_hashes = self
            .hashes
            .get_many(
                &siblings
                    .iter()
                    .map(|&idx| SubKey::Usize(idx))
                    .collect::<Vec<SubKey>>(),
            )
            .await?;

        let mut siblings_hashes_vec: Vec<String> = siblings
            .iter()
            .filter_map(|&idx| siblings_hashes.get(&idx.to_string()).cloned())
            .collect();

        if let Some(formatting_opts) = options.formatting_opts.as_ref() {
            siblings_hashes_vec = format_proof(siblings_hashes_vec, &formatting_opts.proof)?;
        }

        let element_hash = self
            .hashes
            .get(&SubKey::Usize(element_index))
            .await?
            .ok_or(MMRError::NoHashFoundForIndex(element_index))?;

        Ok(Proof {
            element_index,
            element_hash,
            siblings_hashes: siblings_hashes_vec,
            peaks_hashes,
            elements_count: tree_size,
        })
    }

    /// Generates inclusion proofs for multiple elements in one pass, fetching
    /// all sibling hashes from the store only once.
    ///
    /// # Arguments
    ///
    /// * `elements_indexes` - The indexes of the elements to prove (1-based).
    /// * `options` - Optional overrides: the element count to prove against and formatting options.
    ///
    /// # Returns
    ///
    /// A `Result` containing a vector of `Proof`s, in the same order as the
    /// given indexes, or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns `MMRError::InvalidElementIndex` if any index is zero or greater
    /// than the tree size, `MMRError::NoHashFoundForIndex` if a sibling or
    /// element hash is missing from the fetched results, and an `MMRError` if
    /// hashes cannot be retrieved from the store, sibling computation fails, or
    /// formatting fails.
    pub async fn get_proofs(
        &self,
        elements_indexes: Vec<usize>,
        options: Option<ProofOptions>,
    ) -> Result<Vec<Proof>, MMRError> {
        let options = options.unwrap_or_default();
        let tree_size = match options.elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        for &element_index in &elements_indexes {
            if element_index == 0 {
                return Err(MMRError::InvalidElementIndex);
            }
            if element_index > tree_size {
                return Err(MMRError::InvalidElementIndex);
            }
        }

        let peaks = find_peaks(tree_size);
        let peaks_hashes = self.retrieve_peaks_hashes(peaks, None).await?;

        let mut siblings_per_element = HashMap::new();
        for &element_id in &elements_indexes {
            siblings_per_element.insert(element_id, find_siblings(element_id, tree_size)?);
        }
        let sibling_hashes_to_get: Vec<SubKey> = array_deduplicate(
            siblings_per_element
                .values()
                .flat_map(|x| x.iter().copied())
                .collect(),
        )
        .into_iter()
        .map(SubKey::Usize)
        .collect();
        let all_siblings_hashes = self.hashes.get_many(&sibling_hashes_to_get).await?;

        let elements_ids_str: Vec<SubKey> =
            elements_indexes.iter().map(|&x| SubKey::Usize(x)).collect();
        let element_hashes = self.hashes.get_many(&elements_ids_str).await?;

        let mut proofs: Vec<Proof> = Vec::new();
        for &element_id in &elements_indexes {
            let siblings = siblings_per_element
                .get(&element_id)
                .ok_or(MMRError::InvalidElementIndex)?;
            let mut siblings_hashes: Vec<String> = siblings
                .iter()
                .map(|s| {
                    all_siblings_hashes
                        .get(&s.to_string())
                        .ok_or(MMRError::NoHashFoundForIndex(*s))
                        .cloned()
                })
                .collect::<Result<Vec<_>, _>>()?;

            if let Some(formatting_opts) = &options.formatting_opts {
                siblings_hashes = format_proof(siblings_hashes, &formatting_opts.proof)?;
            }

            proofs.push(Proof {
                element_index: element_id,
                element_hash: element_hashes
                    .get(&element_id.to_string())
                    .ok_or(MMRError::NoHashFoundForIndex(element_id))?
                    .clone(),
                siblings_hashes,
                peaks_hashes: peaks_hashes.clone(),
                elements_count: tree_size,
            });
        }

        Ok(proofs)
    }

    /// Verifies an inclusion proof against a known element value.
    ///
    /// # Arguments
    ///
    /// * `proof` - The proof to verify.
    /// * `element_value` - The value of the proven element.
    /// * `options` - Optional overrides: the element count to verify against and formatting options.
    ///
    /// # Returns
    ///
    /// A `Result` containing `true` if the proof is valid for the given element
    /// value, `false` otherwise, or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns `MMRError::InvalidPeaksCount` if the proof's peak count does not
    /// match the tree size, `MMRError::InvalidElementIndex` if the proven index
    /// is zero or out of range, and an `MMRError` if hashing or store reads fail.
    pub async fn verify_proof(
        &self,
        mut proof: Proof,
        element_value: String,
        options: Option<ProofOptions>,
    ) -> Result<bool, MMRError> {
        let options = options.unwrap_or_default();
        let tree_size = match options.elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        let leaf_count = mmr_size_to_leaf_count(tree_size);
        let peaks_count = leaf_count_to_peaks_count(leaf_count);

        if peaks_count != proof.peaks_hashes.len() {
            return Err(MMRError::InvalidPeaksCount);
        }

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

        if element_index == 0 {
            return Err(MMRError::InvalidElementIndex);
        }

        if element_index > tree_size {
            return Err(MMRError::InvalidElementIndex);
        }

        let (peak_index, peak_height) = get_peak_info(tree_size, element_index);
        if proof.siblings_hashes.len() != peak_height {
            return Ok(false);
        }

        let mut hash = element_value.clone();
        let mut leaf_index = element_index_to_leaf_index(element_index)?;

        for proof_hash in &proof.siblings_hashes {
            let is_right = leaf_index % 2 == 1;
            leaf_index /= 2;

            hash = self.hasher.hash(if is_right {
                vec![proof_hash.clone(), hash.clone()]
            } else {
                vec![hash.clone(), proof_hash.clone()]
            })?;
        }

        let peak_hashes = self
            .retrieve_peaks_hashes(find_peaks(tree_size), None)
            .await?;

        Ok(peak_hashes[peak_index] == hash)
    }

    /// Returns the hashes of the MMR's peaks, optionally formatted to a fixed size.
    ///
    /// # Arguments
    ///
    /// * `option` - Optional overrides: the element count to compute peaks for and peaks formatting options.
    ///
    /// # Returns
    ///
    /// A `Result` containing the vector of peak hashes or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns an `MMRError` if the element count or peak hashes cannot be read
    /// from the store, and `MMRError::Formatting` if formatting fails.
    pub async fn get_peaks(&self, option: PeaksOptions) -> Result<Vec<String>, MMRError> {
        let tree_size = match option.elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };

        let peaks_idxs = find_peaks(tree_size);
        let peaks = self.retrieve_peaks_hashes(peaks_idxs, None).await?;
        if let Some(formatting_opts) = &option.formatting_opts {
            match format_peaks(peaks, formatting_opts) {
                Ok(peaks) => Ok(peaks),
                Err(e) => Err(MMRError::Formatting(e)),
            }
        } else {
            Ok(peaks)
        }
    }

    /// Retrieves the hashes stored under the given peak indices, optionally
    /// formatted to a fixed size.
    ///
    /// # Errors
    ///
    /// Returns an `MMRError` if hashes cannot be retrieved from the store, and
    /// `MMRError::Formatting` if formatting fails.
    pub async fn retrieve_peaks_hashes(
        &self,
        peak_idxs: Vec<usize>,
        formatting_opts: Option<PeaksFormattingOptions>,
    ) -> Result<Vec<String>, MMRError> {
        let hashes_result = self
            .hashes
            .get_many(
                &peak_idxs
                    .iter()
                    .map(|&idx| SubKey::Usize(idx))
                    .collect::<Vec<SubKey>>(),
            )
            .await?;
        // Assuming hashes_result is a HashMap<String, String>
        let hashes: Vec<String> = peak_idxs
            .iter()
            .filter_map(|&idx| hashes_result.get(&idx.to_string()).cloned())
            .collect();

        match formatting_opts {
            Some(opts) => match format_peaks(hashes, &opts) {
                Ok(peaks) => Ok(peaks),
                Err(e) => Err(MMRError::Formatting(e)),
            },
            None => Ok(hashes),
        }
    }

    /// Bags the MMR's peaks into a single hash: with zero peaks, `"0x0"` is
    /// returned; with one peak, that peak's hash is returned; otherwise the
    /// peaks are hashed together from the right.
    ///
    /// # Arguments
    ///
    /// * `elements_count` - Optional element count to bag the peaks for; defaults to the MMR's current count.
    ///
    /// # Returns
    ///
    /// A `Result` containing the bagged peak hash or an `MMRError`.
    ///
    /// # Errors
    ///
    /// Returns an `MMRError` if peak hashes cannot be retrieved from the store
    /// or hashing fails.
    pub async fn bag_the_peaks(&self, elements_count: Option<usize>) -> Result<String, MMRError> {
        let tree_size = match elements_count {
            Some(count) => count,
            None => self.elements_count.get().await?,
        };
        let peaks_idxs = find_peaks(tree_size);

        let peaks_hashes = self.retrieve_peaks_hashes(peaks_idxs.clone(), None).await?;

        match peaks_idxs.len() {
            // Use original peaks_idxs here
            0 => Ok("0x0".to_string()),
            1 => peaks_hashes
                .into_iter()
                .next()
                .ok_or(MMRError::NoHashFoundForIndex(peaks_idxs[0])),
            _ => {
                let mut peaks_hashes: VecDeque<String> = peaks_hashes.into();
                let Some(last) = peaks_hashes.pop_back() else {
                    return Err(MMRError::InvalidPeaksCount);
                };
                let Some(second_last) = peaks_hashes.pop_back() else {
                    return Err(MMRError::InvalidPeaksCount);
                };
                let root0 = self.hasher.hash(vec![second_last, last])?;

                let mut root = root0;
                for peak_hash in peaks_hashes.into_iter().rev() {
                    root = self.hasher.hash(vec![peak_hash, root])?;
                }

                Ok(root)
            }
        }
    }

    /// Calculates the MMR's root hash by hashing the element count together
    /// with the bagged peaks hash.
    ///
    /// # Errors
    ///
    /// Returns `MMRError::Hasher` if hashing fails.
    pub fn calculate_root_hash(
        &self,
        bag: &str,
        elements_count: usize,
    ) -> Result<String, MMRError> {
        match self
            .hasher
            .hash(vec![elements_count.to_string(), bag.to_string()])
        {
            Ok(root_hash) => Ok(root_hash),
            Err(e) => Err(MMRError::Hasher(e)),
        }
    }
}
