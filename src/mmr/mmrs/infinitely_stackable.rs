use crate::{
    hasher::Hasher,
    mmr::{
        helpers::{AppendResult, Proof, ProofOptions},
        CoreMMR, MMR,
    },
    store::Store,
};
use anyhow::Result;

/// A tuple of the size at which the MMR is stacked and the MMR itself.
pub type SizeToMMR<H> = (usize, MMR<dyn Store, H>);

pub struct InfinitelyStackableMMR<S, H>
where
    S: Store + ?Sized,
    H: Hasher,
{
    pub mmr: MMR<S, H>,
    /// The MMRs that this one is stacked on top of, in order of oldest to newest, by size.
    pub sub_mmrs: Vec<SizeToMMR<H>>,
}

impl<S, H> CoreMMR for InfinitelyStackableMMR<S, H>
where
    S: Store + ?Sized,
    H: Hasher,
{
    fn append(&mut self, element: String) -> Result<AppendResult> {
        self.mmr.append(element)
    }

    fn get_proof(&self, index: usize, options: ProofOptions) -> Result<Proof> {
        self.mmr.get_proof(index, options)
    }

    fn get_proofs(&self, elements_ids: Vec<usize>, options: ProofOptions) -> Result<Vec<Proof>> {
        self.mmr.get_proofs(elements_ids, options)
    }

    fn verify_proof(
        &self,
        proof: Proof,
        element_value: String,
        options: ProofOptions,
    ) -> Result<bool> {
        self.mmr.verify_proof(proof, element_value, options)
    }

    fn retrieve_peaks_hashes(
        &self,
        peak_idxs: Vec<usize>,
        formatting_opts: Option<crate::mmr::formatting::PeaksFormattingOptions>,
    ) -> Result<Vec<String>> {
        self.mmr.retrieve_peaks_hashes(peak_idxs, formatting_opts)
    }

    fn bag_the_peaks(&self, elements_count: Option<usize>) -> Result<String> {
        self.mmr.bag_the_peaks(elements_count)
    }

    fn calculate_root_hash(&self, bag: &str, leaf_count: usize) -> Result<String> {
        self.mmr.calculate_root_hash(bag, leaf_count)
    }
}
