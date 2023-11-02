use super::formatting::{PeaksFormattingOptions, ProofFormattingOptions};

#[derive(Debug, PartialEq, Eq)]
pub struct Proof {
    /// The index of the proven element.
    /// For example: 1
    pub element_index: usize,

    /// The hash of the element - the hash that is stored in the database.
    /// For example: "0x1234567890abcdef"
    pub element_hash: String,

    /// The proof of the element's inclusion, aka the siblings hashes.
    /// For example: ["0x1234567890abcdef", "0x1234567890abcdef"]
    pub siblings_hashes: Vec<String>,

    /// The hashes of the peaks of the tree.
    /// For example: ["0x1234567890abcdef", "0x1234567890abcdef"]
    pub peaks_hashes: Vec<String>,

    /// The size of the tree, aka the position, aka the number of all elements in the tree.
    /// For example: 1
    pub elements_count: usize,
}

pub struct ProofOptions {
    pub elements_count: Option<usize>,
    pub formatting_opts: Option<FormattingOptionsBundle>,
}

pub struct PeaksOptions {
    elements_count: Option<usize>,
    formatting_opts: Option<PeaksFormattingOptions>,
}

pub struct FormattingOptionsBundle {
    pub proof: ProofFormattingOptions,
    pub peaks: PeaksFormattingOptions,
}
