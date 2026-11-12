//! Formatting utilities for peak and proof hash lists.

use thiserror::Error;

/// Options controlling how a hash list is formatted.
#[derive(Clone)]
pub struct FormattingOptions {
    /// The fixed output size the list is padded up to.
    pub output_size: usize,
    /// The value used to pad the list up to `output_size`.
    pub null_value: String,
}

/// Formatting options applied to a proof's sibling hashes.
pub type ProofFormattingOptions = FormattingOptions;
/// Formatting options applied to a list of peak hashes.
pub type PeaksFormattingOptions = FormattingOptions;

/// An error that can occur while formatting peak or proof hash lists.
#[derive(Error, Debug)]
pub enum FormattingError {
    /// The peaks list is longer than the requested output size.
    #[error("Formatting: Expected peaks output size is smaller than the actual size")]
    PeaksOutputSizeError,
    /// The proof's sibling hash list is longer than the requested output size.
    #[error("Formatting: Expected proof output size is smaller than the actual size")]
    ProofOutputSizeError,
}

/// Pads a list of peak hashes with null values up to `formatting_opts.output_size`.
///
/// # Arguments
///
/// * `peaks` - The peak hashes to format.
/// * `formatting_opts` - The output size to pad up to and the null value to pad with.
///
/// # Returns
///
/// A `Result` containing the padded list of peak hashes or a `FormattingError`.
///
/// # Errors
///
/// Returns `FormattingError::PeaksOutputSizeError` if the peaks list is longer
/// than the requested output size.
pub fn format_peaks(
    mut peaks: Vec<String>,
    formatting_opts: &PeaksFormattingOptions,
) -> Result<Vec<String>, FormattingError> {
    if peaks.len() > formatting_opts.output_size {
        return Err(FormattingError::PeaksOutputSizeError);
    }

    let expected_peaks_size_remainder = formatting_opts.output_size - peaks.len();
    let peaks_null_values: Vec<String> =
        vec![formatting_opts.null_value.clone(); expected_peaks_size_remainder];

    peaks.extend(peaks_null_values);

    Ok(peaks)
}

/// Pads a proof's sibling hashes with null values up to `formatting_opts.output_size`.
///
/// # Arguments
///
/// * `siblings_hashes` - The sibling hashes of the proof to format.
/// * `formatting_opts` - The output size to pad up to and the null value to pad with.
///
/// # Returns
///
/// A `Result` containing the padded list of sibling hashes or a `FormattingError`.
///
/// # Errors
///
/// Returns `FormattingError::ProofOutputSizeError` if the sibling hashes list is
/// longer than the requested output size.
pub fn format_proof(
    siblings_hashes: Vec<String>,
    formatting_opts: &ProofFormattingOptions,
) -> Result<Vec<String>, FormattingError> {
    if siblings_hashes.len() > formatting_opts.output_size {
        return Err(FormattingError::ProofOutputSizeError);
    }

    let expected_proof_size_remainder = formatting_opts.output_size - siblings_hashes.len();
    let mut proof_null_values =
        vec![formatting_opts.null_value.clone(); expected_proof_size_remainder];

    let mut result = siblings_hashes;
    result.append(&mut proof_null_values);

    Ok(result)
}
