use thiserror::Error;
/// Formatting
#[derive(Clone)]
pub struct FormattingOptions {
    pub output_size: usize,
    pub null_value: String,
}

pub type ProofFormattingOptions = FormattingOptions;
pub type PeaksFormattingOptions = FormattingOptions;

// pub fn validate_formatting_options(options: &FormattingOptions) -> Result<(), String> {
//     if !options.null_value.starts_with("0x") {
//         return Err("Formatting options: nullValue must be a hex string".to_string());
//     }

//     if usize::from_str_radix(&options.null_value[2..], 16).is_err() {
//         return Err("Formatting options: nullValue must be a hex string".to_string());
//     }

//     Ok(())
// }

/// Formatting error
#[derive(Error, Debug)]
pub enum FormattingError {
    #[error("Formatting: Expected peaks output size is smaller than the actual size")]
    PeaksOutputSizeError,
    #[error("Formatting: Expected proof output size is smaller than the actual size")]
    ProofOutputSizeError,
}

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

pub fn format_proof(
    siblings_hashes: Vec<String>,
    formatting_opts: ProofFormattingOptions,
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
