//! One error type for the whole crate.
//!
//! Every fallible function returns `Result<T>`, so callers can use `?`
//! and the binary decides how to present the error. Library code never
//! panics on bad input.

use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PreflightError {
    #[error("could not read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("could not read from stdin: {0}")]
    ReadStdin(#[source] std::io::Error),

    #[error("input is not valid UTF-8 text")]
    NotUtf8,

    #[error("input is empty")]
    EmptyInput,

    #[error("could not serialise report: {0}")]
    Serialise(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, PreflightError>;
