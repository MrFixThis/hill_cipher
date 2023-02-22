use thiserror::Error;

/// A specified [`Result`] type for the `cipher` and `decipher` operations.
pub type Result<T> = std::result::Result<T, Error>;

/// The error type for `cipher` and `decipher` operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
	#[error("{0}")]
	ProcessingError(String),
}

impl From<&'static str> for Error {
    fn from(value: &'static str) -> Self {
		Error::ProcessingError(value.to_owned())
    }
}

impl From<String> for Error {
    fn from(value: String) -> Self {
		Error::ProcessingError(value)
    }
}
