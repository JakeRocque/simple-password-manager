//! TODO


#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("aes_gcm error: {0}")]
    AesGcm(#[from] aes_gcm::Error),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("std::io error: {0}")]
    StdIo(#[from] std::io::Error),

    #[error("inavlid service name")]
    InvalidServiceName,
    #[error("inavlid username")]
    InvalidUsername,
    #[error("inavlid password")]
    InvalidPassword,
}

/// Convenience type for Result
pub type Result<T> = std::result::Result<T, Error>;
