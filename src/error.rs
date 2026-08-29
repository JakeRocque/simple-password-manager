//! TODO

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("aes_gcm error: {0}")]
    AesGcm(#[from] aes_gcm::Error),
    #[error("aes_gcm::aes::cipher invalid key length: {0}")]
    AesGcmInvalidLength(#[from] aes_gcm::aes::cipher::InvalidLength),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("serde_json error: {0}")]
    Argon2(#[from] argon2::Error),
    #[error("argon2 error: {0}")]
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
