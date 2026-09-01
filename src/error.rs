//! TODO

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("aes_gcm error: {0}")]
    AesGcm(#[from] aes_gcm::Error),
    #[error("aes_gcm::aes::cipher invalid key length: {0}")]
    AesGcmInvalidLength(#[from] aes_gcm::aes::cipher::InvalidLength),
    #[error("serde_json error: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("toml::ser error: {0}")]
    TomlSer(#[from] toml::ser::Error),
    #[error("toml::de error: {0}")]
    TomlDe(#[from] toml::de::Error),
    #[error("serde_json error: {0}")]
    Argon2(#[from] argon2::Error),
    #[error("argon2 error: {0}")]
    StdIo(#[from] std::io::Error),

    #[error("default system local data directory not found")]
    DataLocalDirNotFound,

    #[error("inavlid vault header")]
    VaultHeaderInvalid,
    #[error("failed to deserialize vault header")]
    VaultHeaderDeserializationFailed,

    #[error("inavlid service name")]
    InvalidServiceName,
    #[error("inavlid username")]
    InvalidUsername,
    #[error("inavlid password")]
    InvalidPassword,

    #[error("service not found in the vault")]
    ServiceNotFound,
    #[error("service already exists in the vault")]
    ServiceAlreadyExists,
}

/// Convenience type for Result
pub type Result<T> = std::result::Result<T, Error>;
