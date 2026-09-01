//! TODO

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authentication/encryption: {0}")]
    AesGcm(#[from] aes_gcm::Error),
    #[error("invalid key length: {0}")]
    AesGcmInvalidLength(#[from] aes_gcm::aes::cipher::InvalidLength),
    #[error("serialization/deserialization: {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("password: {0}")]
    Argon2(#[from] argon2::Error),
    #[error("IO: {0}")]
    StdIo(#[from] std::io::Error),

    #[error("file system: path must be a directory, not a file")]
    PathNotDir,
    #[error("file system: default system local data directory not found")]
    DataLocalDirNotFound,
    #[error("file system: default vault location not found")]
    DefaultVaultLocationNotFound,

    #[error("vault header: inavlid vault header")]
    VaultHeaderInvalid,
    #[error("failed to deserialize vault header")]
    VaultHeaderDeserializationFailed,

    #[error("bad entry: inavlid service name")]
    InvalidServiceName,
    #[error("bad entry: inavlid username")]
    InvalidUsername,
    #[error("bad entry: inavlid password")]
    InvalidPassword,

    #[error("vault: service not found in the vault")]
    ServiceNotFound,
    #[error("vault: service already exists in the vault")]
    ServiceAlreadyExists,
}

/// Convenience type for Result
pub type Result<T> = std::result::Result<T, Error>;
