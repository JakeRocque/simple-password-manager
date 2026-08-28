//! TODO

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("inavlid service name")]
    InvalidServiceName,
    #[error("inavlid username")]
    InvalidUsername,
    #[error("inavlid password")]
    InvalidPassword,
}

/// Convenience type for Result
pub type Result<T> = std::result::Result<T, Error>;
