//! TODO

use core::fmt;
#[cfg(test)]
use std::path::Path;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VAULT_MAGIC: [u8; 4] = [0x3b, 0xd0, 0x07, 0xbd];

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct VaultHeader {
    magic: [u8; 4],
    version: [u8; 2],
    salt: [u8; 16],
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Sealed {
    nonce: [u8; 12],
    ciphertext: Vec<u8>, //  AES-GCM ciphertext & authentication tag
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Vault {
    header: VaultHeader,
    sealed: Sealed,
}

#[derive(Serialize, PartialEq, Eq, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    service: String,
    username: String,
    password: String,
}

#[derive(Serialize, PartialEq, Eq, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Entries {
    entries: Vec<Entry>,
}

impl VaultHeader {
    /// TODO
    pub fn new(magic: [u8; 4], version: [u8; 2], salt: [u8; 16]) -> Self {
        Self {
            magic,
            version,
            salt,
        }
    }

    /// TODO
    pub fn serialize(&self) -> [u8; 22] {
        let mut out = [0u8; 22];

        out[0..4].copy_from_slice(&self.magic);
        out[4..6].copy_from_slice(&self.version);
        out[6..22].copy_from_slice(&self.salt);

        out
    }

    /// TODO
    pub fn deserialize(bytes: &[u8; 22]) -> Self {
        let mut magic = [0u8; 4];
        let mut version = [0u8; 2];
        let mut salt = [0u8; 16];

        magic.copy_from_slice(&bytes[0..4]);
        version.copy_from_slice(&bytes[4..6]);
        salt.copy_from_slice(&bytes[6..22]);

        Self {
            magic,
            version,
            salt,
        }
    }
}

impl Sealed {
    /// TODO
    pub fn new(nonce: [u8; 12], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// TODO
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// TODO
    pub fn ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext
    }
}

impl Vault {
    /// TODO
    pub fn new(header: VaultHeader, sealed: Sealed) -> Self {
        Self { header, sealed }
    }
}

impl Entry {
    /// TODO
    pub fn new(service: &str, username: &str, password: &str) -> Self {
        Self {
            service: service.to_string(),
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    /// TODO
    pub fn username(&self) -> &str {
        &self.username
    }

    /// TODO
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("debug", &"[REDACTED]")
            .finish()
    }
}

impl Entries {
    /// TODO
    pub fn new(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// TODO
    pub fn entries(&self) -> &Vec<Entry> {
        &self.entries
    }
}

impl fmt::Debug for Entries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entries")
            .field("debug", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_() {}
}
