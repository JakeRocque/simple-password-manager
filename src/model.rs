//! TODO

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

pub const VAULT_MAGIC: [u8; 4] = [0x3b, 0xd0, 0x07, 0xbd];

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct VaultHeader {
    magic: [u8; 4],
    version: [u8; 2],
    salt: [u8; 16],
}

#[derive(Debug, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Vault {
    header: VaultHeader,
    sealed_entries: Vec<u8>, // nonce || AES-GCM ciphertext & authentication tag
}

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Entry {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
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

impl Vault {
    /// TODO
    pub fn new(header: VaultHeader,
    sealed_entries: Vec<u8>) -> Self {
        Self {
            header,
            sealed_entries,
        }
    }
}

impl Entry {
    /// TODO
    pub fn new(username: &str, password: &str) -> Self {
        Self {
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

impl Entries {
    /// TODO
    pub fn new(entries: Vec<Entry>) -> Self {
        Self {
            entries,
    }
}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_() {}
}
