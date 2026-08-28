//! TODO
use std::collections::BTreeMap;

pub const VAULT_MAGIC: [u8; 4] = [0x3b, 0xd0, 0x07, 0xbd];
pub const VAULT_VERSION: [u8; 2] = [0x00, 0x01];

#[derive(Debug, Serialize, Deserialize)]
pub struct VaultHeader {
    pub magic: [u8; 4],
    pub version: [u8; 2],
    pub nonce: [u8; 12],
    pub salt: [u8; 16],
}

#[derive(Debug)]
pub struct Vault {
    pub header: VaultHeader,
    pub sealed_entries: Vec<u8>,  // tag is automatically created at the end of this with AES-GCM
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Entry {
    username: String,
    password: String,
}

pub type Entries = BTreeMap<String, Entry>;
