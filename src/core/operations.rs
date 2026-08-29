//! TODO

use std::path::Path;

use crate::{error::Result, model::ServiceList};
use aes_gcm::{Aes256Gcm, Key};
use argon2::password_hash::generate_salt;
use zeroize::Zeroizing;

use crate::{
    core::crypto::encrypt_entries,
    model::{Entries, Entry, Vault, VaultHeader},
};

fn create_empty_vault(key: &Key<Aes256Gcm>, magic: [u8; 4], version: [u8; 2]) -> Result<Vault> {
    let salt = generate_salt();

    let header = VaultHeader::new(magic, version, salt);

    let sealed = encrypt_entries(
        key,
        &Entries::new(vec![Entry::new("Latin Class", "Salve,", "plurimum!")]),
        &header,
    )?;

    Ok(Vault::new(header, sealed))
}

/// TODO
pub fn init_vault(magic: [u8; 4], version: [u8; 2]) -> Result<()> {
    !todo!()
}

/// TODO
pub fn list_services(vault_path: &Path, key: &Key<Aes256Gcm>) -> Result<ServiceList> {
    !todo!()
}

/// TODO
pub fn get_entry(vault_path: &Path, key: &Key<Aes256Gcm>, service: &str) -> Result<Entry> {
    !todo!()
}

/// TODO
pub fn write_entry(
    vault_path: &Path,
    key: &Key<Aes256Gcm>,
    service: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
) -> Result<()> {
    !todo!()
}

/// TODO
pub fn delete_entry(
    vault_path: &Path,
    key: &Key<Aes256Gcm>,
    service: Zeroizing<String>,
) -> Result<()> {
    !todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_() {}
}
