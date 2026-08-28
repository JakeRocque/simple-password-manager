//! TODO

use aes_gcm::{Aes256Gcm, Key};
use argon2::password_hash::generate_salt;
use crate::error::Result;

use crate::{core::crypto::encrypt_entries, model::{Entries, Entry, Vault, VaultHeader}};

fn create_empty_vault(key: &Key<Aes256Gcm>, magic: [u8; 4], version: [u8; 2]) -> Result<Vault> {
    let salt = generate_salt();

    let entry = Entry::new("Salve,", "plurimum!");
    let entries = Entries::new(vec![entry]);

    let header = VaultHeader::new(magic, version, salt);

    let sealed_entries = encrypt_entries(key, &entries, &header)?;

    Ok(Vault::new(header, sealed_entries))
}

/// TODO
pub fn init_vault(
    magic: [u8; 4],
    version: [u8; 2],
) -> Result<()> {
    !todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_() {

    }
}