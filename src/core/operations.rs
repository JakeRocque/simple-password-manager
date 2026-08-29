//! TODO

use crate::error::Result;
use aes_gcm::{Aes256Gcm, Key};
use argon2::password_hash::generate_salt;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_() {}
}
