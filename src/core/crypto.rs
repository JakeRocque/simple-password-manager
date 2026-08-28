//! TODO

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, Generate, Key, KeyInit},
};
use zeroize::Zeroizing;
use crate::{error::Result, model::{Entries, VaultHeader}};

// let key = Key::<Aes256Gcm>::generate();
// let cipher = Aes256Gcm::new(&key);

// let nonce = Nonce::generate(); // MUST be unique per message
// let ciphertext = cipher.encrypt(&nonce, b"plaintext message".as_ref())?;

// let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref())?;
// assert_eq!(&plaintext, b"plaintext message");

/// TODO
pub fn derive_key(password: &[u8], salt: &[u8; 16]) -> Result<Key<Aes256Gcm>> {
    !todo!()
}

/// TODO
fn encrypt(key: &Key<Aes256Gcm>, message: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    Ok(vec![])
}

pub fn encrypt_entries(key: &Key<Aes256Gcm>, entries: &Entries, header: &VaultHeader) -> Result<Vec<u8>> {
    Ok(vec![])
}

/// TODO
pub fn decrypt(key: &Key<Aes256Gcm>, aad: &[u8]) -> Result<Vec<u8>> {
    Ok(vec![])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_() {}
}
