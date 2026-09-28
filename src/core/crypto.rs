//! Cryptography for password manager data
//!
//! This module provides authenticated encryption and decryption for
//! password manager entries using AES-256-GCM. All metadata for a password
//! vault is contained within the vault header and is supplied as additional
//! authenticated data (AAD), binding the encrypted entries to the entire
//! authenticated vault.

use crate::{
    error::{Error, Result},
    model::{Entries, Sealed, VaultHeader},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit, Payload},
};
use zeroize::Zeroizing;

fn encrypt(key: &Key<Aes256Gcm>, message: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = Aes256Gcm::new(key);

    let nonce = Nonce::generate();
    let payload = Payload { msg: message, aad };

    let ciphertext = cipher.encrypt(&nonce, payload).map_err(Error::AesGcm)?;

    Ok(Sealed::new(nonce.into(), ciphertext))
}

/// Serializes and encrypts password vault entries using AES-256-GCM.
///
/// The [`Entries`] and [`VaultHeader`] are serialized before encryptiom.
/// The entries are encrypted using the `key` and authenticated with the
/// header as AAD.
///
/// The header is not encrypted but modifying it causes authentication, and
/// decryption in turn, to fail. The header and encrypted entries together
/// form the entire vault and thus the entire vault is authenticated.
///
/// # Errors
///
/// Returns [`Error::SerdeJson`] if serializing the entries fails.
///
/// Returns [`Error::AesGcm`] if AES-GCM encryption fails.
pub fn encrypt_entries(
    key: &Key<Aes256Gcm>,
    entries: &Entries,
    header: &VaultHeader,
) -> Result<Sealed> {
    let entries_bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(serde_json::to_vec(entries).map_err(Error::SerdeJson)?);

    encrypt(key, &entries_bytes, &header.to_bytes())
}

fn decrypt(key: &Key<Aes256Gcm>, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key);
    let payload = Payload {
        msg: sealed.ciphertext(),
        aad,
    };

    let message = cipher
        .decrypt(sealed.nonce().into(), payload)
        .map_err(Error::AesGcm)?;

    Ok(message)
}

/// Decrypts and deserializes password vault entries using AES-256-GCM.
///
/// The serialized [`VaultHeader`] is used as AAD and so must
/// be unchanged for decryption to succeed.
///
/// # Errors
///
/// Returns [`Error::DecryptionOrAuthenticationFailed`] if decryption or
/// authentication fails, including when the key or vault header is incorrect.
///
/// Returns [`Error::SerdeJson`] if the decrypted data cannot be deserialized
/// into [`Entries`].
pub fn decrypt_entries(
    key: &Key<Aes256Gcm>,
    sealed: &Sealed,
    header: &VaultHeader,
) -> Result<Zeroizing<Entries>> {
    let entries_bytes = Zeroizing::new(
        decrypt(key, sealed, &header.to_bytes())
            .map_err(|_| Error::DecryptionOrAuthenticationFailed)?,
    );

    let entries = serde_json::from_slice(&entries_bytes).map_err(Error::SerdeJson)?; // TODO - can/should this line be tested? can/should zeroizing here be tested?

    Ok(Zeroizing::new(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::generate_salt;

    use crate::model::{Entry, VAULT_MAGIC};

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = Key::<Aes256Gcm>::generate();
        let message = b"Hello, this is a secret message";
        let aad = b"Jan 25, Idaho";

        let sealed = encrypt(&key, message, aad).unwrap();
        let decrypted = decrypt(&key, &sealed, aad).unwrap();
        let bytes: &[u8] = decrypted.as_slice();

        assert_eq!(bytes, message);
    }

    #[test]
    fn test_encrypt_unique_nonce() {
        let key = Key::<Aes256Gcm>::generate();
        let message1 = b"Hello, this is a secret message";
        let message2 = b"Hello, this is also a secret message";
        let aad = b"Jan 25, Idaho";

        let sealed1 = encrypt(&key, message1, aad).unwrap();
        let sealed2 = encrypt(&key, message2, aad).unwrap();
        let sealed3 = encrypt(&key, message1, aad).unwrap();

        assert_ne!(sealed1.nonce(), sealed2.nonce());
        assert_ne!(sealed2.nonce(), sealed3.nonce());
    }

    #[test]
    fn test_encrypt_unique_auth_tag() {
        let key = Key::<Aes256Gcm>::generate();
        let message = b"Hello, this is a secret message";
        let aad1 = b"Jan 25, Idaho";
        let aad2 = b"Jan 26, Idaho";

        let sealed1 = encrypt(&key, message, aad1).unwrap();
        let sealed2 = encrypt(&key, message, aad2).unwrap();
        let sealed3 = encrypt(&key, message, aad1).unwrap();

        assert_ne!(sealed1.ciphertext(), sealed2.ciphertext());
        assert_ne!(sealed2.ciphertext(), sealed3.ciphertext());
    }

    #[test]
    fn test_encrypt_decrypt_wrong_key() {
        let key1 = Key::<Aes256Gcm>::generate();
        let key2 = Key::<Aes256Gcm>::generate();
        let message = b"Hello, this is a secret message";
        let aad = b"Jan 25, Idaho";

        let sealed = encrypt(&key1, message, aad).unwrap();
        let err = decrypt(&key2, &sealed, aad).unwrap_err();

        assert!(matches!(err, Error::AesGcm(_)));
    }

    #[test]
    fn test_encrypt_decrypt_wrong_aad() {
        let key = Key::<Aes256Gcm>::generate();
        let message = b"Hello, this is a secret message";
        let aad1 = b"Jan 25, Idaho";
        let aad2 = b"Jan 26, Idaho";

        let sealed = encrypt(&key, message, aad1).unwrap();
        let err = decrypt(&key, &sealed, aad2).unwrap_err();

        assert!(matches!(err, Error::AesGcm(_)));
    }

    #[test]
    fn test_encrypt_entries_decrypt_entries_roundtrip() {
        let key = Key::<Aes256Gcm>::generate();
        let entries = Entries::new(vec![
            Entry::new(
                "gmail".to_string(),
                "mikey123".to_string(),
                "$dog29!".to_string(),
            ),
            Entry::new(
                "outlook".to_string(),
                "jbhockeyfan@gmail.com".to_string(),
                "rang3rsFanNY?".to_string(),
            ),
        ]);
        let header = VaultHeader::new(VAULT_MAGIC, [0x00, 0x02], generate_salt());

        let sealed = encrypt_entries(&key, &entries, &header).unwrap();
        let decrypted = decrypt_entries(&key, &sealed, &header).unwrap();

        assert_eq!(decrypted, entries.into());
    }

    #[test]
    fn test_encrypt_entries_decrypt_entries_wrong_key() {
        let key = Key::<Aes256Gcm>::generate();
        let entries = Entries::new(vec![
            Entry::new(
                "gmail".to_string(),
                "mikey123".to_string(),
                "$dog29!".to_string(),
            ),
            Entry::new(
                "outlook".to_string(),
                "jbhockeyfan@gmail.com".to_string(),
                "rang3rsFanNY?".to_string(),
            ),
        ]);
        let header = VaultHeader::new(VAULT_MAGIC, [0x00, 0x02], generate_salt());

        let sealed = encrypt_entries(&key, &entries, &header).unwrap();
        let wrong_key = Key::<Aes256Gcm>::generate();

        let err = decrypt_entries(&wrong_key, &sealed, &header).unwrap_err();

        assert!(matches!(err, Error::DecryptionOrAuthenticationFailed));
    }

    #[test]
    fn test_encrypt_entries_decrypt_entries_corrupted_authentication() {
        let key = Key::<Aes256Gcm>::generate();
        let entries = Entries::new(vec![
            Entry::new(
                "gmail".to_string(),
                "mikey123".to_string(),
                "$dog29!".to_string(),
            ),
            Entry::new(
                "outlook".to_string(),
                "jbhockeyfan@gmail.com".to_string(),
                "rang3rsFanNY?".to_string(),
            ),
        ]);
        let salt = generate_salt();
        let header = VaultHeader::new(VAULT_MAGIC, [0x00, 0x02], salt);

        let sealed = encrypt_entries(&key, &entries, &header).unwrap();

        let mut wrong_vault_magic = VAULT_MAGIC.clone();

        wrong_vault_magic[0] = wrong_vault_magic[0] - 1;
        let wrong_header1 = VaultHeader::new(wrong_vault_magic, [0x00, 0x02], salt);

        let wrong_header2 = VaultHeader::new(VAULT_MAGIC, [0x00, 0x01], salt);

        let wrong_header3 = VaultHeader::new(VAULT_MAGIC, [0x00, 0x02], generate_salt());

        let err1 = decrypt_entries(&key, &sealed, &wrong_header1).unwrap_err();
        let err2 = decrypt_entries(&key, &sealed, &wrong_header2).unwrap_err();
        let err3 = decrypt_entries(&key, &sealed, &wrong_header3).unwrap_err();

        assert!(matches!(err1, Error::DecryptionOrAuthenticationFailed));
        assert!(matches!(err2, Error::DecryptionOrAuthenticationFailed));
        assert!(matches!(err3, Error::DecryptionOrAuthenticationFailed));
    }
}
