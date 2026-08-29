//! TODO

use crate::{
    error::{Error, Result},
    model::{Entries, Sealed, VaultHeader},
};
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, Generate, Key, KeyInit, Payload},
};
use argon2::Argon2;
use zeroize::Zeroizing;

fn derive_key_bytes(password: &Zeroizing<String>, salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let argon2 = Argon2::default();

    let mut key_bytes = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut *key_bytes)
        .map_err(Error::Argon2)?;

    Ok(Zeroizing::new(*key_bytes))
}

/// TODO
pub fn key_from_bytes(password: &Zeroizing<String>, salt: &[u8; 16]) -> Result<Key<Aes256Gcm>> {
    let key_bytes = derive_key_bytes(password, salt)?;

    // Caller must handle key zeroization.
    Ok(Key::<Aes256Gcm>::from(*key_bytes))
}

fn encrypt(key: &Key<Aes256Gcm>, message: &[u8], aad: &[u8]) -> Result<Sealed> {
    let cipher = Aes256Gcm::new(&key);

    let nonce = Nonce::generate();
    let payload = Payload {
        msg: message,
        aad: aad,
    };

    let ciphertext = cipher.encrypt(&nonce, payload).map_err(Error::AesGcm)?;

    Ok(Sealed::new(nonce.into(), ciphertext))
}

/// TODO
pub fn encrypt_entries(
    key: &Key<Aes256Gcm>,
    entries: &Entries,
    header: &VaultHeader,
) -> Result<Sealed> {
    let entries_bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(serde_json::to_vec(entries).map_err(Error::SerdeJson)?); // TODO - can/should this line be tested? can/should zeroizing here be tested?

    encrypt(key, &entries_bytes, &header.serialize())
}

fn decrypt(key: &Key<Aes256Gcm>, sealed: &Sealed, aad: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(&key);
    let payload = Payload {
        msg: sealed.ciphertext(),
        aad: aad,
    };

    let message = cipher
        .decrypt(sealed.nonce().into(), payload)
        .map_err(Error::AesGcm)?;

    Ok(message)
}

/// TODO
pub fn decrypt_entries(
    key: &Key<Aes256Gcm>,
    sealed: &Sealed,
    header: &VaultHeader,
) -> Result<Zeroizing<Entries>> {
    let entries_bytes = Zeroizing::new(decrypt(key, sealed, &header.serialize())?);

    let entries = serde_json::from_slice(&entries_bytes).map_err(Error::SerdeJson)?; // TODO - can/should this line be tested? can/should zeroizing here be tested?

    Ok(Zeroizing::new(entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::generate_salt;

    use crate::model::{Entry, VAULT_MAGIC};

    #[test]
    fn test_derive_key_bytes_ok() {
        let password = Zeroizing::new("super_secret".to_string());
        let salt = generate_salt();

        let key_bytes = derive_key_bytes(&password, &salt).unwrap();

        assert_eq!(key_bytes.len(), 32);
    }

    #[test]
    fn test_derive_key_bytes_same_password_salt_same_key() {
        let password = Zeroizing::new("super_secret".to_string());
        let salt = generate_salt();

        let key_bytes1 = derive_key_bytes(&password, &salt).unwrap();
        let key_bytes2 = derive_key_bytes(&password, &salt).unwrap();

        assert_eq!(key_bytes1, key_bytes2);
    }

    #[test]
    fn test_derive_key_bytes_different_password_salt_different_key() {
        let password1 = Zeroizing::new("super_secret".to_string());
        let password2 = Zeroizing::new("super_duper_secret".to_string());
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let key_bytes1 = derive_key_bytes(&password1, &salt1).unwrap();
        let key_bytes2 = derive_key_bytes(&password1, &salt2).unwrap();
        let key_bytes3 = derive_key_bytes(&password2, &salt1).unwrap();
        let key_bytes4 = derive_key_bytes(&password2, &salt2).unwrap();

        assert_ne!(key_bytes1, key_bytes2);
        assert_ne!(key_bytes1, key_bytes3);
        assert_ne!(key_bytes1, key_bytes4);
        assert_ne!(key_bytes2, key_bytes3);
        assert_ne!(key_bytes2, key_bytes4);
        assert_ne!(key_bytes3, key_bytes4);
    }

    #[test]
    fn test_key_from_bytes_ok() {
        let password = Zeroizing::new("super_secret".to_string());
        let salt = generate_salt();

        let key = key_from_bytes(&password, &salt).unwrap();

        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_key_from_bytes_same_password_salt_same_key() {
        let password = Zeroizing::new("super_secret".to_string());
        let salt = generate_salt();

        let key1 = key_from_bytes(&password, &salt).unwrap();
        let key2 = key_from_bytes(&password, &salt).unwrap();

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_key_from_bytes_different_password_salt_different_key() {
        let password1 = Zeroizing::new("super_secret".to_string());
        let password2 = Zeroizing::new("super_duper_secret".to_string());
        let salt1 = generate_salt();
        let salt2 = generate_salt();

        let key1 = derive_key_bytes(&password1, &salt1).unwrap();
        let key2 = derive_key_bytes(&password1, &salt2).unwrap();
        let key3 = derive_key_bytes(&password2, &salt1).unwrap();
        let key4 = derive_key_bytes(&password2, &salt2).unwrap();

        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key1, key4);
        assert_ne!(key2, key3);
        assert_ne!(key2, key4);
        assert_ne!(key3, key4);
    }

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
            Entry::new("gmail", "mikey123", "$dog29!"),
            Entry::new("outlook", "jbhockeyfan@gmail.com", "rang3rsFanNY?"),
        ]);
        let header = VaultHeader::new(VAULT_MAGIC, [0x00, 0x02], generate_salt());

        let sealed = encrypt_entries(&key, &entries, &header).unwrap();
        let decrypted = decrypt_entries(&key, &sealed, &header).unwrap();

        assert_eq!(decrypted, entries.into());
    }
}
