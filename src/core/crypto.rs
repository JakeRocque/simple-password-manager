//! TODO

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

    encrypt(key, &entries_bytes, &header.to_bytes())
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
    let entries_bytes = Zeroizing::new(decrypt(key, sealed, &header.to_bytes())?);

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
}
