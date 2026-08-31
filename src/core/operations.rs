//! TODO

use std::path::Path;

use crate::{
    core::{
        crypto::{encrypt_entries, decrypt_entries},
        storage::{read_vault_file, write_vault_file},
    },
    error::{Error, Result},
    model::{DEFAULT_VAULT_ENTRY, Entries, Entry, Vault, VaultHeader, ServiceList},
};
use aes_gcm::{Aes256Gcm, Key};
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

fn create_empty_vault(
    key: &Key<Aes256Gcm>,
    magic: [u8; 4],
    version: [u8; 2],
    salt: [u8; 16],
) -> Result<Vault> {
    let header = VaultHeader::new(magic, version, salt);

    let sealed = encrypt_entries(
        key,
        &Entries::new(vec![Entry::new(
            DEFAULT_VAULT_ENTRY.0.to_string(),
            DEFAULT_VAULT_ENTRY.1.to_string(),
            DEFAULT_VAULT_ENTRY.2.to_string(),
        )]),
        &header,
    )?;

    Ok(Vault::new(header, sealed))
}

/// TODO
pub fn get_salt(vault_path: &Path) -> Result<[u8; 16]> {
    let vault = read_vault_file(vault_path)?;

    Ok(*vault.header().salt())
}

/// TODO
pub fn init(
    vault_path: &Path,
    overwrite: bool,
    key: &Key<Aes256Gcm>,
    magic: [u8; 4],
    version: [u8; 2],
    salt: [u8; 16],
) -> Result<()> {
    let vault = create_empty_vault(key, magic, version, salt)?;

    write_vault_file(vault_path, &vault, overwrite)
}

/// TODO
pub fn list(vault_path: &Path, key: &Key<Aes256Gcm>) -> Result<Zeroizing<ServiceList>> {
    let vault = read_vault_file(vault_path)?;
    let entries = decrypt_entries(key, vault.sealed(), vault.header())?;

    Ok(Zeroizing::new(ServiceList::new(entries.get_services()))) // Does this get_services create a zeroization issue with its copying?
}

fn empty_string_error(s: &str, e: Error) -> Result<()> {
    if s.is_empty() { Err(e) } else { Ok(()) }
}

/// TODO
pub fn get(
    vault_path: &Path,
    key: &Key<Aes256Gcm>,
    service: Zeroizing<String>,
) -> Result<Zeroizing<Entry>> {
    empty_string_error(&service, Error::InvalidServiceName)?;

    let vault = read_vault_file(vault_path)?;
    let entries = decrypt_entries(key, vault.sealed(), vault.header())?;

    let entry = entries
        .get_entry_by_service(&service)
        .ok_or(Error::ServiceNotFound)?;

    Ok(Zeroizing::new(Entry::new(
        service.to_string(),
        entry.username().to_string(),
        entry.password().to_string(),
    )))
}

/// TODO
pub fn add(
    vault_path: &Path,
    key: &Key<Aes256Gcm>,
    service: Zeroizing<String>,
    username: Zeroizing<String>,
    password: Zeroizing<String>,
) -> Result<()> {
    empty_string_error(&service, Error::InvalidServiceName)?;
    empty_string_error(&username, Error::InvalidUsername)?;
    empty_string_error(&password, Error::InvalidPassword)?;

    let vault = read_vault_file(vault_path)?;
    let header = vault.header();
    let mut entries = decrypt_entries(key, vault.sealed(), header)?;

    entries
        .get_entry_by_service(&service)
        .map(|_| Error::ServiceAlreadyExists)
        .map_or(Ok(()), Err)?;

    entries.add_entry(
        service.to_string(),
        username.to_string(),
        password.to_string(),
    );

    let updated_vault = Vault::new(
        VaultHeader::new(*header.magic(), *header.version(), *header.salt()),
        encrypt_entries(key, &entries, header)?,
    );

    write_vault_file(vault_path, &updated_vault, true)?;

    Ok(())
}

/// TODO
pub fn delete(vault_path: &Path, key: &Key<Aes256Gcm>, service: Zeroizing<String>) -> Result<()> {
    empty_string_error(&service, Error::InvalidServiceName)?;

    let vault = read_vault_file(vault_path)?;
    let header = vault.header();
    let mut entries = decrypt_entries(key, vault.sealed(), header)?;

    entries
        .get_entry_by_service(&service)
        .ok_or(Error::ServiceNotFound)?;

    entries.remove_entry_by_service(&service);

    let updated_vault = Vault::new(
        VaultHeader::new(*header.magic(), *header.version(), *header.salt()),
        encrypt_entries(key, &entries, header)?,
    );

    write_vault_file(vault_path, &updated_vault, true)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        core::{crypto::decrypt_entries, storage::read_vault_file},
        model::VAULT_MAGIC,
    };

    use aes_gcm::{
        Aes256Gcm,
        aead::{Generate, Key},
    };
    use argon2::password_hash::generate_salt;

    fn create_relative_path(test_name: &str) -> std::path::PathBuf {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join(test_name)
            .with_extension("txt");

        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }

        std::fs::create_dir_all(path.parent().unwrap()).unwrap();

        path
    }

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
    fn test_create_empty_vault_ok() {
        let key = Key::<Aes256Gcm>::generate();
        let magic = VAULT_MAGIC;
        let version = [0x00; 0x02];
        let salt = generate_salt();

        let vault = create_empty_vault(&key, magic, version, salt).unwrap();
        let entries = decrypt_entries(&key, vault.sealed(), vault.header()).unwrap();

        let expected_entries = Entries::new(vec![Entry::new(
            DEFAULT_VAULT_ENTRY.0.to_string(),
            DEFAULT_VAULT_ENTRY.1.to_string(),
            DEFAULT_VAULT_ENTRY.2.to_string(),
        )]);

        assert_eq!(vault.header().magic(), &magic);
        assert_eq!(vault.header().version(), &version);
        assert_eq!(entries, expected_entries.into());
    }

    #[test]
    fn test_init_overwrite() {
        let path = create_relative_path("test_init_overwrite");

        let key = Key::<Aes256Gcm>::generate();
        let magic = VAULT_MAGIC;
        let version = [0x00; 0x02];
        let salt = generate_salt();

        init(&path, true, &key, magic, version, salt).unwrap();

        let vault = read_vault_file(&path).unwrap();
        let entries = decrypt_entries(&key, vault.sealed(), vault.header()).unwrap();

        let expected_entries = Entries::new(vec![Entry::new(
            DEFAULT_VAULT_ENTRY.0.to_string(),
            DEFAULT_VAULT_ENTRY.1.to_string(),
            DEFAULT_VAULT_ENTRY.2.to_string(),
        )]);

        assert_eq!(vault.header().magic(), &magic);
        assert_eq!(vault.header().version(), &version);
        assert_eq!(entries, expected_entries.into());
    }

    #[test]
    fn test_init_no_overwrite() {
        let path = create_relative_path("test_init_no_overwrite");

        let key = Key::<Aes256Gcm>::generate();
        let magic = VAULT_MAGIC;
        let version = [0x00; 0x02];
        let salt = generate_salt();

        init(&path, false, &key, magic, version, salt).unwrap();

        let vault = read_vault_file(&path).unwrap();
        let entries = decrypt_entries(&key, vault.sealed(), vault.header()).unwrap();

        let expected_entries = Entries::new(vec![Entry::new(
            DEFAULT_VAULT_ENTRY.0.to_string(),
            DEFAULT_VAULT_ENTRY.1.to_string(),
            DEFAULT_VAULT_ENTRY.2.to_string(),
        )]);

        assert_eq!(vault.header().magic(), &magic);
        assert_eq!(vault.header().version(), &version);
        assert_eq!(entries, expected_entries.into());
    }

    #[test]
    fn test_empty_string_error() {
        assert_eq!(
            empty_string_error("hello", Error::InvalidPassword).unwrap(),
            ()
        );
        assert!(matches!(
            empty_string_error("", Error::InvalidServiceName).unwrap_err(),
            Error::InvalidServiceName
        ));
        assert!(matches!(
            empty_string_error("", Error::InvalidUsername).unwrap_err(),
            Error::InvalidUsername
        ));
        assert!(matches!(
            empty_string_error("", Error::InvalidPassword).unwrap_err(),
            Error::InvalidPassword
        ));
    }

    #[test]
    fn test_list() {
        let path = create_relative_path("test_list");

        let key = Key::<Aes256Gcm>::generate();
        let magic = VAULT_MAGIC;
        let version = [0x00; 0x02];
        let salt = generate_salt();

        init(&path, false, &key, magic, version, salt).unwrap();
        let services1 = list(&path, &key).unwrap();
        let expected_services1 = ServiceList::new(vec!["".to_string()]);

        add(
            &path,
            &key,
            "gmail".to_string().into(),
            "mikey123".to_string().into(),
            "$dog29!".to_string().into(),
        )
        .unwrap();
        let services2 = list(&path, &key).unwrap();
        let expected_services2 = ServiceList::new(vec!["".to_string(), "gmail".to_string()]);

        add(
            &path,
            &key,
            "outlook".to_string().into(),
            "jbhockeyfan@gmail.com".to_string().into(),
            "rang3rsFanNY?".to_string().into(),
        )
        .unwrap();
        let services3 = list(&path, &key).unwrap();
        let expected_services3 = ServiceList::new(vec![
            "".to_string(),
            "gmail".to_string(),
            "outlook".to_string(),
        ]);

        assert_eq!(
            services1.services().len(),
            expected_services1.services().len()
        );
        assert_eq!(services1, expected_services1.into());

        assert_eq!(
            services2.services().len(),
            expected_services2.services().len()
        );
        assert_eq!(services2, expected_services2.into());

        assert_eq!(
            services3.services().len(),
            expected_services3.services().len()
        );
        assert_eq!(services3, expected_services3.into());
    }

    #[test]
    fn test_get() {
        let path = create_relative_path("test_get");

        let key = Key::<Aes256Gcm>::generate();
        let magic = VAULT_MAGIC;
        let version = [0x00; 0x02];
        let salt = generate_salt();
        let service1 = "gmail";
        let service2 = "outlook";
        let entries = Entries::new(vec![
            Entry::new(
                service1.to_string(),
                "mikey123".to_string(),
                "$dog29!".to_string(),
            ),
            Entry::new(
                service2.to_string(),
                "jbhockeyfan@gmail.com".to_string(),
                "rang3rsFanNY?".to_string(),
            ),
        ]);

        let header = VaultHeader::new(magic, version, salt);
        let sealed = encrypt_entries(&key, &entries, &header).unwrap();
        let vault = Vault::new(header, sealed);

        let err1 = get(&path, &key, service1.to_string().into()).unwrap_err();

        write_vault_file(&path, &vault, false).unwrap();

        let entry1 = get(&path, &key, service1.to_string().into()).unwrap();
        let entry2 = get(&path, &key, service2.to_string().into()).unwrap();

        let expected_entry1 = Entry::new(
            service1.to_string(),
            "mikey123".to_string(),
            "$dog29!".to_string(),
        );
        let expected_entry2 = Entry::new(
            service2.to_string(),
            "jbhockeyfan@gmail.com".to_string(),
            "rang3rsFanNY?".to_string(),
        );

        let err2 = get(&path, &key, "nonexistant".to_string().into()).unwrap_err();
        let err3 = get(&path, &key, "".to_string().into()).unwrap_err();

        assert_eq!(entry1, expected_entry1.into());
        assert_eq!(entry2, expected_entry2.into());
        assert!(matches!(err1, Error::StdIo(_)));
        assert!(matches!(err2, Error::ServiceNotFound));
        assert!(matches!(err3, Error::InvalidServiceName));
    }

    #[test]
    fn test_add() {
        let path = create_relative_path("test_add");

        let key = Key::<Aes256Gcm>::generate();
        let magic = VAULT_MAGIC;
        let version = [0x00; 0x02];
        let salt = generate_salt();
        let service1 = "gmail";
        let service2 = "outlook";
        let username1 = "pabloT27";
        let username2 = "airplaneFan@outlook.com";
        let password1 = "!!00927hDj298Sk39jc!!?p";
        let password2 = "GaRlic2002$";

        let err1 = add(
            &path,
            &key,
            service1.to_string().into(),
            username1.to_string().into(),
            password1.to_string().into(),
        )
        .unwrap_err();

        init(&path, false, &key, magic, version, salt).unwrap();

        add(
            &path,
            &key,
            service1.to_string().into(),
            username1.to_string().into(),
            password1.to_string().into(),
        )
        .unwrap();
        add(
            &path,
            &key,
            service2.to_string().into(),
            username2.to_string().into(),
            password2.to_string().into(),
        )
        .unwrap();

        let vault = read_vault_file(&path).unwrap();

        let entries = decrypt_entries(&key, vault.sealed(), vault.header()).unwrap();

        let expected_entries = Entries::new(vec![
            Entry::new(
                DEFAULT_VAULT_ENTRY.0.to_string(),
                DEFAULT_VAULT_ENTRY.1.to_string(),
                DEFAULT_VAULT_ENTRY.2.to_string(),
            ),
            Entry::new(
                service1.to_string(),
                username1.to_string(),
                password1.to_string(),
            ),
            Entry::new(
                service2.to_string(),
                username2.to_string(),
                password2.to_string(),
            ),
        ]);

        let err2 = add(
            &path,
            &key,
            "".to_string().into(),
            username1.to_string().into(),
            password1.to_string().into(),
        )
        .unwrap_err();
        let err3 = add(
            &path,
            &key,
            service1.to_string().into(),
            "".to_string().into(),
            password1.to_string().into(),
        )
        .unwrap_err();
        let err4 = add(
            &path,
            &key,
            service1.to_string().into(),
            username1.to_string().into(),
            "".to_string().into(),
        )
        .unwrap_err();
        let err5 = add(
            &path,
            &key,
            "".to_string().into(),
            "".to_string().into(),
            "".to_string().into(),
        )
        .unwrap_err();
        let err6 = add(
            &path,
            &key,
            service1.to_string().into(),
            username1.to_string().into(),
            password1.to_string().into(),
        )
        .unwrap_err();

        assert_eq!(vault.header().magic(), &magic);
        assert_eq!(vault.header().version(), &version);
        assert_eq!(entries.entries().len(), expected_entries.entries().len());
        assert_eq!(entries, expected_entries.into());
        assert!(matches!(err1, Error::StdIo(_)));
        assert!(matches!(err2, Error::InvalidServiceName));
        assert!(matches!(err3, Error::InvalidUsername));
        assert!(matches!(err4, Error::InvalidPassword));
        assert!(matches!(err5, Error::InvalidServiceName));
        assert!(matches!(err6, Error::ServiceAlreadyExists));
    }

    #[test]
    fn test_delete() {
        let path = create_relative_path("test_delete");

        let key = Key::<Aes256Gcm>::generate();
        let magic = VAULT_MAGIC;
        let version = [0x00; 0x02];
        let salt = generate_salt();
        let service1 = "gmail";
        let service2 = "outlook";

        let err1 = delete(&path, &key, service1.to_string().into()).unwrap_err();

        init(&path, false, &key, magic, version, salt).unwrap();
        add(
            &path,
            &key,
            service1.to_string().into(),
            "mikey123".to_string().into(),
            "$dog29!".to_string().into(),
        )
        .unwrap();
        add(
            &path,
            &key,
            service2.to_string().into(),
            "jbhockeyfan@gmail.com".to_string().into(),
            "rang3rsFanNY?".to_string().into(),
        )
        .unwrap();

        let err2 = delete(&path, &key, "nonexistant".to_string().into()).unwrap_err();
        let err3 = delete(&path, &key, "".to_string().into()).unwrap_err();

        delete(&path, &key, service1.to_string().into()).unwrap();
        let vault1 = read_vault_file(&path).unwrap();
        let entries1 = decrypt_entries(&key, vault1.sealed(), vault1.header()).unwrap();
        let expected_entries1 = Entries::new(vec![
            Entry::new(
                DEFAULT_VAULT_ENTRY.0.to_string(),
                DEFAULT_VAULT_ENTRY.1.to_string(),
                DEFAULT_VAULT_ENTRY.2.to_string(),
            ),
            Entry::new(
                service2.to_string(),
                "jbhockeyfan@gmail.com".to_string(),
                "rang3rsFanNY?".to_string(),
            ),
        ]);

        delete(&path, &key, service2.to_string().into()).unwrap();
        let vault2 = read_vault_file(&path).unwrap();
        let entries2 = decrypt_entries(&key, vault2.sealed(), vault2.header()).unwrap();
        let expected_entries2 = Entries::new(vec![Entry::new(
            DEFAULT_VAULT_ENTRY.0.to_string(),
            DEFAULT_VAULT_ENTRY.1.to_string(),
            DEFAULT_VAULT_ENTRY.2.to_string(),
        )]);

        let err4 = delete(&path, &key, service1.to_string().into()).unwrap_err();

        assert_eq!(vault1.header().magic(), &magic);
        assert_eq!(vault1.header().version(), &version);
        assert_eq!(entries1.entries().len(), expected_entries1.entries().len());
        assert_eq!(entries1, expected_entries1.into());

        assert_eq!(vault2.header().magic(), &magic);
        assert_eq!(vault2.header().version(), &version);
        assert_eq!(entries2.entries().len(), expected_entries2.entries().len());
        assert_eq!(entries2, expected_entries2.into());

        assert!(matches!(err1, Error::StdIo(_)));
        assert!(matches!(err2, Error::ServiceNotFound));
        assert!(matches!(err3, Error::InvalidServiceName));
        assert!(matches!(err4, Error::ServiceNotFound));
    }
}
