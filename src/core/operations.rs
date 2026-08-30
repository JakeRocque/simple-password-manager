//! TODO

use std::path::Path;

use crate::{
    core::{
        crypto::decrypt_entries,
        storage::{read_vault_file, write_vault_file},
    },
    error::{Error, Result},
    model::{DEFAULT_VAULT_ENTRY, Sealed, ServiceList},
};
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
pub fn init(
    vault_path: &Path,
    overwrite: bool,
    key: &Key<Aes256Gcm>,
    magic: [u8; 4],
    version: [u8; 2],
) -> Result<()> {
    let vault = create_empty_vault(key, magic, version)?;

    write_vault_file(vault_path, &vault, overwrite)
}

/// TODO
pub fn list(vault_path: &Path, key: &Key<Aes256Gcm>) -> Result<ServiceList> {
    !todo!()
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
    use argon2::password_hash::Error::SaltInvalid;
    use clap::ArgAction::Append;

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
    fn test_create_empty_vault_ok() {
        let key = Key::<Aes256Gcm>::generate();
        let magic = VAULT_MAGIC;
        let version = [0x00; 0x02];

        let vault = create_empty_vault(&key, magic, version).unwrap();
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

        init(&path, true, &key, magic, version).unwrap();

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

        init(&path, false, &key, magic, version).unwrap();

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

        init(&path, false, &key, magic, version).unwrap();

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

        init(&path, false, &key, magic, version).unwrap();
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
