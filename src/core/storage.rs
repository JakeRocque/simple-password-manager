//! TODO

use std::io::{Write};
use std::path::Path;
use std::fs::OpenOptions;


use crate::{
    error::{Error, Result},
    model::{Entries, Sealed, VaultHeader},
};
use crate::model::Vault;

fn write_file(path: &Path, data: &[u8], overwrite: bool) -> Result<()> {
    let mut file = if overwrite {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path).map_err(Error::StdIo)?
    } else {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path).map_err(Error::StdIo)?
    };

    file.write_all(data).map_err(Error::StdIo)?;

    Ok(())
}

/// TODO
pub fn write_vault_file(path: &Path, vault: &Vault, overwrite: bool) -> Result<()> {
    let serialized_vault = serde_json::to_vec(vault).map_err(Error::SerdeJson)?;  // TODO - can/should this line be tested?

    write_file(path, &serialized_vault, overwrite)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(Error::StdIo)
}

/// TODO
pub fn read_vault_file(path: &Path) -> Result<Vault> {
    let serialized_vault = read_file(path)?;

    Ok(serde_json::from_slice(&serialized_vault).map_err(Error::SerdeJson)?)  // TODO - can/should this line be tested?
}

#[cfg(test)]
mod tests {
use aes_gcm::{
    Aes256Gcm,
    aead::{Generate, Key},
};
use argon2::password_hash::generate_salt;

use crate::{core::crypto::encrypt_entries, error::Error::StdIo, model::{Entry, VAULT_MAGIC}};

use super::*;

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
    fn test_write_file_read_file_roundtrip() {
        let path = create_relative_path("test_write_file_read_file_roundtrip");
        let data = b"Welcome to the information age.";

        write_file(&path, &data.to_vec(), false).unwrap();
        let result = read_file(&path).unwrap();

        assert_eq!(result, data);
    }

    #[test]
    fn test_write_file_read_file_roundtrip_emty() {
        let path = create_relative_path("test_write_file_read_file_roundtrip_emty");
        let data = b"";

        write_file(&path, &data.to_vec(), false).unwrap();
        let result = read_file(&path).unwrap();

        assert_eq!(result, data);
    }


    #[test]
    fn test_write_file_path_already_exists() {
        let path = create_relative_path("test_write_file_path_already_exists");
        let data1 = b"Welcome to the information age.";
        let data2 = b"This should not overwrite the message.";

        write_file(&path, &data1.to_vec(), false).unwrap();

        let err = write_file(&path, &data2.to_vec(), false).unwrap_err();
        let result = read_file(&path).unwrap();

        assert!(matches!(err, StdIo(_)));
        assert_eq!(result, data1);
    }

    #[test]
    fn test_write_file_path_already_exists_overwrite() {
        let path = create_relative_path("test_write_file_path_overwrite");
        let data1 = b"Welcome to the information age.";
        let data2 = b"This should overwrite the message.";

        write_file(&path, &data1.to_vec(), false).unwrap();
        write_file(&path, &data2.to_vec(), true).unwrap();
        
        let result = read_file(&path).unwrap();

        assert_eq!(result, data2);
    }

    #[test]
    fn test_write_file_path_doesnt_already_exist_overwrite() {
        let path = create_relative_path("test_write_file_path_doesnt_already_exist_overwrite");
        let data = b"Welcome to the information age.";

        write_file(&path, &data.to_vec(), true).unwrap();
        
        let result = read_file(&path).unwrap();

        assert_eq!(result, data);
    }

    #[test]
    fn test_write_vault_file_read_vault_file_roundtrip() {
        let path = create_relative_path("test_write_vault_file_read_vault_file_roundtrip");

        let key = Key::<Aes256Gcm>::generate();
        let entries = Entries::new(vec![
            Entry::new("mikey123", "$dog29!"),
            Entry::new("jbhockeyfan@gmail.com", "rang3rsFanNY?"),
        ]);
        let header = VaultHeader::new(VAULT_MAGIC, [0x00, 0x02], generate_salt());
        let sealed = encrypt_entries(&key, &entries, &header).unwrap();        
        let vault = Vault::new(VaultHeader::new(VAULT_MAGIC, [0x00, 0x03], generate_salt()), sealed);

        write_vault_file(&path, &vault, false).unwrap();
        let result = read_vault_file(&path).unwrap();

        assert_eq!(result, vault);
    }
}
