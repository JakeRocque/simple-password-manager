//! TODO

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::model::{FOLDER_NAME, VAULT_HEADER_LEN, Vault, VaultHeader};

/// TODO
pub fn vault_path() -> Result<PathBuf> {
    let data_dir = dirs::data_local_dir().ok_or(Error::DataLocalDirNotFound)?;

    Ok(data_dir.join(FOLDER_NAME).join("vault.txt"))
}

/// TODO
pub fn custom_path_dir_to_path(path: &Path) -> Result<PathBuf> {
    if !path.is_dir() {
        return Err(Error::PathNotDir);
    }

    Ok(path.join(FOLDER_NAME).join("vault.txt"))
}

fn create_dir_all(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::StdIo)?;
    }

    Ok(())
}

fn write_file(path: &Path, data: &[u8], overwrite: bool, parent_dirs: bool) -> Result<()> {
    if parent_dirs {
        create_dir_all(path)?;
    }

    let mut file = if overwrite {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(Error::StdIo)?
    } else {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(Error::StdIo)?
    };

    file.write_all(data).map_err(Error::StdIo)?;

    Ok(())
}

/// TODO
pub fn write_vault_file(
    path: &Path,
    vault: &Vault,
    overwrite: bool,
    parent_dirs: bool,
) -> Result<()> {
    let mut serialized_vault = Vec::new();

    serialized_vault.extend_from_slice(&vault.header().to_bytes());
    serde_json::to_writer(&mut serialized_vault, vault.sealed()).map_err(Error::SerdeJson)?; // TODO - can/should this line be tested?

    write_file(path, &serialized_vault, overwrite, parent_dirs)
}

fn read_file(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).map_err(Error::StdIo)
}

/// TODO
pub fn read_vault_file(path: &Path) -> Result<Vault> {
    let serialized_vault = read_file(path)?;

    if serialized_vault.len() < VAULT_HEADER_LEN {
        return Err(Error::VaultHeaderInvalid);
    }

    let header = VaultHeader::from_bytes(
        serialized_vault[..VAULT_HEADER_LEN]
            .try_into()
            .or(Err(Error::VaultHeaderDeserializationFailed))?,
    );
    let sealed =
        serde_json::from_slice(&serialized_vault[VAULT_HEADER_LEN..]).map_err(Error::SerdeJson)?; // TODO - can/should this line be tested?

    Ok(Vault::new(header, sealed))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use aes_gcm::{
        Aes256Gcm,
        aead::{Generate, Key},
    };
    use argon2::password_hash::generate_salt;

    use crate::{
        core::crypto::encrypt_entries,
        error::Error::{SerdeJson, StdIo},
        model::{Entries, Entry, VAULT_MAGIC, VaultHeader},
    };

    use super::*;

    fn create_relative_path(test_name: &str) -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join(test_name);

        if dir.exists() {
            fs::remove_dir_all(&dir).unwrap();
        }

        fs::create_dir_all(&dir).unwrap();

        dir.join("test.txt")
    }

    fn create_relative_path_no_parent(test_name: &str) -> std::path::PathBuf {
        create_relative_path(test_name)
            .join("nonexistent")
            .join("file.txt")
    }

    #[test]
    fn test_vault_path_ok() {
        let path = dirs::data_local_dir()
            .unwrap()
            .join(FOLDER_NAME)
            .join("vault")
            .with_extension("txt");

        assert_eq!(vault_path().unwrap(), path)
    }

    #[test]
    fn test_custom_path_to_dir() {
        let custom_dir = create_relative_path("test_custom_path_to_dir")
            .parent()
            .unwrap()
            .to_path_buf();

        let path = custom_dir
            .join(FOLDER_NAME)
            .join("vault")
            .with_extension("txt");

        assert_eq!(custom_path_dir_to_path(&custom_dir).unwrap(), path);
    }

    #[test]
    fn test_create_dir_all_() {
        let path = create_relative_path_no_parent("test_create_dir_all_");

        create_dir_all(&path).unwrap();

        assert!(path.parent().unwrap().exists())
    }

    #[test]
    fn test_write_file_read_file_roundtrip() {
        let path = create_relative_path("test_write_file_read_file_roundtrip");
        let data = b"Welcome to the information age.";

        write_file(&path, &data.to_vec(), false, false).unwrap();
        let result = read_file(&path).unwrap();

        assert_eq!(result, data);
    }

    #[test]
    fn test_write_file_read_file_roundtrip_empty() {
        let path = create_relative_path("test_write_file_read_file_roundtrip_empty");
        let data = b"";

        write_file(&path, &data.to_vec(), false, false).unwrap();
        let result = read_file(&path).unwrap();

        assert_eq!(result, data);
    }

    #[test]
    fn test_write_file_path_already_exists() {
        let path = create_relative_path("test_write_file_path_already_exists");
        let data1 = b"Welcome to the information age.";
        let data2 = b"This should not overwrite the message.";

        write_file(&path, &data1.to_vec(), false, false).unwrap();

        let err = write_file(&path, &data2.to_vec(), false, false).unwrap_err();
        let result = read_file(&path).unwrap();

        assert!(matches!(err, StdIo(_)));
        assert_eq!(result, data1);
    }

    #[test]
    fn test_write_file_path_already_exists_overwrite() {
        let path = create_relative_path("test_write_file_path_overwrite");
        let data1 = b"Welcome to the information age.";
        let data2 = b"This should overwrite the message.";

        write_file(&path, &data1.to_vec(), false, false).unwrap();
        write_file(&path, &data2.to_vec(), true, false).unwrap();

        let result = read_file(&path).unwrap();

        assert_eq!(result, data2);
    }

    #[test]
    fn test_write_file_path_doesnt_already_exist_overwrite() {
        let path = create_relative_path("test_write_file_path_doesnt_already_exist_overwrite");
        let data = b"Welcome to the information age.";

        write_file(&path, &data.to_vec(), true, false).unwrap();

        let result = read_file(&path).unwrap();

        assert_eq!(result, data);
    }

    #[test]
    fn test_write_file_create_parent_dir_fail() {
        let path = create_relative_path_no_parent("test_write_file_create_parent_dir_fail");
        let data = b"Welcome to the information age.";

        let err = write_file(&path, &data.to_vec(), true, false).unwrap_err();

        assert!(matches!(err, Error::StdIo(_)));
    }

    #[test]
    fn test_write_file_ok_create_parent_dir() {
        let path = create_relative_path_no_parent("test_write_file_ok_create_parent_dir");
        let data = b"Welcome to the information age.";

        write_file(&path, &data.to_vec(), true, true).unwrap();

        let result = read_file(&path).unwrap();

        assert_eq!(result, data);
    }

    #[test]
    fn test_read_vault_file_non_vault_file() {
        let path = create_relative_path("test_read_file_non_vault_file");
        let data = b"Welcome to the information age.";

        fs::write(&path, data).unwrap();

        let err = read_vault_file(&path).unwrap_err();

        assert!(matches!(err, SerdeJson(_)));
    }

    #[test]
    fn test_read_vault_file_less_than_min_size() {
        let path = create_relative_path("test_read_vault_file_less_than_min_size");
        let data = b"Welcome.";

        fs::write(&path, data).unwrap();

        let err = read_vault_file(&path).unwrap_err();

        assert!(matches!(err, Error::VaultHeaderInvalid));
    }

    #[test]
    fn test_write_vault_file_read_vault_file_roundtrip() {
        let path = create_relative_path("test_write_vault_file_read_vault_file_roundtrip");

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
        let vault = Vault::new(
            VaultHeader::new(VAULT_MAGIC, [0x00, 0x03], generate_salt()),
            sealed,
        );

        write_vault_file(&path, &vault, false, false).unwrap();
        let result = read_vault_file(&path).unwrap();

        assert_eq!(result, vault);
    }
}
