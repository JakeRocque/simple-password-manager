//! Core data models and constants
//!
//! This module defines the data structures and their implementations to manage
//! a vault file and its components as well as constants.

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const FOLDER_NAME: &str = "JakeysPasswordVault";
pub const VAULT_MAGIC: [u8; 4] = [0x3b, 0xd0, 0x07, 0xbd];
pub const VAULT_HEADER_LEN: usize = 22;
pub const DEFAULT_VAULT_ENTRY: (&str, &str, &str) = ("", "SALVE,", "PLVRIMVM");

pub const BANNER: &str = r"
       _       _              _       _____                                    _  __      __         _ _   
      | |     | |            ( )     |  __ \                                  | | \ \    / /        | | |  
      | | __ _| | _____ _   _|/ ___  | |__) |_ _ ___ _____      _____  _ __ __| |  \ \  / /_ _ _   _| | |_ 
  _   | |/ _` | |/ / _ \ | | | / __| |  ___/ _` / __/ __\ \ /\ / / _ \| '__/ _` |   \ \/ / _` | | | | | __|
 | |__| | (_| |   <  __/ |_| | \__ \ | |  | (_| \__ \__ \\ V  V / (_) | | | (_| |    \  / (_| | |_| | | |_ 
  \____/ \__,_|_|\_\___|\__, | |___/ |_|   \__,_|___/___/ \_/\_/ \___/|_|  \__,_|     \/ \__,_|\__,_|_|\__|
                         __/ |                                                                             
                        |___/                                                                              
";

/// A vault header which contains all metadata about the vault.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct VaultHeader {
    /// A 4-byte magic indicating that the file is a JakeysPassWordVault vault.
    magic: [u8; 4],
    /// A 2-byte version identifier for this vault.
    version: [u8; 2],
    /// A 16-byte, random, unique value used to hash this vault's master password.
    salt: [u8; 16],
}

/// Encrypted ciphertext and nonce used for that encryption.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Sealed {
    /// 12-byte nonce used for encryption.
    nonce: [u8; 12],
    /// The encrypted ciphertext.
    ciphertext: Vec<u8>, //  AES-GCM ciphertext & authentication tag
}

/// A vault which contains a vault header and an encrypted blob.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Vault {
    /// Vault's [`VaultHeader`].
    header: VaultHeader,
    /// Vault's [`Sealed`]
    sealed: Sealed,
}

/// A single entry in the password vault.
#[derive(PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop, Zeroize)]
pub struct Entry {
    /// Service name in this entry.
    service: String,
    /// Username in this entry.
    username: String,
    /// Password in this entry.
    password: String,
}

/// A collection of password vault entries.
#[derive(PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop, Zeroize)]
pub struct Entries {
    /// Vector of entries in this [`Entries`]
    entries: Vec<Entry>,
}

/// A collection of password vault entry service names.
#[derive(Serialize, PartialEq, Eq, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ServiceList {
    /// Vector of service names in this [`ServiceList`]
    services: Vec<String>,
}

impl VaultHeader {
    /// Creates a vault header with the given magic, version, and salt.
    pub fn new(magic: [u8; 4], version: [u8; 2], salt: [u8; 16]) -> Self {
        Self {
            magic,
            version,
            salt,
        }
    }

    /// Get the magic bytes of this [`VaultHeader`]
    pub fn magic(&self) -> &[u8; 4] {
        &self.magic
    }

    /// Get the version of this [`VaultHeader`]
    pub fn version(&self) -> &[u8; 2] {
        &self.version
    }

    /// Get the salt of this [`VaultHeader`]
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// Serializes this [`VaultHeader`] into a 22-byte representation.
    ///
    /// The layout is:
    /// - bytes 0..4: magic
    /// - bytes 4..6: version
    /// - bytes 6..22: salt
    pub fn to_bytes(&self) -> [u8; VAULT_HEADER_LEN] {
        let mut out = [0u8; VAULT_HEADER_LEN];

        out[0..4].copy_from_slice(&self.magic);
        out[4..6].copy_from_slice(&self.version);
        out[6..22].copy_from_slice(&self.salt);

        out
    }

    /// Convert a 22-byte slice to a [`VaultHeader`]
    ///
    /// The expected layout is:
    /// - bytes 0..4: magic
    /// - bytes 4..6: version
    /// - bytes 6..22: salt
    pub fn from_bytes(bytes: &[u8; VAULT_HEADER_LEN]) -> Self {
        let mut magic = [0u8; 4];
        let mut version = [0u8; 2];
        let mut salt = [0u8; 16];

        magic.copy_from_slice(&bytes[0..4]);
        version.copy_from_slice(&bytes[4..6]);
        salt.copy_from_slice(&bytes[6..22]);

        Self {
            magic,
            version,
            salt,
        }
    }
}

impl Sealed {
    /// Creates a ciphertext and nonce pair with the given nonce and ciphertext.
    pub fn new(nonce: [u8; 12], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// Get the nonce of this [`Sealed`]
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Get the ciphertext of this [`Sealed`]
    pub fn ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext
    }
}

impl Vault {
    /// Creates a vault with the given vault header and sealed blob.
    pub fn new(header: VaultHeader, sealed: Sealed) -> Self {
        Self { header, sealed }
    }

    /// Get the [`VaultHeader`] of this [`Vault`]
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Get the [`Sealed`] of this [`Vault`]
    pub fn sealed(&self) -> &Sealed {
        &self.sealed
    }
}

impl Entry {
    /// Creates a password manager entry with the given service name, username, and password.
    pub fn new(service: String, username: String, password: String) -> Self {
        Self {
            service,
            username,
            password,
        }
    }

    /// Convert this [`Entry`] to a CLI friendly string.
    pub fn to_cli_string(&self, show_password: bool) -> String {
        let password = if show_password {
            &self.password.to_string()
        } else {
            "[REDACTED]"
        };

        format!(
            "{}\n{}\nUsername: {}\nPassword: {}",
            self.service,
            "-".repeat(self.service.len()),
            self.username,
            password,
        )
    }

    /// Get the service of this [`Entry`]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Get the username of this [`Entry`]
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Get the password of this [`Entry`]
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("debug", &"[REDACTED]")
            .finish()
    }
}

impl Entries {
    /// Creates a collection of password manager entries with the given entries.
    pub fn new(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// Get collection of entries of this [`Entries`]
    #[allow(dead_code)]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Get the vector of service names from this [`Entries`]
    pub fn get_services(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|e| e.service().to_string())
            .collect()
    }

    /// Get [`Entry`] with the given service name if it exists in this [`Entries`].
    ///
    /// # Returns
    ///
    /// The [`Entry`] containing the given service, or [`None`] if none do.
    pub fn get_entry_by_service(&self, service: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.service() == service)
    }

    /// Add [`Entry`] to this [`Entries`] with the given service name, username, and password.
    pub fn add_entry(&mut self, service: String, username: String, password: String) {
        self.entries.push(Entry::new(service, username, password))
    }

    /// Remove [`Entry`] with the given service name from this [`Entries`] if it exists.
    ///
    /// # Returns
    ///
    /// The removed [`Entry`] containing the given service, or [`None`] if none do.
    pub fn remove_entry_by_service(&mut self, service: &str) -> Option<Entry> {
        let idx = self
            .entries
            .iter()
            .position(|entry| entry.service() == service)?;

        Some(self.entries.remove(idx))
    }
}

impl fmt::Debug for Entries {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entries")
            .field("debug", &"[REDACTED]")
            .finish()
    }
}

impl ServiceList {
    /// Creates a collection of password manager entry service names with the given service names.
    pub fn new(services: Vec<String>) -> Self {
        Self { services }
    }

    /// Convert this [`ServiceList`] to a CLI friendly string.
    pub fn to_cli_string(&self) -> String {
        format!(
            "{}\n{}\n{}",
            "Services",
            "-".repeat("Services".len()),
            self.services
                .iter()
                .filter(|s| !s.is_empty()) // remove the default entry
                .cloned()
                .collect::<Vec<String>>()
                .join("\n")
        )
    }

    /// Get the vector of service names of this [`ServiceList`]
    #[allow(dead_code)]
    pub fn services(&self) -> &[String] {
        &self.services
    }
}

impl fmt::Debug for ServiceList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServiceList")
            .field("debug", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use argon2::password_hash::generate_salt;

    #[test]
    fn test_to_bytes_from_bytes_round_trip() {
        let header = VaultHeader::new(VAULT_MAGIC, [0x00, 0x01], generate_salt());

        assert_eq!(VaultHeader::from_bytes(&header.to_bytes()), header);
    }

    #[test]
    fn test_get_services() {
        assert_eq!(
            ServiceList::new(Entries::new(vec![]).get_services()),
            ServiceList::new(vec![])
        );

        assert_eq!(
            ServiceList::new(
                Entries::new(vec![Entry::new(
                    "github".to_string(),
                    "allab0uttheM3TS".to_string(),
                    "$Dec301988$".to_string()
                ),])
                .get_services()
            ),
            ServiceList::new(vec!["github".to_string()])
        );

        assert_eq!(
            ServiceList::new(
                Entries::new(vec![
                    Entry::new(
                        "github".to_string(),
                        "allab0uttheM3TS".to_string(),
                        "$Dec301988$".to_string()
                    ),
                    Entry::new(
                        "google".to_string(),
                        "3aglesAllDay".to_string(),
                        "Ph1llyFan17293?".to_string()
                    ),
                    Entry::new(
                        "chase".to_string(),
                        "Boston Red Sox".to_string(),
                        "Jul41776".to_string()
                    ),
                ])
                .get_services()
            ),
            ServiceList::new(vec![
                "github".to_string(),
                "google".to_string(),
                "chase".to_string()
            ])
        );
    }

    #[test]
    fn test_get_entry_by_service() {
        let entries = Entries::new(vec![
            Entry::new(
                "github".to_string(),
                "allab0uttheM3TS".to_string(),
                "$Dec301988$".to_string(),
            ),
            Entry::new(
                "google".to_string(),
                "3aglesAllDay".to_string(),
                "Ph1llyFan17293?".to_string(),
            ),
            Entry::new(
                "chase".to_string(),
                "Boston Red Sox".to_string(),
                "Jul41776".to_string(),
            ),
        ]);

        assert_eq!(
            entries.get_entry_by_service("google").unwrap(),
            &Entry::new(
                "google".to_string(),
                "3aglesAllDay".to_string(),
                "Ph1llyFan17293?".to_string()
            )
        );

        assert_eq!(entries.get_entry_by_service("youtube"), None);

        assert_eq!(Entries::new(vec![]).get_entry_by_service("google"), None);
    }

    #[test]
    fn test_add_entry() {
        let mut entries = Entries::new(vec![]);
        assert_eq!(entries.entries(), vec![]);

        entries.add_entry(
            "github".to_string(),
            "allab0uttheM3TS".to_string(),
            "$Dec301988$".to_string(),
        );
        assert_eq!(
            entries.entries(),
            vec![Entry::new(
                "github".to_string(),
                "allab0uttheM3TS".to_string(),
                "$Dec301988$".to_string()
            ),]
        );

        entries.add_entry(
            "google".to_string(),
            "3aglesAllDay".to_string(),
            "Ph1llyFan17293?".to_string(),
        );
        assert_eq!(
            entries.entries(),
            vec![
                Entry::new(
                    "github".to_string(),
                    "allab0uttheM3TS".to_string(),
                    "$Dec301988$".to_string()
                ),
                Entry::new(
                    "google".to_string(),
                    "3aglesAllDay".to_string(),
                    "Ph1llyFan17293?".to_string()
                ),
            ]
        );
    }

    #[test]
    fn test_remove_entry_by_service() {
        let mut entries = Entries::new(vec![
            Entry::new(
                "github".to_string(),
                "allab0uttheM3TS".to_string(),
                "$Dec301988$".to_string(),
            ),
            Entry::new(
                "google".to_string(),
                "3aglesAllDay".to_string(),
                "Ph1llyFan17293?".to_string(),
            ),
            Entry::new(
                "chase".to_string(),
                "Boston Red Sox".to_string(),
                "Jul41776".to_string(),
            ),
        ]);
        assert_eq!(
            entries.entries(),
            vec![
                Entry::new(
                    "github".to_string(),
                    "allab0uttheM3TS".to_string(),
                    "$Dec301988$".to_string()
                ),
                Entry::new(
                    "google".to_string(),
                    "3aglesAllDay".to_string(),
                    "Ph1llyFan17293?".to_string()
                ),
                Entry::new(
                    "chase".to_string(),
                    "Boston Red Sox".to_string(),
                    "Jul41776".to_string()
                ),
            ]
        );

        entries.remove_entry_by_service(&"github");
        assert_eq!(
            entries.entries(),
            vec![
                Entry::new(
                    "google".to_string(),
                    "3aglesAllDay".to_string(),
                    "Ph1llyFan17293?".to_string()
                ),
                Entry::new(
                    "chase".to_string(),
                    "Boston Red Sox".to_string(),
                    "Jul41776".to_string()
                ),
            ]
        );

        let none = entries.remove_entry_by_service(&"fortnite");
        assert_eq!(none, None);
        assert_eq!(
            entries.entries(),
            vec![
                Entry::new(
                    "google".to_string(),
                    "3aglesAllDay".to_string(),
                    "Ph1llyFan17293?".to_string()
                ),
                Entry::new(
                    "chase".to_string(),
                    "Boston Red Sox".to_string(),
                    "Jul41776".to_string()
                ),
            ]
        );

        entries.remove_entry_by_service(&"chase");
        assert_eq!(
            entries.entries(),
            vec![Entry::new(
                "google".to_string(),
                "3aglesAllDay".to_string(),
                "Ph1llyFan17293?".to_string()
            ),]
        );
    }
}
