//! TODO

use core::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const VAULT_MAGIC: [u8; 4] = [0x3b, 0xd0, 0x07, 0xbd];
pub const VAULT_HEADER_LEN: usize = 22;
pub const DEFAULT_VAULT_ENTRY: (&str, &str, &str) = ("", "SALVE,", "PLVRIMVM");

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct VaultHeader {
    magic: [u8; 4],
    version: [u8; 2],
    salt: [u8; 16],
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Sealed {
    nonce: [u8; 12],
    ciphertext: Vec<u8>, //  AES-GCM ciphertext & authentication tag
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct Vault {
    header: VaultHeader,
    sealed: Sealed,
}

#[derive(PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop, Zeroize)]
pub struct Entry {
    service: String,
    username: String,
    password: String,
}

#[derive(PartialEq, Eq, Serialize, Deserialize, ZeroizeOnDrop, Zeroize)]
pub struct Entries {
    entries: Vec<Entry>,
}

#[derive(Serialize, PartialEq, Eq, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ServiceList {
    services: Vec<String>,
}

impl VaultHeader {
    /// TODO
    pub fn new(magic: [u8; 4], version: [u8; 2], salt: [u8; 16]) -> Self {
        Self {
            magic,
            version,
            salt,
        }
    }

    /// TODO
    pub fn magic(&self) -> &[u8; 4] {
        &self.magic
    }

    /// TODO
    pub fn version(&self) -> &[u8; 2] {
        &self.version
    }

    /// TODO
    pub fn salt(&self) -> &[u8; 16] {
        &self.salt
    }

    /// TODO
    pub fn to_bytes(&self) -> [u8; VAULT_HEADER_LEN] {
        let mut out = [0u8; VAULT_HEADER_LEN];

        out[0..4].copy_from_slice(&self.magic);
        out[4..6].copy_from_slice(&self.version);
        out[6..22].copy_from_slice(&self.salt);

        out
    }

    /// TODO
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
    /// TODO
    pub fn new(nonce: [u8; 12], ciphertext: Vec<u8>) -> Self {
        Self { nonce, ciphertext }
    }

    /// TODO
    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// TODO
    pub fn ciphertext(&self) -> &Vec<u8> {
        &self.ciphertext
    }
}

impl Vault {
    /// TODO
    pub fn new(header: VaultHeader, sealed: Sealed) -> Self {
        Self { header, sealed }
    }

    /// TODO
    pub fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// TODO
    pub fn sealed(&self) -> &Sealed {
        &self.sealed
    }
}

impl Entry {
    /// TODO
    pub fn new(service: String, username: String, password: String) -> Self {
        Self {
            service: service,
            username: username,
            password: password,
        }
    }

    /// TODO
    pub fn to_cli_string(&self, show_password: bool) -> String {
        let password = if show_password {
            &self.password.to_string()
        } else {
            "[REDACTED]"
        };

        format!(
            "{}\n{}\nUsername: {}\nPassword: {}",
            self.service,
            "─".repeat(self.service.len()),
            self.username,
            password,
        )
    }

    /// TODO
    pub fn service(&self) -> &str {
        &self.service
    }

    /// TODO
    pub fn username(&self) -> &str {
        &self.username
    }

    /// TODO
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
    /// TODO
    pub fn new(entries: Vec<Entry>) -> Self {
        Self { entries }
    }

    /// TODO
    #[allow(dead_code)]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// TODO
    pub fn get_services(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|e| e.service().to_string())
            .collect()
    }

    /// TODO
    pub fn get_entry_by_service(&self, service: &str) -> Option<&Entry> {
        self.entries.iter().find(|entry| entry.service() == service)
    }

    /// TODO
    pub fn add_entry(&mut self, service: String, username: String, password: String) {
        self.entries.push(Entry::new(service, username, password))
    }

    /// TODO
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
    /// TODO
    pub fn new(services: Vec<String>) -> Self {
        Self { services }
    }

    /// TODO
    pub fn to_cli_string(&self) -> String {
        format!(
            "{}\n{}\n{}",
            "Services",
            "-".repeat("Services".len()),
            self.services.join("\n")
        )
    }

    /// TODO
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
