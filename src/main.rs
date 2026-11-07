//! Jakey's Password Vault: a minimal, local, command-line password manager.
//!
//! All entries (service, username, password) live in a single encrypted vault
//! file on disk. Nothing is sent over the network, and neither the master
//! password nor the encryption key is ever written to disk. The key is
//! re-derived from the master password every time a command runs.
//!
//! # Overview
//!
//! The crate is split into four modules:
//!
//! - [`cli`]: argument parsing (clap), master-password input, and output.
//! - [`core`]: the actual work, split into `crypto` (AES-256-GCM),
//!   `storage` (reading/writing the vault file), and `operations`
//!   (key derivation and the public init/list/get/add/delete operations).
//! - [`model`]: the vault data structures and constants.
//! - [`error`]: a single error type used throughout the crate.
//!
//! # Cryptography
//!
//! **Key derivation (Argon2id).** The master password is hashed with Argon2
//!   together with a random 16-byte salt to produce a 32-byte key. The salt is
//!   generated once when the vault is created and stored, unencrypted, in the
//!   vault header. Salts are not secret. their job is to make every vault's key
//!   unique even if two users pick the same password. This defeats
//!   precomputed (rainbow table) attacks. Argon2 ensures that any guess at the
//!   master password is expensive for an attacker.
//!
//! **Encryption (AES-256-GCM).** The derived key is used with AES-256 in
//!   Galois/Counter Mode. AES-256 is the block cipher. GCM turns it into an
//!   AEAD (Authenticated Encryption with Associated Data) scheme, meaning a
//!   single operation gives both:
//!
//! - *Encryption*: the entries can't be read without the key.
//! - *Authentication*: If the ciphertext is tampered with at all
//!   then decryption fails.
//!
//! **Nonces** Every encryption uses a fresh, random 12-byte (96-bit) nonce,
//!   stored next to the ciphertext. A nonce must never be reused.
//!
//! **Additional Authenticated Data (AAD).** The 22-byte vault header is
//!   passed to AES-GCM as AAD. It is stored in plaintext (it has to be, since
//!   the salt is needed to derive the key), but it is covered by the
//!   authentication tag. Between the AAD and actual encyrpted data,
//!   every single piece of data written to disk is authenticated.
//!
//! # Vault file format
//!
//! ```text
//! vault.txt = header (22 bytes, raw) || sealed (JSON, variable length)
//!
//! header:
//!   magic   4 bytes   0x3B 0xD0 0x07 0xBD, identifies the file as a vault
//!   version 2 bytes   big-endian u16, chosen at `init-vault`
//!   salt   16 bytes   random, used for Argon2 key derivation
//!
//! sealed (serde_json):
//!   { "nonce": [12 bytes], "ciphertext": [n + 16 bytes] }
//!   where ciphertext = AES-256-GCM(key, nonce, plaintext, aad = header)
//!   and the last 16 bytes are the authentication tag
//!
//! plaintext (serde_json, never written to disk):
//!   { "entries": [ { "service", "username", "password" }, ... ] }
//! ```
//!
//! By default the vault lives at `<local data dir>/JakeysPasswordVault/vault.txt`
//! (see the `default-location` command); `--path` points to a different
//! parent directory.
//!
//! # How It Works
//!
//! **`init-vault`**
//! 1. Generate a random 16-byte salt.
//! 2. Read the master password (interactive prompt strongly recommended,
//!    but can stdin with `--allow-piped`).
//! 3. Derive the key with Argon2 (password + salt).
//! 4. Build the header (magic, version, salt) and encrypt an entry list
//!    using the header as AAD.
//! 5. Write the file.
//!
//! **`list` / `get`**
//! 1. Read the vault file, check its length and magic, and parse the header.
//! 2. Read the master password and derive the key using the salt from the
//!    header.
//! 3. Decrypt and authenticate the entries using the header as AAD, then
//!    deserialize them.
//! 4. Print the service names, or the requested entry.
//!
//! **`add` / `delete`**
//! 1. Same as steps 1–3 above.
//! 2. Add or remove the entry in memory.
//! 3. Re-encrypt the full entry list with a fresh nonce and the same header.
//! 4. Write to a temporary file, `fsync` it, then rename it over the vault.
//!    The rename is atomic so a crash doesn't leave a half-written file.
//!
//! Sensitive values (master password, decrypted entries, intermediate byte
//! buffers) are wrapped in [`zeroize::Zeroizing`] or derive `ZeroizeOnDrop`,
//! so their memory is overwritten when they are dropped.
//!
//! # Limitations
//!
//! This is a learning project, not an audited tool. There are some known limits:
//!
//! - **Rollback attacks.** The header has no counter or timestamp, so an
//!   older copy of the vault is still a valid vault. Someone with
//!   write access to the file can silently restore an old version and it
//!   will decrypt without error (although if an attacker has write access,
//!   you have bigger issues).
//! - **Sizing.** The file size reveals roughly how much data the vault holds.
//! - **Memory zeroization is best-effort.** I can't guarantee rust never
//!   holds copies of sensitive data.
//!
//! # Sources (not comprehensive)
//!
//! Crates and standard library:
//! - <https://docs.rs/aes-gcm/latest/aes_gcm/#rustcrypto-aes-gcm>
//! - <https://docs.rs/argon2/latest/argon2/>
//! - <https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#examples>
//! - <https://doc.rust-lang.org/beta/std/fs/struct.File.html>
//!
//! File reading/writing:
//! - Bitwarden CLI: <https://github.com/bitwarden/clients/blob/c08787d1f2a43aea47fd134048a2b47de8e4f212/apps/cli/src/utils.ts#L132>
//!
//! Testing:
//! - <https://www.reddit.com/r/rust/comments/yfharn/write_tests_around_the_file_system/>

mod cli;
mod core;
mod error;
mod model;

fn main() {
    cli::run();
}
