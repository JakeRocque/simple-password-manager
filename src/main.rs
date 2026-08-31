//! TODO

// vault struct -> json -> bytes -> written to disk:
// header(22) + ciphertext(n)
// header:
// magic(4) + version(2) + salt(16)
// ciphertext:
// nonce + encrypted text & tag

// AES
// AES-256
// GCM
// AEAD
// nonce
// authentication tag
// AAD
// key generation
// nonce uniqueness
// key storage
// serialization

// SOURCES:
// crates: https://docs.rs/aes-gcm/latest/aes_gcm/#rustcrypto-aes-gcm, https://docs.rs/argon2/latest/argon2/, https://doc.rust-lang.org/std/fs/struct.OpenOptions.html#examples,
// https://doc.rust-lang.org/beta/std/fs/struct.File.html
//
// file read/write: https://github.com/bitwarden/clients/blob/c08787d1f2a43aea47fd134048a2b47de8e4f212/apps/cli/src/utils.ts#L132, OpenOptions and File crates

// STEPS:
// crypto:
// hash given password with unique, persisted salt and use that to generate a master key
// encrypt/decrypt entries using master key and AAD of the header. header contains all other info in file written on disk. it has no clock or counter and is vulnerable to rollback attacks.
//

// TODO:
// cli
// rust docs + comments
// main file level comment with explanations, details, crypto limits, sources, and process
// readme either copying or very similar to main file level comment

pub(crate) mod error;

mod cli;
mod core;
mod model;

fn main() {
    cli::run();
}
