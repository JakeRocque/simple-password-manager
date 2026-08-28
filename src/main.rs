//! TODO

// file stored will literally be in bytes:
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

// let mut file = Vec::new();
//
// file.extend_from_slice(MAGIC);
// file.extend_from_slice(VERSION);
// file.extend_from_slice(&salt);
// file.extend_from_slice(&nonce);
// file.extend_from_slice(&ciphertext);
// file.extend_from_slice(&tag);

mod cli;
mod core;
pub(crate) mod error;
mod model;

fn main() {
    println!("Hello, world!");
}
