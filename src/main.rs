//! TODO



// file stored will literally be in bytes: 
// header(34) + ciphertext(n)
// header:
// salt(4) + version(2) + nonce(12) + salt(16)
// ciphertext:
// encrypted text + tag

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
mod models;

fn main() {
    println!("Hello, world!");
}
