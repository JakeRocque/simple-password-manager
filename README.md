A minimal CLI password manager written entirely in Rust.
 
All entries (service, username, password) live in a single encrypted vault file on your machine. Nothing is sent over the network, and neither the master password nor the encryption key is ever written to disk. The key is re-derived from the master password every time a command runs.
 
- **Encryption:** AES-256-GCM (authenticated encryption)
- **Key derivation:** Argon2id with a random per-vault salt
- **Tamper detection:** every byte written to disk is authenticated, so any modification makes the vault fail to open
- **Memory hygiene:** sensitive values are zeroized when dropped (best-effort)

> [!WARNING]
> This is a learning project, not an audited tool. See [Limitations](#limitations).

# Development Process
This was primarily built as a personal tool and learning exercise, so I'd like to share my development process including what I had to learn and useful sources.

## Cryptography
At first, I was very overwhelmed trying to find Rust libraries that were simple enough for me to navigate and contained relevant code to learn from. Every open-source password manager had massive codebases, and I didn't really know what I was looking for.

I realized that I had to better understand my task independent of code and found the following path worked the best:
- First, I read up on cryptography basics (and made sure I understood them)
- Then, I looked into the most commonly used cryptographic algorithms today (I made sure to understand the inputs, outputs, and how they defend against common attack vectors)
- Only after that did I feel able to actually look into the code of popular open-source password managers (this was still difficult, but I was able to narrow my search to look at only the critical components)

**Topics**
- Encryption & Nonces
- Authentication
- Hashing & Salts
- Serialization & Deserialization
- Additional Authenticated Data (AAD)
- Authenticated Encryption with Associated Data (AEAD)
- Advanced Encryption Standard (AES) & AES-256
- Galois/Counter Mode (GCM)
- AES-256-GCM
- Argon2

# How It Works

## Cryptography

**Key derivation (Argon2id).** The master password is hashed with Argon2
together with a random 16-byte salt to produce a 32-byte key. The salt is
generated once when the vault is created and stored, unencrypted, in the
vault header. Salts are not secret. Their job is to make every vault's key
unique even if two users pick the same password. This defeats
precomputed (rainbow table) attacks. Argon2 ensures that any guess at the
master password is expensive for an attacker.

**Encryption (AES-256-GCM).** The derived key is used with AES-256 in
Galois/Counter Mode. AES-256 is the block cipher. GCM turns it into an
AEAD (Authenticated Encryption with Associated Data) scheme, meaning a
single operation gives both:
- *Encryption*: the entries can't be read without the key.
- *Authentication*: If the ciphertext is tampered with at all
  then decryption fails.

**Nonces.** Every encryption uses a fresh, random 12-byte (96-bit) nonce,
stored next to the ciphertext. A nonce must never be reused.

**Additional Authenticated Data (AAD).** The 22-byte vault header is
passed to AES-GCM as AAD. It is stored in plaintext (it has to be, since
the salt is needed to derive the key), but it is covered by the
authentication tag. Between the AAD and actual encrypted data,
every single piece of data written to disk is authenticated.

## Vault File Format

```text
vault.txt = header (22 bytes, raw) || sealed (JSON, variable length)

header:
  magic   4 bytes   0x3B 0xD0 0x07 0xBD, identifies the file as a vault
  version 2 bytes   big-endian u16, chosen at `init-vault`
  salt   16 bytes   random, used for Argon2 key derivation

sealed (serde_json):
  { "nonce": [12 bytes], "ciphertext": [n + 16 bytes] }
  where ciphertext = AES-256-GCM(key, nonce, plaintext, aad = header)
  and the last 16 bytes are the authentication tag

plaintext (serde_json, never written to disk):
  { "entries": [ { "service", "username", "password" }, ... ] }
```

By default the vault lives at `<local data dir>/JakeysPasswordVault/vault.txt`
(see the `default-location` command); `--path` points to a different
parent directory.

## Step by Step Explanation

**`init-vault`**
1. Generate a random 16-byte salt.
2. Read the master password (interactive prompt strongly recommended,
   but can stdin with `--allow-piped`).
3. Derive the key with Argon2 (password + salt).
4. Build the header (magic, version, salt) and encrypt an entry list
   using the header as AAD.
5. Write the file.

**`list` / `get`**
1. Read the vault file, check its length and magic, and parse the header.
2. Read the master password and derive the key using the salt from the
   header.
3. Decrypt and authenticate the entries using the header as AAD, then
   deserialize them.
4. Print the service names, or the requested entry.

**`add` / `delete`**
1. Same as steps 1–3 above.
2. Add or remove the entry in memory.
3. Re-encrypt the full entry list with a fresh nonce and the same header.
4. Write to a temporary file, `fsync` it, then rename it over the vault.
   The rename is atomic so a crash doesn't leave a half-written file.

Sensitive values (master password, decrypted entries, intermediate byte
buffers) are wrapped in `Zeroizing` or derive `ZeroizeOnDrop`,
so their memory is overwritten when they are dropped.

## Limitations
 
- **Rollback attacks.** The header has no counter or timestamp, so an older copy of the vault is still a valid vault. Someone with write access to the file can silently restore an old version and it will decrypt without error (although if an attacker has write access, you have bigger issues).
- **Sizing.** The file size reveals roughly how much data the vault holds.
- **Memory zeroization is best-effort.** Rust can't guarantee that no copies of sensitive data are left in memory.


# Installation
 
Requires [Rust](https://www.rust-lang.org/tools/install) (installed via `rustup`).
 
```
git clone https://github.com/JakeRocque/simple-password-manager.git
cd simple-password-manager
cargo install --path .
```
 
This builds a release binary and puts `jakeys_password_manager_bin` on your PATH (in `~/.cargo/bin`, or `%USERPROFILE%\.cargo\bin` on Windows).
 
To build without installing, run `cargo build --release`; the binary is at `target/release/jakeys_password_manager_bin`.
 
# Use
 
| Command | Description |
|---|---|
| `init-vault <VERSION>` | Create a new vault |
| `list` | List saved services |
| `get <SERVICE>` | Show the username and password for a service |
| `add <SERVICE> <USERNAME> <PASSWORD>` | Add an entry |
| `delete <SERVICE>` | Delete an entry |
| `health` | Check whether a vault has been initialized |
| `default-location` | Show where the vault is stored by default |
 
Every command that opens the vault prompts for the master password. Run any command with `--help` for full details.
 
**Options**
- `-p, --path <DIR>`: use a vault in a different directory instead of the default location.
- `-a, --allow-piped`: read passwords from piped stdin instead of the interactive prompt. Intended for scripting and tests; the interactive prompt is strongly recommended.

**Example**
```
$ jakeys_password_manager_bin init-vault 1
Master password:
 
$ jakeys_password_manager_bin add github jacob super-secret
Master password:
 
$ jakeys_password_manager_bin list
Master password:
 
Services
--------
github
 
$ jakeys_password_manager_bin get github
Master password:
 
github
------
Username: jacob
Password: super-secret
```
 
> [!IMPORTANT]
> **There is no recovery.** If you forget the master password or lose the vault file, your entries are gone. You can back up the vault file (run `default-location` to find it).

 
# Development
Integration tests in `tests/cli.rs` run the real binary against vaults in `tmp/`, using `--allow-piped` to supply passwords.
