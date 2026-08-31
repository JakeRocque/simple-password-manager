//! TODO

use std::path::PathBuf;

use crate::{
    core::operations::{add, delete, get, get_salt, list},
    error::{Error, Result},
};
use argon2::password_hash::generate_salt;
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::{
    core::operations::{init, key_from_bytes},
    model::VAULT_MAGIC,
};

#[derive(Parser, Debug)]
#[command(version, about = "A local password manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Initialize the empty vault at a given location
    Init {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Vault version
        version: u16,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = default_vault_path(true))]
        path: PathBuf,
    },
    /// Delete the password vault at a given location
    // DeleteVault {
    //     /// Location of the vault
    //     #[arg(short, long, default_value_os_t = default_vault_path(false))]
    //     path: PathBuf,
    // },
    /// List out all saved services
    List {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = default_vault_path(false))]
        path: PathBuf,
    },
    /// Get an entry (service, username, password) from the vault
    Get {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Service to add
        service: Zeroizing<String>,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = default_vault_path(false))]
        path: PathBuf,
    },
    /// Add an entry to the vault
    Add {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Service to add
        service: Zeroizing<String>,
        /// username of new service
        username: Zeroizing<String>,
        /// password of new service
        password: Zeroizing<String>,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = default_vault_path(false))]
        path: PathBuf,
    },

    /// Delete an entry from the vault
    Delete {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Service to add
        service: Zeroizing<String>,
        #[arg(short, long, default_value_os_t = default_vault_path(false))]
        path: PathBuf,
    },
}

fn default_vault_path(create: bool) -> PathBuf {
    let dir = dirs::data_dir()
        .expect("Could not determine user data directory")
        .join("jakeys-password-vault");

    if create {
        std::fs::create_dir_all(&dir).expect("Could not create password vault directory");
    }

    dir.join("vault.txt")
}

fn display_error(e: Error) {
    eprintln!("ERROR --- {e}");
}

fn eval() -> Result<Zeroizing<String>> {
    let args = Cli::parse();

    match args.command {
        Commands::Init {
            path,
            master_password,
            version,
        } => {
            let salt = generate_salt();

            init(
                &path,
                false,
                &key_from_bytes(&master_password, &salt)?,
                VAULT_MAGIC,
                version.to_be_bytes(),
                salt,
            )?;

            Ok(Zeroizing::new(
                "Successfully initialized vault.".to_string(),
            ))
        }
        // Commands::DeleteVault { path } => {
        //     // TODO
        // }
        Commands::List {
            path,
            master_password,
        } => {
            let salt = get_salt(&path)?;

            let result = Zeroizing::new(
                list(&path, &key_from_bytes(&master_password, &salt)?)?.to_cli_string(),
            );

            Ok(result)
        }
        Commands::Get {
            path,
            master_password,
            service,
        } => {
            let salt = get_salt(&path)?;

            let result = Zeroizing::new(
                get(&path, &key_from_bytes(&master_password, &salt)?, service)?.to_cli_string(true),
            );

            Ok(result)
        }
        Commands::Add {
            path,
            master_password,
            service,
            username,
            password,
        } => {
            let salt = get_salt(&path)?;

            add(
                &path,
                &key_from_bytes(&master_password, &salt)?,
                service,
                username,
                password,
            )?;

            Ok(Zeroizing::new("Successfully added entry.".to_string()))
        }
        Commands::Delete {
            path,
            master_password,
            service,
        } => {
            let salt = get_salt(&path)?;

            Zeroizing::new(delete(
                &path,
                &key_from_bytes(&master_password, &salt)?,
                service,
            )?);

            Ok(Zeroizing::new("Successfully deleted entry.".to_string()))
        }
    }
}

pub fn run() {
    let response = eval();

    print!("\n\n");
    match response {
        Err(e) => {
            display_error(e);
            std::process::exit(1);
        }
        Ok(s) => {
            println!("{}", *s)
        }
    }
    print!("\n\n");
}
