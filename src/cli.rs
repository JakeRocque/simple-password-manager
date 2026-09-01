//! TODO

use std::path::PathBuf;

use crate::{
    core::operations::{
        add, delete, delete_vault, get, get_salt, get_vault_path, is_default_vault_init, list,
    },
    error::{Error, Result},
};
use argon2::password_hash::generate_salt;
use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use crate::{
    core::operations::{init_vault, key_from_bytes},
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
    /// Check if default vault has been initialized
    Health {},
    /// Initialize the empty vault
    InitVault {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Vault version
        version: u16,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = get_vault_path())]
        path: PathBuf,
    },
    /// Delete the vault
    DeleteVault {
        /// Location of the vault
        #[arg(short, long, default_value_os_t = get_vault_path())]
        path: PathBuf,
    },
    /// List saved services
    List {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = get_vault_path())]
        path: PathBuf,
    },
    /// Get an entry (service, username, password)
    Get {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Service to add
        service: Zeroizing<String>,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = get_vault_path())]
        path: PathBuf,
    },
    /// Add an entry
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
        #[arg(short, long, default_value_os_t = get_vault_path())]
        path: PathBuf,
    },

    /// Delete an entry
    Delete {
        /// Vault password
        master_password: Zeroizing<String>,
        /// Service to add
        service: Zeroizing<String>,
        #[arg(short, long, default_value_os_t = get_vault_path())]
        path: PathBuf,
    },
}

fn display_error(e: Error) {
    eprintln!("ERROR --- {e}");
}

fn eval() -> Result<Zeroizing<String>> {
    let args = Cli::parse();

    match args.command {
        Commands::Health {} => match is_default_vault_init() {
            true => return Ok(Zeroizing::new("Default vault initialized.".to_string())),
            false => return Ok(Zeroizing::new("Default vault not initialized.".to_string())),
        },
        Commands::InitVault {
            path,
            master_password,
            version,
        } => {
            let salt = generate_salt();

            init_vault(
                &path,
                false,
                true,
                &key_from_bytes(&master_password, &salt)?,
                VAULT_MAGIC,
                version.to_be_bytes(),
                salt,
            )?;

            Ok(Zeroizing::new(
                "Successfully initialized vault.".to_string(),
            ))
        }
        Commands::DeleteVault { path } => {
            delete_vault(&path)?;

            Ok(Zeroizing::new("Successfully deleted vault.".to_string()))
        }
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
