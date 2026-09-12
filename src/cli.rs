//! TODO

use std::path::{Path, PathBuf};

use crate::{
    core::operations::{
        add, delete, get, get_path_dir_to_vault_path, get_salt, get_vault_path_dir, is_vault_init,
        list,
    },
    error::{Error, Result},
    model::BANNER,
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
    /// Check if vault has been initialized and default vault location
    Health {
        #[arg(short, long, default_value_os_t = get_vault_path_dir())]
        path: PathBuf,
    },
    /// Get the default vault file location
    DefaultLocation {},
    /// Initialize the empty vault
    InitVault {
        /// Vault version
        version: u16,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = get_vault_path_dir())]
        path: PathBuf,
    },
    /// List saved services
    List {
        /// Location of the vault
        #[arg(short, long, default_value_os_t = get_vault_path_dir())]
        path: PathBuf,
    },
    /// Get an entry (service, username, password)
    Get {
        /// Service to add
        service: Zeroizing<String>,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = get_vault_path_dir())]
        path: PathBuf,
    },
    /// Add an entry
    Add {
        /// Service to add
        service: Zeroizing<String>,
        /// username of new service
        username: Zeroizing<String>,
        /// password of new service
        password: Zeroizing<String>,
        /// Location of the vault
        #[arg(short, long, default_value_os_t = get_vault_path_dir())]
        path: PathBuf,
    },

    /// Delete an entry
    Delete {
        /// Service to add
        service: Zeroizing<String>,
        #[arg(short, long, default_value_os_t = get_vault_path_dir())]
        path: PathBuf,
    },
}

fn display_error(e: Error) {
    eprintln!("ERROR --- {e}");
}

fn get_inputs(path: &Path, gen_salt: bool) -> Result<(PathBuf, [u8; 16], Zeroizing<String>)> {
    let true_path = get_path_dir_to_vault_path(&path);

    let salt = if gen_salt {
        generate_salt()
    } else {
        get_salt(&true_path)?
    };

    let master_password =
        Zeroizing::new(rpassword::prompt_password("Master password: ").map_err(Error::RPassword)?);

    Ok((true_path, salt, master_password))
}

fn eval() -> Result<Zeroizing<String>> {
    let args = Cli::parse();

    match args.command {
        Commands::Health { path } => match is_vault_init(&get_path_dir_to_vault_path(&path)) {
            true => return Ok(Zeroizing::new("Vault initialized.".to_string())),
            false => return Ok(Zeroizing::new("Vault not initialized.".to_string())),
        },
        Commands::DefaultLocation {} => Ok(Zeroizing::new(
            get_path_dir_to_vault_path(&get_vault_path_dir())
                .to_str()
                .ok_or(Error::DefaultVaultLocationNotFound)?
                .to_string(),
        )),
        Commands::InitVault { path, version } => {
            let (true_path, salt, master_password) = get_inputs(&path, true)?;

            init_vault(
                &true_path,
                false,
                true,
                &key_from_bytes(&master_password, &salt)?,
                VAULT_MAGIC,
                version.to_be_bytes(),
                salt,
            )?;

            Ok(Zeroizing::new(format!(
                "{}\nSuccessfully initialized vault at '{}'. Do not change this folder or vault name.",
                BANNER,
                true_path.display()
            )))
        }
        Commands::List { path } => {
            let (true_path, salt, master_password) = get_inputs(&path, false)?;

            let result = Zeroizing::new(
                list(&true_path, &key_from_bytes(&master_password, &salt)?)?.to_cli_string(),
            );

            Ok(result)
        }
        Commands::Get { path, service } => {
            let (true_path, salt, master_password) = get_inputs(&path, false)?;

            let result = Zeroizing::new(
                get(
                    &true_path,
                    &key_from_bytes(&master_password, &salt)?,
                    service,
                )?
                .to_cli_string(true),
            );

            Ok(result)
        }
        Commands::Add {
            path,
            service,
            username,
            password,
        } => {
            let (true_path, salt, master_password) = get_inputs(&path, false)?;

            add(
                &true_path,
                &key_from_bytes(&master_password, &salt)?,
                service,
                username,
                password,
            )?;

            Ok(Zeroizing::new("Successfully added entry.".to_string()))
        }
        Commands::Delete { path, service } => {
            let (true_path, salt, master_password) = get_inputs(&path, false)?;

            Zeroizing::new(delete(
                &true_path,
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
            print!("{}", *s)
        }
    }
    print!("\n\n\n");
}
