//! Command-line interface (CLI) Integration test
//!
//! This file has some integration tests for the actual program binary.
//! Passwords are piped in instead of using an interactive terminal.

use assert_cmd::Command;
use std::fs;
use std::path::Path;

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

fn create_relative_path_string(test_name: &str) -> String {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tmp")
        .join(test_name);

    if dir.exists() {
        fs::remove_dir_all(&dir).unwrap();
    }

    fs::create_dir_all(&dir).unwrap();

    return dir.to_str().unwrap().to_string();
}

#[test]
fn test_health() {
    let path = create_relative_path_string("test_health");

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("health")
        .arg("--path")
        .arg(&path)
        .assert()
        .code(0)
        .stdout("\n\nVault not initialized.\n\n\n");

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("init-vault")
        .arg("1")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0);

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("health")
        .arg("--path")
        .arg(&path)
        .assert()
        .code(0)
        .stdout("\n\nVault initialized.\n\n\n");
}

#[test]
fn test_default_location() {
    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("default-location").assert().code(0);
}

#[test]
fn test_init_vault() {
    let path = create_relative_path_string("test_init_vault");

    let expected_vault_path = Path::new(&path)
        .join("JakeysPasswordVault")
        .join("vault.txt");

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd
        .arg("init-vault")
        .arg("1")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .stdout(format!("\n\n{}\nSuccessfully initialized vault at '{}'. Do not change this folder or vault name.\n\n\n",
                BANNER,
                expected_vault_path.display()
            ));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("init-vault")
        .arg("1")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(1)
        .stderr(format!("ERROR --- vault file: vault file already exists\n",));
}

#[test]
fn test_list_get_add_delete() {
    let path = create_relative_path_string("test_list_get_add_delete");

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd
        .arg("list")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(1)
        .stderr(format!("ERROR --- vault file: vault file doesn't exist in vault directory or vault directory doesn't exist\n",
            ));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("init-vault")
        .arg("1")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0);

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("list")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .code(0)
        .stdout(format!("\n\nServices\n--------\n\n\n\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd
        .arg("list")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("wrong_password\n")
        .assert()
        .code(1)
        .stderr(format!("ERROR --- vault: decryption or authentication failed, wrong password or corrupted vault\n",
            ));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("add")
        .arg("Minecraft")
        .arg("Steve123")
        .arg("redSt0nef@n12!")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .code(0)
        .stdout(format!("\n\nSuccessfully added entry.\n\n\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("list")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .code(0)
        .stdout(format!("\n\nServices\n--------\nMinecraft\n\n\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("add")
        .arg("etsy")
        .arg("Brig1988")
        .arg("?aS02Ks8FoW!sk8E8Es2$")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .code(0)
        .stdout(format!("\n\nSuccessfully added entry.\n\n\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("list")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .code(0)
        .stdout(format!("\n\nServices\n--------\nMinecraft\netsy\n\n\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd
        .arg("list")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("wrong_password\n")
        .assert()
        .code(1)
        .stderr(format!("ERROR --- vault: decryption or authentication failed, wrong password or corrupted vault\n",
            ));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("get")
        .arg("etsy")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .stdout(format!(
            "\n\netsy\n----\nUsername: Brig1988\nPassword: ?aS02Ks8FoW!sk8E8Es2$\n\n\n"
        ));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("get")
        .arg("Etsy")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(1)
        .stderr(format!("ERROR --- vault: service not found in the vault\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("get")
        .arg("")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(1)
        .stderr(format!("ERROR --- bad entry: inavlid service name\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("delete")
        .arg("Minecraft")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .stdout(format!("\n\nSuccessfully deleted entry.\n\n\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("delete")
        .arg("Minecraft")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(1)
        .stderr(format!("ERROR --- vault: service not found in the vault\n"));

    let mut cmd = Command::cargo_bin("jakeys_password_manager_bin").unwrap();
    cmd.arg("list")
        .arg("--path")
        .arg(&path)
        .arg("--allow-piped")
        .write_stdin("password\n")
        .assert()
        .code(0)
        .code(0)
        .stdout(format!("\n\nServices\n--------\netsy\n\n\n"));
}
