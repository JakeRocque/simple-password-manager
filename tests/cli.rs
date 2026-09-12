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
    cmd
        .arg("init-vault")
        .arg("1")
        .arg("--path")
        .arg(&path)
        .write_stdin("password\n")
        .assert()
        .code(0)
        .stdout(format!("\n\n{}\nSuccessfully initialized vault at '{}'. Do not change this folder or vault name.\n\n\n",
                BANNER,
                path
            ));
}
