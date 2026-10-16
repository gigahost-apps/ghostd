//! `ghostd setup`, and that no source touches the SSH configuration.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::Env;

fn run(env: &Env, args: &[&str]) -> (bool, serde_json::Value, String) {
    let out = env.cmd(args).output().unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    (
        out.status.success(),
        json,
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

#[test]
fn setup_creates_config_and_records_the_origin() {
    let env = Env::new();
    fs::remove_file(&env.config).unwrap();
    let (ok, v, err) = run(
        &env,
        &[
            "setup", "--origin", "source", "--ref", "v0.1.0", "--commit", "abc123",
        ],
    );
    assert!(ok, "{err}");
    assert_eq!(v["config_created"], true);
    let config = fs::read_to_string(&env.config).unwrap();
    assert!(config.contains("# stop_grace_ms = 5000"));
    let install: serde_json::Value =
        serde_json::from_slice(&fs::read(env.state.join("install.json")).unwrap()).unwrap();
    assert_eq!(install["origin"], "source");
    assert_eq!(install["ref"], "v0.1.0");
    assert_eq!(install["commit"], "abc123");
    assert_eq!(mode(&env.state), 0o700);
    let (ok, v, _) = run(&env, &["setup"]);
    assert!(ok);
    assert_eq!(v["config_created"], false);
    // Nothing under the home's SSH directory appears.
    assert!(!env.home.join(".ssh").exists());
}

#[test]
fn setup_refuses_the_removed_key_options() {
    let env = Env::new();
    let (ok, _, _) = run(&env, &["setup", "--authorize-key", "ssh-ed25519 AAAA x"]);
    assert!(!ok);
    let (ok, _, _) = run(&env, &["keys", "list"]);
    assert!(!ok);
}

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            sources(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// ghostd never reads or writes the user's SSH files: no source under
/// `crates/` names them, except the ssh test's own sshd configuration.
#[test]
fn no_source_names_the_ssh_files() {
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut files = Vec::new();
    sources(crates, &mut files);
    assert!(files.len() > 10, "{files:?}");
    // Spelled in pieces so this file does not match itself.
    let needles = [format!("authorized{}keys", '_'), format!(".ssh{}", '/')];
    let allowed = crates.join("ghostd/tests/ssh.rs");
    let mut found = Vec::new();
    for file in files.iter().filter(|f| **f != allowed) {
        let text = String::from_utf8_lossy(&fs::read(file).unwrap()).into_owned();
        for needle in &needles {
            if text.contains(needle.as_str()) {
                found.push(format!("{} names {needle}", file.display()));
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}
