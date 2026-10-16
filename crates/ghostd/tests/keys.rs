//! `ghostd setup` and `ghostd keys` on a temp home's `authorized_keys`.

#![allow(clippy::too_many_lines)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use common::{EXE, Env};

fn keygen(dir: &Path, name: &str) -> (String, String) {
    let path = dir.join(name);
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "test@example", "-f"])
        .arg(&path)
        .status()
        .expect("ssh-keygen");
    assert!(status.success());
    let public = fs::read_to_string(path.with_extension("pub")).unwrap();
    let out = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(path.with_extension("pub"))
        .output()
        .unwrap();
    let fingerprint = String::from_utf8(out.stdout)
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .to_string();
    (public.trim().to_string(), fingerprint)
}

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
}

#[test]
fn authorize_list_and_remove() {
    let env = Env::new();
    let keys = env.dir.path().join("keys");
    fs::create_dir(&keys).unwrap();
    let (a, a_fp) = keygen(&keys, "a");
    let (b, _) = keygen(&keys, "b");
    let (plain, plain_fp) = keygen(&keys, "plain");
    let ssh = env.home.join(".ssh");
    let file = ssh.join("authorized_keys");

    // A fresh home: ~/.ssh 0700 and the file 0600 are created.
    let (ok, v, err) = run(&env, &["setup", "--authorize-key", &a, "--label", "agent"]);
    assert!(ok, "{err}");
    assert_eq!(v["key"]["action"], "added");
    assert_eq!(v["key"]["fingerprint"], a_fp.as_str());
    assert_eq!(mode(&ssh), 0o700);
    assert_eq!(mode(&file), 0o600);
    let exe = fs::canonicalize(EXE).unwrap();
    let a_body = a.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
    let expected = format!(
        "command=\"{} stdio --client agent\",restrict {a_body} ghostd:agent\n",
        exe.display()
    );
    assert_eq!(fs::read_to_string(&file).unwrap(), expected);

    // Other lines, odd bytes and all, are kept byte for byte.
    let mut others = b"# my keys\r\n".to_vec();
    others.extend_from_slice(format!("from=\"192.0.2.1\" {plain}\n").as_bytes());
    others.extend_from_slice(b"\xff\xfe not a key at all\n");
    let mut content = others.clone();
    content.extend_from_slice(expected.as_bytes());
    content.extend_from_slice(b"# trailing, no newline");
    fs::write(&file, &content).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o640)).unwrap();

    let (ok, v, _) = run(&env, &["setup", "--authorize-key", &a, "--label", "agent"]);
    assert!(ok);
    assert_eq!(v["key"]["action"], "unchanged");
    assert_eq!(fs::read(&file).unwrap(), content);

    // The same label with another key replaces the line in place.
    let (ok, v, _) = run(&env, &["setup", "--authorize-key", &b, "--label", "agent"]);
    assert!(ok);
    assert_eq!(v["key"]["action"], "replaced");
    let now = fs::read(&file).unwrap();
    assert!(now.starts_with(&others));
    assert!(now.ends_with(b"ghostd:agent\n# trailing, no newline"));
    assert!(!String::from_utf8_lossy(&now).contains(&a_body));
    assert_eq!(mode(&file), 0o640, "the mode is kept");

    // A key authorized for plain logins is refused without --replace.
    let (ok, _, err) = run(&env, &["setup", "--authorize-key", &plain, "--label", "p"]);
    assert!(!ok);
    assert!(err.contains("--replace"), "{err}");
    assert_eq!(fs::read(&file).unwrap(), now);
    let (ok, _, err) = run(
        &env,
        &[
            "setup",
            "--authorize-key",
            &plain,
            "--label",
            "p",
            "--replace",
        ],
    );
    assert!(ok, "{err}");
    let text = String::from_utf8_lossy(&fs::read(&file).unwrap()).into_owned();
    assert!(!text.contains("from=\"192.0.2.1\""));
    assert!(text.contains("ghostd:p"));

    let (ok, v, _) = run(&env, &["keys", "list"]);
    assert!(ok);
    let listed = v.as_array().unwrap();
    assert_eq!(listed.len(), 2);
    assert!(
        listed
            .iter()
            .any(|k| k["label"] == "p" && k["fingerprint"] == plain_fp.as_str())
    );
    assert!(listed.iter().any(|k| k["label"] == "agent"));

    let before = fs::read(&file).unwrap();
    let (ok, v, _) = run(&env, &["keys", "remove", "agent"]);
    assert!(ok);
    assert_eq!(v["removed"], 1);
    let after = fs::read(&file).unwrap();
    assert!(!String::from_utf8_lossy(&after).contains("ghostd:agent"));
    assert!(after.len() < before.len());
    assert!(after.starts_with(b"# my keys\r\n"));
    assert!(after.ends_with(b"# trailing, no newline"));
    let (ok, _, err) = run(&env, &["keys", "remove", "agent"]);
    assert!(!ok);
    assert!(err.contains("no ghostd key"), "{err}");

    // Bad input is refused before anything is touched.
    let (ok, _, _) = run(
        &env,
        &[
            "setup",
            "--authorize-key",
            "ssh-ed25519 AAAA",
            "--label",
            "x",
        ],
    );
    assert!(!ok);
    let (ok, _, _) = run(
        &env,
        &["setup", "--authorize-key", &a, "--label", "bad label"],
    );
    assert!(!ok);
    assert_eq!(fs::read(&file).unwrap(), after);
}
