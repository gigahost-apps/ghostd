//! `ghostd setup` and `ghostd keys`: the configuration, the install record
//! and the forced-command keys in `~/.ssh/authorized_keys`.
//!
//! Only lines whose comment starts with `ghostd:<label>` are ever changed
//! or removed. Every other line is kept byte for byte, and the file is
//! replaced atomically, so an edit can never leave a half-written file or
//! take away a login key: a key already authorized for plain logins is
//! refused unless `--replace` asks to turn it into a ghostd-only key.

use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use base64::Engine;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::TEMPLATE;
use crate::paths::{Paths, private_dir};
use crate::util::{atomic_write, home, now_ms, sync_dir, valid_label};

const KEY_TYPES: &[&str] = &[
    "ssh-ed25519",
    "ssh-rsa",
    "ssh-dss",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

fn is_key_type(token: &str) -> bool {
    KEY_TYPES.contains(&token)
        || token
            .strip_suffix("-cert-v01@openssh.com")
            .is_some_and(|base| {
                KEY_TYPES
                    .iter()
                    .any(|t| base == *t || base == t.trim_end_matches("@openssh.com"))
            })
}

/// One authorized key line, parsed.
#[derive(Debug, PartialEq, Eq)]
struct KeyLine {
    /// The options field as it is (`from="…",no-pty`), empty when none.
    options: String,
    key_type: String,
    base64: String,
    comment: String,
}

impl KeyLine {
    /// The label of a ghostd line (`ghostd:<label>` comment).
    fn ghostd_label(&self) -> Option<&str> {
        self.comment
            .split_whitespace()
            .next()
            .and_then(|w| w.strip_prefix("ghostd:"))
    }

    fn same_key(&self, other: &KeyLine) -> bool {
        self.key_type == other.key_type && self.base64 == other.base64
    }
}

/// Skips an options field (`a,b="x y",c`) up to the first unquoted blank.
fn skip_options(line: &str) -> Option<&str> {
    let mut quoted = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ' ' | '\t' if !quoted => return Some(&line[i..]),
            _ => {}
        }
    }
    None
}

/// Parses an `authorized_keys` line (options allowed); `None` for blank
/// lines, comments and lines it does not understand.
fn parse_line(line: &str) -> Option<KeyLine> {
    let line = line.trim_matches(|c| c == '\r' || c == '\n').trim_start();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let first = line.split_whitespace().next()?;
    let (options, rest) = if is_key_type(first) {
        ("", line)
    } else {
        let rest = skip_options(line)?;
        (&line[..line.len() - rest.len()], rest.trim_start())
    };
    let mut parts = rest.splitn(3, [' ', '\t']);
    let key_type = parts.next()?;
    if !is_key_type(key_type) {
        return None;
    }
    let base64 = parts.next()?.trim();
    if base64.is_empty() {
        return None;
    }
    let comment = parts.next().unwrap_or("").trim().to_string();
    Some(KeyLine {
        options: options.to_string(),
        key_type: key_type.to_string(),
        base64: base64.to_string(),
        comment,
    })
}

/// Parses and checks the public key a user gives: `<type> <base64>
/// [comment]`, the blob decoding and naming its own type.
fn parse_public_key(text: &str) -> Result<KeyLine, String> {
    if text.contains(['\n', '\r']) {
        return Err("the key must be one line".into());
    }
    let mut parts = text.split_whitespace();
    let (Some(key_type), Some(base64)) = (parts.next(), parts.next()) else {
        return Err("expected an OpenSSH public key: <type> <base64> [comment]".into());
    };
    if !is_key_type(key_type) {
        return Err(format!("unknown key type {key_type:?}"));
    }
    let blob = base64::engine::general_purpose::STANDARD
        .decode(base64)
        .map_err(|e| format!("the key's base64 is invalid: {e}"))?;
    let named = blob
        .get(..4)
        .map(|n| u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize)
        .and_then(|len| blob.get(4..4 + len));
    if named != Some(key_type.as_bytes()) {
        return Err("the key's data does not match its type".into());
    }
    Ok(KeyLine {
        options: String::new(),
        key_type: key_type.to_string(),
        base64: base64.to_string(),
        comment: String::new(),
    })
}

/// An options field's options (`a,b="x,y",c`), split at unquoted commas.
fn split_options(field: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0;
    for (i, c) in field.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ',' if !quoted => {
                out.push(&field[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push(&field[start..]);
    out.retain(|o| !o.is_empty());
    out
}

/// The options of a line ours replaces that ours keeps: the ones that
/// restrict the key (`from=`, `expiry-time=`, `principals=`, `no-*`,
/// `verify-required`…). Not `command=` and `restrict`, which ours sets,
/// and not the ones that would give back what `restrict` takes away.
fn carried_options(field: &str) -> Vec<&str> {
    const DROPPED: &[&str] = &[
        "command",
        "restrict",
        "agent-forwarding",
        "port-forwarding",
        "pty",
        "user-rc",
        "x11-forwarding",
        "permitopen",
        "permitlisten",
        "tunnel",
    ];
    split_options(field)
        .into_iter()
        .filter(|option| {
            let name = option.split('=').next().unwrap_or("").trim();
            !DROPPED.iter().any(|d| d.eq_ignore_ascii_case(name))
        })
        .collect()
}

/// The fingerprint as `ssh-keygen -l` prints it: `SHA256:<base64>`.
fn fingerprint(base64: &str) -> String {
    match base64::engine::general_purpose::STANDARD.decode(base64) {
        Ok(blob) => format!(
            "SHA256:{}",
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(&blob))
        ),
        Err(_) => "invalid".into(),
    }
}

/// The binary's path as the forced command names it, quoted for the shell
/// sshd runs it with when it holds anything but plain path characters.
fn command_path(exe: &Path) -> Result<String, String> {
    let path = exe
        .to_str()
        .ok_or_else(|| format!("the binary's path {} is not UTF-8", exe.display()))?;
    let plain = |c: char| c.is_ascii_alphanumeric() || "/._+-".contains(c);
    if path.chars().all(plain) {
        Ok(path.to_string())
    } else if path
        .chars()
        .any(|c| c == '\'' || c == '"' || c == '\\' || c.is_control())
    {
        Err(format!(
            "the binary's path {path:?} holds a quote, backslash or control character; install it elsewhere"
        ))
    } else {
        Ok(format!("'{path}'"))
    }
}

fn authorized_keys() -> PathBuf {
    home().join(".ssh/authorized_keys")
}

/// The file's lines, each with its line terminator, as they are.
fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.split_inclusive(|&b| b == b'\n').collect()
}

fn parse_bytes(line: &[u8]) -> Option<KeyLine> {
    std::str::from_utf8(line).ok().and_then(parse_line)
}

/// Writes the new content over `path` atomically, keeping an existing
/// file's mode (0600 for a new one) and creating `~/.ssh` 0700.
fn replace(path: &Path, content: &[u8]) -> io::Result<()> {
    // Write through a symlinked authorized_keys to its target.
    let target = match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => fs::canonicalize(path)?,
        _ => path.to_path_buf(),
    };
    if let Some(dir) = target.parent()
        && !dir.exists()
    {
        private_dir(dir)?;
    }
    let mode = fs::metadata(&target).map_or(0o600, |m| m.permissions().mode() & 0o7777);
    atomic_write(&target, content, mode, true)?;
    if let Some(dir) = target.parent() {
        sync_dir(dir);
    }
    Ok(())
}

fn read_keys(path: &Path) -> io::Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
    }
}

/// What [`authorize`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Authorized {
    Added,
    Replaced(usize),
    Unchanged,
}

/// Computes the new `authorized_keys` content for authorizing `key` under
/// `label` with the forced command `command`.
fn authorize_content(
    existing: &[u8],
    key: &KeyLine,
    label: &str,
    command: &str,
    replace_plain: bool,
) -> Result<(Vec<u8>, Authorized), String> {
    // The line ours replaces keeps its restrictions (a `from=` must never
    // be lost): those of the same key's line, else of the label's.
    let lines: Vec<KeyLine> = split_lines(existing)
        .into_iter()
        .filter_map(parse_bytes)
        .collect();
    let source = lines
        .iter()
        .find(|l| l.same_key(key))
        .or_else(|| lines.iter().find(|l| l.ghostd_label() == Some(label)));
    let extra: String = source
        .map(|l| carried_options(&l.options))
        .unwrap_or_default()
        .iter()
        .flat_map(|o| [",", o])
        .collect();
    let line = format!(
        "command=\"{command} stdio --client {label}\",restrict{extra} {} {} ghostd:{label}",
        key.key_type, key.base64
    );
    let mut out: Vec<u8> = Vec::with_capacity(existing.len() + line.len() + 1);
    let mut placed = false;
    let mut dropped = 0usize;
    for raw in split_lines(existing) {
        let Some(parsed) = parse_bytes(raw) else {
            out.extend_from_slice(raw);
            continue;
        };
        let ours = parsed.ghostd_label();
        let replaces = ours == Some(label) || (parsed.same_key(key) && ours.is_some());
        if parsed.same_key(key) && ours.is_none() {
            if !replace_plain {
                return Err(
                    "this key is already authorized for plain logins; a ghostd forced command would take its shell access away. Pass --replace to make it a ghostd-only key, or use another key"
                        .into(),
                );
            }
        } else if !replaces {
            out.extend_from_slice(raw);
            continue;
        }
        // This line gives way to ours; the first one keeps its place.
        if placed {
            dropped += 1;
        } else {
            let ending: &[u8] = if raw.ends_with(b"\r\n") {
                b"\r\n"
            } else if raw.ends_with(b"\n") {
                b"\n"
            } else {
                b""
            };
            if raw[..raw.len() - ending.len()] != *line.as_bytes() {
                dropped += 1;
            }
            out.extend_from_slice(line.as_bytes());
            out.extend_from_slice(ending);
            placed = true;
        }
    }
    if !placed {
        if !out.is_empty() && !out.ends_with(b"\n") {
            out.push(b'\n');
        }
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    let outcome = if out == existing {
        Authorized::Unchanged
    } else if dropped > 0 || placed {
        Authorized::Replaced(dropped)
    } else {
        Authorized::Added
    };
    Ok((out, outcome))
}

fn authorize(key_text: &str, label: &str, replace_plain: bool) -> Result<Value, String> {
    if !valid_label(label) {
        return Err("the label must match [A-Za-z0-9._-]{1,64}".into());
    }
    let key = parse_public_key(key_text.trim())?;
    let exe = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| format!("cannot find this binary's path: {e}"))?;
    let command = command_path(&exe)?;
    let path = authorized_keys();
    let existing = read_keys(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (content, outcome) = authorize_content(&existing, &key, label, &command, replace_plain)?;
    if outcome != Authorized::Unchanged {
        replace(&path, &content).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    let action = match outcome {
        Authorized::Added => "added",
        Authorized::Replaced(_) => "replaced",
        Authorized::Unchanged => "unchanged",
    };
    Ok(json!({
        "authorized_keys": path,
        "label": label,
        "type": key.key_type,
        "fingerprint": fingerprint(&key.base64),
        "command": format!("{command} stdio --client {label}"),
        "action": action,
    }))
}

/// The options of `ghostd setup`.
pub struct Setup {
    pub authorize_key: Option<String>,
    pub label: Option<String>,
    pub replace: bool,
    pub origin: Option<String>,
    pub git_ref: Option<String>,
    pub commit: Option<String>,
}

pub fn setup(paths: &Paths, options: &Setup) -> ExitCode {
    match run_setup(paths, options) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ghostd setup: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_setup(paths: &Paths, options: &Setup) -> Result<Value, String> {
    paths
        .ensure()
        .map_err(|e| format!("creating the directories: {e}"))?;
    let mut config_created = false;
    if !paths.config.exists() {
        if let Some(dir) = paths.config.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        atomic_write(&paths.config, TEMPLATE.as_bytes(), 0o644, true)
            .map_err(|e| format!("{}: {e}", paths.config.display()))?;
        config_created = true;
    }
    let mut install = Value::Null;
    if let Some(origin) = &options.origin {
        if !matches!(origin.as_str(), "source" | "channel" | "client") {
            return Err("--origin is source, channel or client".into());
        }
        let binary = std::env::current_exe()
            .and_then(fs::canonicalize)
            .map_err(|e| format!("cannot find this binary's path: {e}"))?;
        install = json!({
            "origin": origin,
            "ref": options.git_ref,
            "commit": options.commit,
            "version": env!("CARGO_PKG_VERSION"),
            "binary": binary,
            "installed_at_ms": now_ms(),
        });
        let bytes = serde_json::to_vec_pretty(&install).map_err(|e| e.to_string())?;
        atomic_write(&paths.install_record(), &bytes, 0o600, true)
            .map_err(|e| format!("{}: {e}", paths.install_record().display()))?;
    }
    let mut key = Value::Null;
    if let Some(text) = &options.authorize_key {
        let label = options
            .label
            .as_deref()
            .ok_or("--authorize-key needs --label")?;
        key = authorize(text, label, options.replace)?;
    }
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "state_dir": paths.state,
        "runtime_dir": paths.runtime,
        "config": paths.config,
        "config_created": config_created,
        "install": install,
        "key": key,
    }))
}

pub fn list() -> ExitCode {
    let path = authorized_keys();
    let existing = match read_keys(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("ghostd keys: {}: {e}", path.display());
            return ExitCode::from(1);
        }
    };
    let keys: Vec<Value> = split_lines(&existing)
        .into_iter()
        .filter_map(parse_bytes)
        .filter_map(|k| {
            let label = k.ghostd_label()?.to_string();
            Some(json!({
                "label": label,
                "type": k.key_type,
                "fingerprint": fingerprint(&k.base64),
            }))
        })
        .collect();
    println!("{}", Value::Array(keys));
    ExitCode::SUCCESS
}

/// The content without the ghostd lines labelled `label`, and how many.
fn remove_content(existing: &[u8], label: &str) -> (Vec<u8>, usize) {
    let mut out = Vec::with_capacity(existing.len());
    let mut removed = 0;
    for raw in split_lines(existing) {
        if parse_bytes(raw).is_some_and(|k| k.ghostd_label() == Some(label)) {
            removed += 1;
        } else {
            out.extend_from_slice(raw);
        }
    }
    (out, removed)
}

pub fn remove(label: &str) -> ExitCode {
    let path = authorized_keys();
    let existing = match read_keys(&path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("ghostd keys: {}: {e}", path.display());
            return ExitCode::from(1);
        }
    };
    let (content, removed) = remove_content(&existing, label);
    if removed == 0 {
        eprintln!("ghostd keys: no ghostd key labelled {label:?}");
        return ExitCode::from(1);
    }
    if let Err(e) = replace(&path, &content) {
        eprintln!("ghostd keys: {}: {e}", path.display());
        return ExitCode::from(1);
    }
    println!("{}", json!({ "label": label, "removed": removed }));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    // A syntactically valid ed25519 public key (32 zero bytes).
    fn key(n: u8) -> String {
        let mut blob = Vec::new();
        blob.extend_from_slice(&11u32.to_be_bytes());
        blob.extend_from_slice(b"ssh-ed25519");
        blob.extend_from_slice(&32u32.to_be_bytes());
        blob.extend_from_slice(&[n; 32]);
        format!(
            "ssh-ed25519 {}",
            base64::engine::general_purpose::STANDARD.encode(blob)
        )
    }

    #[test]
    fn parses_lines_with_options() {
        let k = key(1);
        let parsed = parse_line(&format!("command=\"a b\",restrict {k} ghostd:x more")).unwrap();
        assert_eq!(parsed.ghostd_label(), Some("x"));
        assert_eq!(parsed.key_type, "ssh-ed25519");
        let plain = parse_line(&format!("{k} me@laptop")).unwrap();
        assert_eq!(plain.ghostd_label(), None);
        assert!(parse_line("# comment").is_none());
        assert!(parse_line("").is_none());
        assert!(parse_public_key(&key(2)).is_ok());
        assert!(parse_public_key("ssh-ed25519 AAAA").is_err());
        assert!(parse_public_key("ssh-rsa AAAAC3NzaC1lZDI1NTE5AAAAIA==").is_err());
    }

    #[test]
    fn add_replace_refuse() {
        let a = parse_public_key(&key(1)).unwrap();
        let b = parse_public_key(&key(2)).unwrap();
        let other = format!("# keep me\r\nfrom=\"10.0.0.1\" {} me\n", key(9));
        let (one, outcome) =
            authorize_content(other.as_bytes(), &a, "x", "/bin/ghostd", false).unwrap();
        assert_eq!(outcome, Authorized::Added);
        assert!(one.starts_with(other.as_bytes()));
        // Idempotent.
        let (again, outcome) = authorize_content(&one, &a, "x", "/bin/ghostd", false).unwrap();
        assert_eq!(outcome, Authorized::Unchanged);
        assert_eq!(again, one);
        // The same label with another key replaces the line in place.
        let (swapped, outcome) = authorize_content(&one, &b, "x", "/bin/ghostd", false).unwrap();
        assert_eq!(outcome, Authorized::Replaced(1));
        assert!(swapped.starts_with(other.as_bytes()));
        assert_eq!(swapped.len(), one.len());
        // A plain key is refused without --replace.
        let plain = format!("{} me@laptop", key(3));
        let c = parse_public_key(&key(3)).unwrap();
        assert!(authorize_content(plain.as_bytes(), &c, "y", "/bin/ghostd", false).is_err());
        let (forced, _) =
            authorize_content(plain.as_bytes(), &c, "y", "/bin/ghostd", true).unwrap();
        assert!(String::from_utf8(forced).unwrap().starts_with("command="));
        // A file without a final newline gets one before our line.
        let (joined, _) = authorize_content(b"# x", &a, "x", "/bin/ghostd", false).unwrap();
        assert!(joined.starts_with(b"# x\ncommand="));
    }

    #[test]
    fn restrictions_of_a_replaced_line_are_kept() {
        let k = key(4);
        let a = parse_public_key(&k).unwrap();
        // A plain key restricted to a network, made a ghostd key.
        let plain = format!(
            "from=\"192.0.2.0/24,198.51.100.7\",expiry-time=\"20990101\",pty,command=\"/bin/sh\" {k} me@laptop\n"
        );
        let (out, _) = authorize_content(plain.as_bytes(), &a, "x", "/bin/ghostd", true).unwrap();
        let text = String::from_utf8(out.clone()).unwrap();
        assert_eq!(
            text,
            format!(
                "command=\"/bin/ghostd stdio --client x\",restrict,from=\"192.0.2.0/24,198.51.100.7\",expiry-time=\"20990101\" {k} ghostd:x\n"
            )
        );
        // Setup again: unchanged, the restriction still there.
        let (again, outcome) = authorize_content(&out, &a, "x", "/bin/ghostd", false).unwrap();
        assert_eq!(outcome, Authorized::Unchanged);
        assert_eq!(again, out);
        // A restriction added by hand to a ghostd line survives a setup
        // that moves the binary, and a new key under the same label.
        let hand = format!(
            "from=\"10.1.2.3\",command=\"/old/ghostd stdio --client x\",restrict {k} ghostd:x\n"
        );
        let (moved, outcome) =
            authorize_content(hand.as_bytes(), &a, "x", "/bin/ghostd", false).unwrap();
        assert_eq!(outcome, Authorized::Replaced(1));
        assert!(
            String::from_utf8(moved).unwrap().starts_with(
                "command=\"/bin/ghostd stdio --client x\",restrict,from=\"10.1.2.3\" "
            )
        );
        let b = parse_public_key(&key(5)).unwrap();
        let (rotated, _) =
            authorize_content(hand.as_bytes(), &b, "x", "/bin/ghostd", false).unwrap();
        assert!(
            String::from_utf8(rotated)
                .unwrap()
                .contains(",restrict,from=\"10.1.2.3\" ")
        );
        assert_eq!(
            split_options(r#"a,b="x,\"y\",z",c"#),
            vec!["a", r#"b="x,\"y\",z""#, "c"]
        );
    }

    #[test]
    fn removal_touches_only_ghostd_lines() {
        let content = format!(
            "{} ghostd:x\n{} ghostd:x-not\ncommand=\"g\" {} ghostd:x\n",
            key(1),
            key(2),
            key(3)
        );
        let (out, n) = remove_content(content.as_bytes(), "x");
        assert_eq!(n, 2);
        assert_eq!(out, format!("{} ghostd:x-not\n", key(2)).into_bytes());
    }

    #[test]
    fn command_paths() {
        assert_eq!(
            command_path(Path::new("/usr/bin/ghostd")).unwrap(),
            "/usr/bin/ghostd"
        );
        assert_eq!(
            command_path(Path::new("/a b/ghostd")).unwrap(),
            "'/a b/ghostd'"
        );
        assert!(command_path(Path::new("/a'b/ghostd")).is_err());
    }

    #[test]
    fn fingerprint_format() {
        let k = key(0);
        let b64 = k.split(' ').nth(1).unwrap();
        assert!(fingerprint(b64).starts_with("SHA256:"));
        assert!(!fingerprint(b64).ends_with('='));
    }
}
