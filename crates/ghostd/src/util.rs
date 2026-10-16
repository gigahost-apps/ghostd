//! Small helpers shared by the daemon's parts.

use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ghostd_protocol::v1::{Error, ErrorKind};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Milliseconds since the Unix epoch.
#[must_use]
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `n` random bytes as lowercase hex, from the kernel.
///
/// # Errors
///
/// When `/dev/urandom` cannot be read.
pub fn random_hex(n: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; n];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().fold(String::with_capacity(n * 2), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    }))
}

/// A path from bytes.
#[must_use]
pub fn path_from(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsStr::from_bytes(bytes))
}

/// The user's home directory: `$HOME`, else the password database's, else `/`.
#[must_use]
pub fn home() -> PathBuf {
    if let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) {
        return PathBuf::from(home);
    }
    nix::unistd::User::from_uid(nix::unistd::getuid())
        .ok()
        .flatten()
        .map_or_else(|| PathBuf::from("/"), |u| u.dir)
}

/// A path relative to `$HOME` unless absolute; empty means `$HOME`.
#[must_use]
pub fn resolve(bytes: &[u8]) -> PathBuf {
    let path = path_from(bytes);
    if path.is_absolute() {
        path
    } else {
        home().join(path)
    }
}

/// Writes `data` to `path` atomically: a temp file in the same directory,
/// fsync when `sync`, then rename over `path`.
///
/// # Errors
///
/// Any failing step; the temp file is removed then.
pub fn atomic_write(path: &Path, data: &[u8], mode: u32, sync: bool) -> io::Result<()> {
    let tmp = temp_beside(path)?;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        file.write_all(data)?;
        if sync {
            file.sync_all()?;
        }
        drop(file);
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// A fresh temp file name in `path`'s directory.
///
/// # Errors
///
/// When no random bytes can be read.
pub fn temp_beside(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .map_or_else(|| "file".into(), |n| n.to_string_lossy().into_owned());
    let tmp_name = format!(".{name}.ghostd-{}.tmp", random_hex(6)?);
    Ok(path.with_file_name(tmp_name))
}

/// fsyncs a directory (after a rename into it), ignoring failures.
pub fn sync_dir(dir: &Path) {
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
}

/// An I/O error as a protocol error.
#[must_use]
pub fn io_error(e: &io::Error, context: &str) -> Error {
    let kind = match e.kind() {
        io::ErrorKind::NotFound => ErrorKind::NotFound,
        io::ErrorKind::PermissionDenied => ErrorKind::PermissionDenied,
        io::ErrorKind::AlreadyExists => ErrorKind::AlreadyExists,
        io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => ErrorKind::InvalidArgument,
        io::ErrorKind::DirectoryNotEmpty => ErrorKind::Conflict,
        io::ErrorKind::ResourceBusy => ErrorKind::Busy,
        io::ErrorKind::Unsupported => ErrorKind::Unsupported,
        _ => ErrorKind::Io,
    };
    Error {
        kind,
        message: format!("{context}: {e}"),
        os_code: e.raw_os_error(),
    }
}

/// A protocol error of `kind`.
pub fn err(kind: ErrorKind, message: impl Into<String>) -> Error {
    Error::new(kind, message)
}

/// A client label: `[A-Za-z0-9._-]{1,64}`.
#[must_use]
pub fn valid_label(label: &str) -> bool {
    (1..=64).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Bytes stored as base64 in JSON files.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct B64(pub Vec<u8>);

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .map(B64)
            .map_err(serde::de::Error::custom)
    }
}

/// The current time as `YYYY-MM-DDTHH:MM:SS.mmmZ`.
#[must_use]
pub fn timestamp() -> String {
    let ms = now_ms();
    let secs = ms / 1000;
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        ms % 1000
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels() {
        assert!(valid_label("laptop-1.agent_x"));
        assert!(!valid_label(""));
        assert!(!valid_label("a b"));
        assert!(!valid_label("a\"b"));
        assert!(!valid_label(&"x".repeat(65)));
    }

    #[test]
    fn timestamp_shape() {
        let t = timestamp();
        assert_eq!(t.len(), 24, "{t}");
        assert!(t.starts_with("20"));
    }
}
