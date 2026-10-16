//! The daemon's own log, `<state>/ghostd.log`, rotated at 8 MiB.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

use crate::paths::Paths;
use crate::util::timestamp;

const MAX_LOG: u64 = 8 * 1024 * 1024;

/// Appends one line, rotating the file first when it is full. Never fails:
/// a log that cannot be written is skipped.
pub fn log(paths: &Paths, message: &str) {
    let path = paths.log_file();
    if fs::metadata(&path).is_ok_and(|m| m.len() >= MAX_LOG) {
        let _ = fs::rename(&path, path.with_extension("log.1"));
    }
    if let Ok(mut file) = open(paths) {
        let line = format!(
            "{} [{}] {}\n",
            timestamp(),
            std::process::id(),
            message.replace('\n', "\n    ")
        );
        let _ = file.write_all(line.as_bytes());
    }
}

/// The log opened for appending (a child's stderr goes there).
///
/// # Errors
///
/// When it cannot be opened.
pub fn open(paths: &Paths) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(paths.log_file())
}
