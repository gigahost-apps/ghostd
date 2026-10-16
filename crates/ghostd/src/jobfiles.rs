//! The files of a job directory, shared by the worker and the shim.
//!
//! `<state>/jobs/<id>/`: `spec.json` (what to run), `stdin` and `script`
//! when given, `status.json` (written by the shim, atomically),
//! `stdout.log` / `stderr.log` and one rotated `.1` each, `log.lock` (held
//! exclusively by the shim while it rotates, shared by readers while they
//! open the logs), `stop` (the grace a stop asks for) and `rule` (for an
//! Exec with `keep_on_timeout`: whether it ended as an Exec or became a
//! job, claimed once by whoever decides first, see [`claim_rule`]).
//!
//! Jobs outlive the binary that started them (an update, a rollback), so
//! one ghostd reads the files of a newer or an older one: readers ignore
//! fields they do not know and default the ones that are missing, so a
//! field is only ever added, with a default that means what older files
//! meant. A change older readers would misread instead raises [`FORMAT`];
//! a reader leaves a job of a newer format alone (it never stops or
//! collects it).

use std::fs;
use std::io;
use std::path::Path;

use ghostd_protocol::v1::Stream;
use serde::{Deserialize, Serialize};

use crate::util::{B64, atomic_write};

pub const SPEC: &str = "spec.json";
pub const STATUS: &str = "status.json";
pub const STDIN: &str = "stdin";
pub const SCRIPT: &str = "script";
pub const STOP: &str = "stop";
pub const LOG_LOCK: &str = "log.lock";
pub const RULE: &str = "rule";
/// The [`RULE`] of an Exec whose program ended before its timeout: what
/// it left in the job's session is stopped.
pub const RULE_EXEC: &str = "exec";
/// The [`RULE`] of an Exec answered at its timeout with the program still
/// running: from then on it is a job, and what it leaves is its own.
pub const RULE_JOB: &str = "job";

/// The format of `spec.json` and `status.json` this build writes.
pub const FORMAT: u32 = 1;

fn first_format() -> u32 {
    1
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Exec,
    #[default]
    Job,
}

/// What the shim runs, everything resolved by the worker.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SpecFile {
    #[serde(default = "first_format")]
    pub format: u32,
    pub kind: Kind,
    pub argv: Vec<B64>,
    pub env: Vec<(B64, B64)>,
    pub env_remove: Vec<B64>,
    pub env_clear: bool,
    pub cwd: B64,
    pub stdin: bool,
    /// The shim stops the program this long after it started, when
    /// `kill_on_timeout`.
    pub timeout_ms: Option<u64>,
    pub kill_on_timeout: bool,
    pub stop_grace_ms: u64,
    pub log_max_bytes: u64,
    pub name: Option<String>,
    pub summary: String,
    pub created_at_ms: u64,
    /// The SHA-256 of the request's `ExecSpec` (hex), to tell a repeat of
    /// a request with a client-chosen job ID from another request.
    pub spec_sha256: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    #[default]
    Running,
    Exited,
    Signaled,
    FailedToStart,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StreamStatus {
    /// Every byte the stream produced (and the log kept).
    pub total: u64,
    /// The absolute offset where the current `.log` file starts.
    pub current_start: u64,
    /// The absolute offset where the rotated `.log.1` file starts.
    pub previous_start: Option<u64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct StatusFile {
    #[serde(default = "first_format")]
    pub format: u32,
    pub state: State,
    pub code: Option<i32>,
    pub signal: Option<i32>,
    pub message: Option<String>,
    pub pid: Option<u32>,
    pub pgid: Option<u32>,
    pub shim_pid: u32,
    /// The shim's start time from `/proc/<pid>/stat`, against pid reuse.
    pub shim_start: u64,
    pub started_at_ms: u64,
    /// When the program ended.
    pub ended_at_ms: Option<u64>,
    /// When the job finished (with `tree_gone`): a job keeps what its
    /// program left, so this can be long after `ended_at_ms`. Older files
    /// have none.
    pub finished_at_ms: Option<u64>,
    pub timed_out: bool,
    /// Nothing is left in the job's session (processes that started a
    /// session of their own aside) and the logs are final: the job is
    /// finished.
    pub tree_gone: bool,
    /// The processes in the job's session below the shim, the program
    /// included, as the shim last counted them (0 when finished).
    pub processes: u32,
    /// How many processes the program left in the job's session the shim
    /// stopped after it ended by itself (an Exec's leftovers).
    pub stopped: u32,
    pub stdout: StreamStatus,
    pub stderr: StreamStatus,
    pub log_error: Option<String>,
}

impl StatusFile {
    #[must_use]
    pub fn stream(&self, stream: Stream) -> &StreamStatus {
        match stream {
            Stream::Stdout => &self.stdout,
            Stream::Stderr => &self.stderr,
        }
    }

    pub fn stream_mut(&mut self, stream: Stream) -> &mut StreamStatus {
        match stream {
            Stream::Stdout => &mut self.stdout,
            Stream::Stderr => &mut self.stderr,
        }
    }
}

#[must_use]
pub fn log_name(stream: Stream) -> &'static str {
    match stream {
        Stream::Stdout => "stdout.log",
        Stream::Stderr => "stderr.log",
    }
}

#[must_use]
pub fn rotated_name(stream: Stream) -> &'static str {
    match stream {
        Stream::Stdout => "stdout.log.1",
        Stream::Stderr => "stderr.log.1",
    }
}

fn newer(what: &str, format: u32) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("{what} has format {format}, newer than this ghostd's {FORMAT}"),
    )
}

/// Reads `status.json`: `None` when there is none (yet).
///
/// # Errors
///
/// When it exists but cannot be read or parsed, or is of a newer format.
pub fn read_status_checked(dir: &Path) -> io::Result<Option<StatusFile>> {
    let bytes = match fs::read(dir.join(STATUS)) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let status: StatusFile = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{STATUS}: {e}")))?;
    if status.format > FORMAT {
        return Err(newer(STATUS, status.format));
    }
    Ok(Some(status))
}

/// Reads `status.json`, `None` when it is missing or unreadable.
#[must_use]
pub fn read_status(dir: &Path) -> Option<StatusFile> {
    read_status_checked(dir).ok().flatten()
}

/// Replaces `status.json` atomically.
///
/// # Errors
///
/// When it cannot be written.
pub fn write_status(dir: &Path, status: &StatusFile, sync: bool) -> io::Result<()> {
    let bytes = serde_json::to_vec(status).map_err(io::Error::other)?;
    atomic_write(&dir.join(STATUS), &bytes, 0o600, sync)
}

/// Claims the [`RULE`] of an Exec with `keep_on_timeout`, atomically:
/// `Ok(None)` when this call set it to `rule`, `Ok(Some(other))` with the
/// rule another claim set first.
///
/// # Errors
///
/// When the file can be neither created nor read.
pub fn claim_rule(dir: &Path, rule: &str) -> io::Result<Option<String>> {
    let path = dir.join(RULE);
    let temp = dir.join(format!(
        ".{RULE}.{}.{}",
        std::process::id(),
        crate::util::now_ms()
    ));
    fs::write(&temp, rule)?;
    // A hard link never replaces an existing file: the first claim wins,
    // and the file is complete before its name appears.
    let linked = fs::hard_link(&temp, &path);
    let _ = fs::remove_file(&temp);
    match linked {
        Ok(()) => Ok(None),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            Ok(Some(fs::read_to_string(&path)?.trim().to_string()))
        }
        Err(e) => Err(e),
    }
}

/// Reads `spec.json`.
///
/// # Errors
///
/// When it cannot be read or parsed, or is of a newer format.
pub fn read_spec(dir: &Path) -> io::Result<SpecFile> {
    let bytes = fs::read(dir.join(SPEC))?;
    let spec: SpecFile = serde_json::from_slice(&bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{SPEC}: {e}")))?;
    if spec.format > FORMAT {
        return Err(newer(SPEC, spec.format));
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_of_other_versions_are_read() {
        let dir = tempfile::tempdir().unwrap();
        // A newer build's fields are ignored, missing ones defaulted.
        fs::write(
            dir.path().join(SPEC),
            br#"{"kind":"exec","argv":["c2g="],"cwd":"Lw==","created_at_ms":5,"added_later":{"x":1}}"#,
        )
        .unwrap();
        let spec = read_spec(dir.path()).unwrap();
        assert_eq!(spec.format, 1);
        assert_eq!(spec.kind, Kind::Exec);
        assert_eq!(spec.argv, vec![B64(b"sh".to_vec())]);
        assert_eq!(spec.created_at_ms, 5);
        fs::write(
            dir.path().join(STATUS),
            br#"{"state":"exited","code":3,"shim_pid":7,"tree_gone":true,"stdout":{"total":9,"new":0},"new":[]}"#,
        )
        .unwrap();
        let status = read_status_checked(dir.path()).unwrap().unwrap();
        assert_eq!(status.state, State::Exited);
        assert_eq!(status.code, Some(3));
        assert_eq!(status.stdout.total, 9);
        assert!(status.tree_gone);
        // A newer format is refused; a broken file is an error, not "none".
        fs::write(dir.path().join(STATUS), br#"{"format":2}"#).unwrap();
        assert_eq!(
            read_status_checked(dir.path()).unwrap_err().kind(),
            io::ErrorKind::Unsupported
        );
        fs::write(dir.path().join(STATUS), b"{").unwrap();
        assert!(read_status_checked(dir.path()).is_err());
        fs::remove_file(dir.path().join(STATUS)).unwrap();
        assert!(read_status_checked(dir.path()).unwrap().is_none());
    }

    #[test]
    fn the_first_rule_claim_wins() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(claim_rule(dir.path(), RULE_JOB).unwrap(), None);
        assert_eq!(
            claim_rule(dir.path(), RULE_EXEC).unwrap().as_deref(),
            Some(RULE_JOB)
        );
        assert_eq!(
            claim_rule(dir.path(), RULE_JOB).unwrap().as_deref(),
            Some(RULE_JOB)
        );
        // No temp file is left.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
