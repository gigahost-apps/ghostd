//! The files of a job directory, shared by the worker and the shim.
//!
//! `<state>/jobs/<id>/`: `spec.json` (what to run), `stdin` and `script`
//! when given, `status.json` (written by the shim, atomically),
//! `stdout.log` / `stderr.log` and one rotated `.1` each, `log.lock` (held
//! exclusively by the shim while it rotates, shared by readers while they
//! open the logs) and `stop` (the grace a stop asks for).

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Exec,
    Job,
}

/// What the shim runs, everything resolved by the worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecFile {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Running,
    Exited,
    Signaled,
    FailedToStart,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamStatus {
    /// Every byte the stream produced (and the log kept).
    pub total: u64,
    /// The absolute offset where the current `.log` file starts.
    pub current_start: u64,
    /// The absolute offset where the rotated `.log.1` file starts.
    pub previous_start: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusFile {
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
    pub ended_at_ms: Option<u64>,
    pub timed_out: bool,
    /// Everything the program started is gone and the logs are final.
    pub tree_gone: bool,
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

#[must_use]
pub fn read_status(dir: &Path) -> Option<StatusFile> {
    let bytes = fs::read(dir.join(STATUS)).ok()?;
    serde_json::from_slice(&bytes).ok()
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

/// Reads `spec.json`.
///
/// # Errors
///
/// When it cannot be read or parsed.
pub fn read_spec(dir: &Path) -> io::Result<SpecFile> {
    let bytes = fs::read(dir.join(SPEC))?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}
