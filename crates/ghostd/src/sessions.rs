//! Sessions, seen from the worker: starting their shims, relaying requests
//! to them, reading their final screens and logs, closing them and
//! collecting old ones. A session's directory is
//! `<state>/sessions/<id>/`, with a job's files (see [`crate::jobfiles`])
//! and the shim's socket and final screen (see
//! [`crate::shim::run_session`]).

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ghostd_protocol::v1;
use ghostd_protocol::v2::{
    Error, ErrorKind, Key, LogSlice, MAX_DATA, Screen, SessionInfo, SessionSpec, Stream, Until,
};
use nix::sys::signal::{Signal, kill};

use crate::config::Config;
use crate::jobfiles::{FORMAT, Kind, SPEC, SpecFile, State, read_spec, read_status};
use crate::jobs::{Jobs, POLL, abandoned, check_bytes, pid, read_log, spec_digest, summarize};
use crate::procfs;
use crate::sessproto::{self, CallError, ShimRequest, ShimResponse};
use crate::shim::session::{COLS, MAX_READ_WAIT_MS, ROWS, SCREEN, SCROLLBACK, holds_on_final};
use crate::util::{B64, atomic_write, io_error, now_ms, random_hex, resolve};

/// How long a relayed request may take beyond what it waits for.
const RELAY_MARGIN: Duration = Duration::from_secs(15);

pub struct Sessions {
    root: PathBuf,
    config: Config,
    start_lock: tokio::sync::Mutex<()>,
}

fn valid_id(id: &str) -> bool {
    id.len() == 17
        && id.starts_with('s')
        && id[1..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn err(kind: ErrorKind, message: impl Into<String>) -> Error {
    Error::new(kind, message)
}

fn not_found(id: &str) -> Error {
    err(ErrorKind::NotFound, format!("no session {id}"))
}

fn ended(id: &str) -> Error {
    err(ErrorKind::Conflict, format!("session {id} has ended"))
}

fn read_error(id: &str, e: &io::Error) -> Error {
    if e.kind() == io::ErrorKind::NotFound {
        not_found(id)
    } else {
        io_error(e, &format!("reading session {id}")).into()
    }
}

fn v2(e: v1::Error) -> Error {
    e.into()
}

async fn blocking<T, F>(f: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| err(ErrorKind::Internal, format!("a task failed: {e}")))?
}

/// The final screen a session's shim wrote when it ended.
fn final_screen(dir: &Path) -> io::Result<Screen> {
    let bytes = fs::read(dir.join(SCREEN))?;
    serde_json::from_slice(&bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Keeps the last `lines` lines of a saved scrollback (none for 0).
fn trim_scrollback(screen: &mut Screen, lines: usize) {
    screen.scrollback = match (lines, screen.scrollback.take()) {
        (0, _) | (_, None) => None,
        (n, Some(all)) => {
            let kept: Vec<&str> = all.split('\n').collect();
            let from = kept.len().saturating_sub(n);
            Some(kept[from..].join("\n"))
        }
    };
}

enum Created {
    New(String, PathBuf),
    Exists(String),
}

impl Sessions {
    #[must_use]
    pub fn new(root: PathBuf, config: Config) -> Self {
        Self {
            root,
            config,
            start_lock: tokio::sync::Mutex::new(()),
        }
    }

    fn dir(&self, id: &str) -> Result<PathBuf, Error> {
        if !valid_id(id) {
            return Err(not_found(id));
        }
        let dir = self.root.join(id);
        if dir.join(SPEC).is_file() {
            Ok(dir)
        } else {
            Err(not_found(id))
        }
    }

    fn ids(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|e| e.file_name().to_str().map(str::to_string))
            .filter(|id| valid_id(id))
            .collect()
    }

    fn info_of(id: &str, live: &crate::jobs::Live) -> SessionInfo {
        let status = live.status.as_ref();
        SessionInfo {
            session_id: id.to_string(),
            name: live.spec.name.clone(),
            argv_summary: live.spec.summary.clone(),
            state: Jobs::state(live),
            started_at_ms: status.map_or(live.spec.created_at_ms, |s| s.started_at_ms),
            ended_at_ms: status.and_then(|s| s.ended_at_ms),
            pid: status.and_then(|s| s.pid),
            cols: status
                .and_then(|s| s.cols)
                .or(live.spec.cols)
                .unwrap_or(120),
            rows: status.and_then(|s| s.rows).or(live.spec.rows).unwrap_or(40),
            output_total: status.map_or(0, |s| s.stdout.total),
            finished: !live.busy,
        }
    }

    fn live(dir: &Path, id: &str) -> Result<crate::jobs::Live, Error> {
        Jobs::live(dir).map_err(|e| read_error(id, &e))
    }

    /// A session's info.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown session.
    pub fn info(&self, id: &str) -> Result<SessionInfo, Error> {
        let dir = self.dir(id)?;
        let live = Self::live(&dir, id)?;
        Ok(Self::info_of(id, &live))
    }

    /// Every kept session, newest first.
    #[must_use]
    pub fn list(&self) -> Vec<SessionInfo> {
        let mut sessions: Vec<SessionInfo> = self
            .ids()
            .into_iter()
            .filter_map(|id| {
                let live = Jobs::live(&self.root.join(&id)).ok()?;
                Some(Self::info_of(&id, &live))
            })
            .collect();
        sessions.sort_by(|a, b| {
            b.started_at_ms
                .cmp(&a.started_at_ms)
                .then_with(|| b.session_id.cmp(&a.session_id))
        });
        sessions
    }

    /// How many sessions still have a running shim.
    #[must_use]
    pub fn live_count(&self) -> usize {
        self.ids()
            .iter()
            .filter(|id| Jobs::live(&self.root.join(id)).is_ok_and(|l| l.busy))
            .count()
    }

    fn prepare(&self, spec: &SessionSpec, digest: String) -> Result<SpecFile, Error> {
        let argv = if let Some(argv) = &spec.argv {
            if argv.first().is_none_or(Vec::is_empty) {
                return Err(err(
                    ErrorKind::InvalidArgument,
                    "argv is empty or its program is empty",
                ));
            }
            argv.clone()
        } else {
            let shell = std::env::var_os("SHELL")
                .filter(|s| !s.is_empty())
                .map_or_else(
                    || b"/bin/sh".to_vec(),
                    std::ffi::OsString::into_encoded_bytes,
                );
            vec![shell, b"-l".to_vec()]
        };
        for arg in &argv {
            check_bytes("an argument", arg).map_err(v2)?;
        }
        for (name, value) in &spec.env {
            if name.is_empty() || name.contains(&b'=') {
                return Err(err(
                    ErrorKind::InvalidArgument,
                    "an environment name is empty or holds '='",
                ));
            }
            check_bytes("an environment name", name).map_err(v2)?;
            check_bytes("an environment value", value).map_err(v2)?;
        }
        for name in &spec.env_remove {
            check_bytes("an environment name", name).map_err(v2)?;
        }
        let cols = spec.cols.unwrap_or(120);
        let rows = spec.rows.unwrap_or(40);
        if !COLS.contains(&cols) || !ROWS.contains(&rows) {
            return Err(err(
                ErrorKind::InvalidArgument,
                format!(
                    "a session is {}..={} columns and {}..={} rows",
                    COLS.start(),
                    COLS.end(),
                    ROWS.start(),
                    ROWS.end()
                ),
            ));
        }
        let mut env: Vec<(B64, B64)> = Vec::with_capacity(spec.env.len() + 1);
        if !spec.env.iter().any(|(n, _)| n == b"TERM") {
            env.push((B64(b"TERM".to_vec()), B64(b"xterm-256color".to_vec())));
        }
        env.extend(
            spec.env
                .iter()
                .map(|(n, v)| (B64(n.clone()), B64(v.clone()))),
        );
        let cwd = resolve(spec.cwd.as_deref().unwrap_or_default());
        Ok(SpecFile {
            format: FORMAT,
            kind: Kind::Exec,
            summary: summarize(&argv),
            argv: argv.into_iter().map(B64).collect(),
            env,
            env_remove: spec.env_remove.iter().cloned().map(B64).collect(),
            env_clear: false,
            cwd: B64(cwd.into_os_string().into_encoded_bytes()),
            stdin: false,
            timeout_ms: None,
            kill_on_timeout: false,
            stop_grace_ms: self.config.stop_grace_ms,
            log_max_bytes: self.config.log_max_bytes,
            name: spec.name.clone(),
            created_at_ms: now_ms(),
            spec_sha256: digest,
            cols: Some(cols),
            rows: Some(rows),
        })
    }

    fn create(&self, spec: &SessionSpec) -> Result<Created, Error> {
        let digest = spec_digest(spec);
        if let Some(id) = &spec.session_id {
            if !valid_id(id) {
                return Err(err(
                    ErrorKind::InvalidArgument,
                    "session_id is `s` and 16 lowercase hex digits",
                ));
            }
            let dir = self.root.join(id);
            if fs::symlink_metadata(&dir).is_ok() {
                let kept = read_spec(&dir).map_err(|e| {
                    err(
                        ErrorKind::Conflict,
                        format!(
                            "session {id} exists but cannot be read ({e}); choose another \
                             session_id"
                        ),
                    )
                })?;
                if kept.spec_sha256 != digest {
                    return Err(err(
                        ErrorKind::Conflict,
                        format!(
                            "session {id} exists for another request; choose another session_id"
                        ),
                    ));
                }
                return Ok(Created::Exists(id.clone()));
            }
        }
        let live = self.live_count();
        if live as u64 >= self.config.max_sessions {
            return Err(err(
                ErrorKind::Busy,
                format!("{live} sessions run, the most allowed (max_sessions); close one"),
            ));
        }
        let id = match &spec.session_id {
            Some(id) => id.clone(),
            None => format!(
                "s{}",
                random_hex(8).map_err(|e| v2(io_error(&e, "random bytes")))?
            ),
        };
        let dir = self.root.join(&id);
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| v2(io_error(&e, "creating the session directory")))?;
        let file = match self.prepare(spec, digest) {
            Ok(file) => file,
            Err(e) => {
                let _ = fs::remove_dir_all(&dir);
                return Err(e);
            }
        };
        let bytes =
            serde_json::to_vec(&file).map_err(|e| err(ErrorKind::Internal, e.to_string()))?;
        if let Err(e) = atomic_write(&dir.join(SPEC), &bytes, 0o600, true) {
            let _ = fs::remove_dir_all(&dir);
            return Err(v2(io_error(&e, "writing the session's spec")));
        }
        Ok(Created::New(id, dir))
    }

    /// Starts a session and waits until its program runs (or failed to
    /// start). A client-chosen ID of a kept session of the same request
    /// answers that session.
    ///
    /// # Errors
    ///
    /// When the spec is invalid, too many sessions run, or it cannot start.
    pub async fn start(self: &Arc<Self>, spec: SessionSpec) -> Result<String, Error> {
        let _guard = self.start_lock.lock().await;
        let this = Arc::clone(self);
        let (id, dir) = match blocking(move || this.create(&spec)).await? {
            Created::New(id, dir) => (id, dir),
            Created::Exists(id) => return Ok(id),
        };
        let mut command = tokio::process::Command::new("/proc/self/exe");
        command
            .arg0("ghostd")
            .arg("shim")
            .arg(&dir)
            .arg("--session")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                let _ = fs::remove_dir_all(&dir);
                return Err(v2(io_error(&e, "starting the session's shim")));
            }
        };
        let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let _ = child.wait().await;
            let _ = done_tx.send(());
        });
        let begun = Instant::now();
        let status = loop {
            if let Some(status) = read_status(&dir) {
                break status;
            }
            if !matches!(
                done_rx.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ) && read_status(&dir).is_none()
            {
                let _ = fs::remove_dir_all(&dir);
                return Err(err(
                    ErrorKind::Internal,
                    "the session's shim exited before it started the program",
                ));
            }
            if begun.elapsed() > Duration::from_secs(10) {
                return Err(err(
                    ErrorKind::Internal,
                    format!("the shim of {id} did not start the program within 10 s"),
                ));
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        if status.state == State::FailedToStart {
            let _ = fs::remove_dir_all(&dir);
            return Err(err(
                ErrorKind::NotFound,
                status
                    .message
                    .unwrap_or_else(|| "the program did not start".into()),
            ));
        }
        Ok(id)
    }

    /// Sends `request` to a live session's shim. `None`: no shim answers
    /// (the session has ended, or its shim is gone).
    async fn relay(
        dir: &Path,
        request: &ShimRequest,
        timeout: Duration,
    ) -> Result<Option<ShimResponse>, Error> {
        match sessproto::call(dir, request, timeout).await {
            Ok(response) => Ok(Some(response)),
            Err(CallError::Unreachable) => Ok(None),
            Err(CallError::Failed(e)) => Err(e),
        }
    }

    /// Relays a request that needs the session's program to run.
    async fn relay_live(&self, id: &str, request: ShimRequest) -> Result<(), Error> {
        let dir = self.dir(id)?;
        let d = dir.clone();
        let i = id.to_string();
        let live = blocking(move || Self::live(&d, &i)).await?;
        if !live.busy {
            return Err(ended(id));
        }
        match Self::relay(&dir, &request, RELAY_MARGIN).await? {
            Some(ShimResponse::Done) => Ok(()),
            Some(ShimResponse::Screen(_)) => Err(err(
                ErrorKind::Internal,
                "the session's shim answered a screen",
            )),
            None => Err(ended(id)),
        }
    }

    /// Types into a session.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Conflict` once it has ended, `Busy` while the program
    /// has not read what was sent before.
    pub async fn send(&self, id: &str, input: Vec<Key>) -> Result<(), Error> {
        self.relay_live(id, ShimRequest::Send(input)).await
    }

    /// Resizes a session's terminal.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Conflict` once it has ended, `InvalidArgument` for a
    /// size out of range.
    pub async fn resize(&self, id: &str, cols: u16, rows: u16) -> Result<(), Error> {
        self.relay_live(id, ShimRequest::Resize { cols, rows })
            .await
    }

    /// Signals a session's foreground process group.
    ///
    /// # Errors
    ///
    /// `NotFound`, `Conflict` once it has ended.
    pub async fn signal(&self, id: &str, signal: i32) -> Result<(), Error> {
        self.relay_live(id, ShimRequest::Signal(signal)).await
    }

    /// A session's screen: from its shim while it runs, else the final one.
    ///
    /// # Errors
    ///
    /// `NotFound`, `InvalidArgument` for a bad regex or more than 1000
    /// scrollback lines.
    pub async fn read(
        &self,
        id: &str,
        wait_ms: u64,
        until: Option<Until>,
        scrollback_lines: u32,
    ) -> Result<Screen, Error> {
        if scrollback_lines as usize > SCROLLBACK {
            return Err(err(
                ErrorKind::InvalidArgument,
                format!("scrollback_lines is at most {SCROLLBACK}"),
            ));
        }
        if let Some(Until::Matches(pattern)) = &until {
            crate::shim::session::regex(pattern)?;
        }
        let dir = self.dir(id)?;
        let d = dir.clone();
        let i = id.to_string();
        let live = blocking(move || Self::live(&d, &i)).await?;
        if live.busy {
            let wait = wait_ms.min(MAX_READ_WAIT_MS);
            let request = ShimRequest::Read {
                wait_ms: wait,
                until: until.clone(),
                scrollback_lines,
            };
            match Self::relay(&dir, &request, Duration::from_millis(wait) + RELAY_MARGIN).await? {
                Some(ShimResponse::Screen(screen)) => return Ok(screen),
                Some(ShimResponse::Done) => {
                    return Err(err(
                        ErrorKind::Internal,
                        "the session's shim answered no screen",
                    ));
                }
                None => {}
            }
        }
        let id = id.to_string();
        blocking(move || {
            let mut screen = match final_screen(&dir) {
                Ok(screen) => screen,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let live = Self::live(&dir, &id)?;
                    return Err(if live.busy {
                        err(
                            ErrorKind::Internal,
                            format!("the shim of session {id} does not answer"),
                        )
                    } else {
                        err(
                            ErrorKind::Conflict,
                            format!("session {id} is lost: its shim left no final screen"),
                        )
                    });
                }
                Err(e) => return Err(v2(io_error(&e, "reading the final screen"))),
            };
            trim_scrollback(&mut screen, scrollback_lines as usize);
            screen.until_met = until
                .as_ref()
                .map(|u| holds_on_final(u, &screen))
                .transpose()?;
            Ok(screen)
        })
        .await
    }

    /// Hangs a session up and stops everything it started; answers once
    /// all is gone.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown session.
    pub async fn close(
        self: &Arc<Self>,
        id: String,
        grace_ms: Option<u64>,
    ) -> Result<SessionInfo, Error> {
        let dir = self.dir(&id)?;
        let grace = grace_ms.unwrap_or(self.config.stop_grace_ms);
        let d = dir.clone();
        let i = id.clone();
        let live = blocking(move || Self::live(&d, &i)).await?;
        let shim = match (&live.status, live.busy) {
            (Some(s), true) => Some((s.shim_pid, s.shim_start)),
            _ => None,
        };
        if let Some((shim_pid, shim_start)) = shim {
            let request = ShimRequest::Close { grace_ms: grace };
            let asked = Self::relay(&dir, &request, RELAY_MARGIN).await;
            if !matches!(asked, Ok(Some(_))) && procfs::is_same_process(shim_pid, shim_start) {
                // Its socket does not answer: a SIGTERM is a close too.
                let _ = kill(pid(shim_pid), Signal::SIGTERM);
            }
            let until = Instant::now() + Duration::from_millis(grace) + Duration::from_secs(30);
            while Instant::now() < until {
                let gone = !procfs::is_same_process(shim_pid, shim_start)
                    || read_status(&dir).is_some_and(|s| s.tree_gone);
                if gone {
                    break;
                }
                tokio::time::sleep(POLL).await;
            }
        }
        let this = Arc::clone(self);
        blocking(move || this.info(&id)).await
    }

    /// A slice of a session's raw output.
    ///
    /// # Errors
    ///
    /// `NotFound`, `TooLarge` past [`MAX_DATA`], or an I/O failure.
    pub fn log_read(&self, id: &str, offset: Option<u64>, max_len: u32) -> Result<LogSlice, Error> {
        if max_len as usize > MAX_DATA {
            return Err(err(
                ErrorKind::TooLarge,
                format!("max_len is at most {MAX_DATA}"),
            ));
        }
        let dir = self.dir(id)?;
        let live = Self::live(&dir, id)?;
        let ended = !live.busy && live.status.is_some();
        let read = read_log(&dir, Stream::Stdout, offset, max_len as usize)
            .map_err(|e| v2(io_error(&e, "reading the log")))?;
        Ok(LogSlice {
            data: read.data,
            offset: read.offset,
            total: read.total,
            first_available: read.first_available,
            ended,
        })
    }

    /// The directory of a session, for a wait on its log.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown session.
    pub fn log_dir(&self, id: &str) -> Result<PathBuf, Error> {
        self.dir(id)
    }

    /// Removes ended sessions past `exec_retention_hours`, then the oldest
    /// ended beyond `max_jobs_kept`. Never a live one, nor one it cannot
    /// read.
    pub fn gc(&self) -> usize {
        let now = now_ms();
        let mut ended = Vec::new();
        for id in self.ids() {
            let dir = self.root.join(&id);
            let Ok(live) = Jobs::live(&dir) else {
                if abandoned(&dir) {
                    let _ = fs::remove_dir_all(&dir);
                }
                continue;
            };
            if live.busy {
                continue;
            }
            let finished_at = live.status.as_ref().map_or(live.spec.created_at_ms, |s| {
                s.finished_at_ms
                    .or(s.ended_at_ms)
                    .unwrap_or(s.started_at_ms)
            });
            ended.push((finished_at, dir));
        }
        ended.sort_by_key(|(finished_at, _)| *finished_at);
        let retention = self.config.exec_retention_hours.saturating_mul(3_600_000);
        let mut removed = 0;
        let mut kept = ended.len();
        for (finished_at, dir) in ended {
            let old = now.saturating_sub(finished_at) >= retention;
            if (old || kept as u64 > self.config.max_jobs_kept) && fs::remove_dir_all(&dir).is_ok()
            {
                removed += 1;
                kept -= 1;
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids() {
        assert!(valid_id("s0123456789abcdef"));
        assert!(!valid_id("j0123456789abcdef"));
        assert!(!valid_id("s../../etc/passwd"));
    }

    fn session(root: &Path, id: &str, live: bool, finished_ago_min: u64) {
        use crate::jobfiles::{FORMAT, StatusFile, write_status};
        let dir = root.join(id);
        fs::create_dir(&dir).unwrap();
        let ago = now_ms() - finished_ago_min * 60_000;
        let spec = SpecFile {
            created_at_ms: ago - 60_000,
            ..SpecFile::default()
        };
        fs::write(dir.join(SPEC), serde_json::to_vec(&spec).unwrap()).unwrap();
        let me = std::process::id();
        let status = if live {
            // Its shim runs: this process stands in for it.
            StatusFile {
                format: FORMAT,
                shim_pid: me,
                shim_start: procfs::start_time(me).unwrap(),
                started_at_ms: ago - 60_000,
                ..StatusFile::default()
            }
        } else {
            StatusFile {
                format: FORMAT,
                state: State::Exited,
                code: Some(0),
                started_at_ms: ago - 60_000,
                ended_at_ms: Some(ago),
                finished_at_ms: Some(ago),
                tree_gone: true,
                ..StatusFile::default()
            }
        };
        write_status(&dir, &status, false).unwrap();
    }

    #[test]
    fn gc_keeps_live_sessions() {
        let root = tempfile::tempdir().unwrap();
        let config = Config {
            exec_retention_hours: 1,
            max_jobs_kept: 1,
            ..Config::default()
        };
        let sessions = Sessions::new(root.path().to_path_buf(), config);
        // Live for days, and over every limit: kept.
        session(root.path(), "s000000000000000a", true, 3 * 24 * 60);
        session(root.path(), "s000000000000000b", true, 3 * 24 * 60);
        // Ended past the retention.
        session(root.path(), "s000000000000000c", false, 90);
        // Ended within it, two of them over max_jobs_kept: the older goes.
        session(root.path(), "s000000000000000d", false, 30);
        session(root.path(), "s000000000000000e", false, 10);
        assert_eq!(sessions.gc(), 2);
        let mut left = sessions.ids();
        left.sort();
        assert_eq!(
            left,
            [
                "s000000000000000a",
                "s000000000000000b",
                "s000000000000000e"
            ]
        );
        assert_eq!(sessions.live_count(), 2);
    }

    #[test]
    fn scrollback_trimmed_to_the_last_lines() {
        let mut screen = Screen {
            scrollback: Some("a\nb\nc".into()),
            ..Screen::default()
        };
        trim_scrollback(&mut screen, 2);
        assert_eq!(screen.scrollback.as_deref(), Some("b\nc"));
        trim_scrollback(&mut screen, 0);
        assert_eq!(screen.scrollback, None);
    }
}
