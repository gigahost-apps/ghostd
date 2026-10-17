//! Jobs, seen from the worker: starting shims, reading their state and
//! logs, stopping them and collecting old ones.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ghostd_protocol::v1::{
    Error, ErrorKind, ExecResult, ExecSpec, JobInfo, JobState, LogSlice, MAX_DATA, Outcome, Output,
    Program, Stream,
};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, kill, killpg};
use nix::unistd::Pid;
use sha2::{Digest, Sha256};

use crate::config::{Config, MAX_EXEC_TIMEOUT_MS, MAX_OUTPUT_CAP};
use crate::jobfiles::{
    FORMAT, Kind, LOG_LOCK, RULE_JOB, SCRIPT, SPEC, STATUS, STDIN, STOP, SpecFile, State,
    StatusFile, claim_rule, log_name, read_spec, read_status, read_status_checked, rotated_name,
};
use crate::procfs;
use crate::shim::SETTLE;
use crate::util::{B64, atomic_write, err, io_error, now_ms, random_hex, resolve};

/// How long a `JobWait` may wait.
const MAX_WAIT_MS: u64 = 60_000;
/// A job directory without a status this old is a shim that never started.
pub const STARTING_GRACE_MS: u64 = 30_000;
/// A job directory with neither a spec nor a status this old is one the
/// worker died creating (no shim ever started for it).
const ABANDONED_AFTER: Duration = Duration::from_hours(1);
/// What an exec's two outputs may take of a frame, leaving room for the rest.
const EXEC_OUTPUT_BUDGET: usize = ghostd_protocol::MAX_FRAME - 64 * 1024;
/// How often job state is polled.
pub const POLL: Duration = Duration::from_millis(50);

pub struct Jobs {
    root: PathBuf,
    config: Config,
    start_lock: tokio::sync::Mutex<()>,
}

/// A job's (or a session's) state as read from its directory.
pub struct Live {
    pub spec: SpecFile,
    pub status: Option<StatusFile>,
    /// The shim (and so the program or what it left) still runs.
    pub busy: bool,
}

fn valid_id(id: &str) -> bool {
    id.len() == 17
        && id.starts_with('j')
        && id[1..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn not_found(id: &str) -> Error {
    err(ErrorKind::NotFound, format!("no job {id}"))
}

/// A job directory that cannot be read: gone meanwhile, or written by
/// another ghostd in a format this one does not know.
fn read_error(id: &str, e: &io::Error) -> Error {
    if e.kind() == io::ErrorKind::NotFound {
        not_found(id)
    } else {
        io_error(e, &format!("reading job {id}"))
    }
}

fn blocking_error(e: &tokio::task::JoinError) -> Error {
    err(ErrorKind::Internal, format!("a task failed: {e}"))
}

/// Runs blocking work off the async threads.
async fn blocking<T, F>(f: F) -> Result<T, Error>
where
    F: FnOnce() -> Result<T, Error> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| blocking_error(&e))?
}

pub fn pid(raw: u32) -> Pid {
    Pid::from_raw(i32::try_from(raw).unwrap_or(i32::MAX))
}

/// The first four arguments, lossy, at most 200 characters.
pub fn summarize(argv: &[Vec<u8>]) -> String {
    let joined = argv
        .iter()
        .take(4)
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .collect::<Vec<_>>()
        .join(" ");
    joined.chars().take(200).collect()
}

pub fn check_bytes(what: &str, bytes: &[u8]) -> Result<(), Error> {
    if bytes.contains(&0) {
        return Err(err(
            ErrorKind::InvalidArgument,
            format!("{what} contains a NUL byte"),
        ));
    }
    Ok(())
}

impl Jobs {
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

    /// Reads a job's files. A status that exists but cannot be read is an
    /// error, never "no status": a job is only ever taken for finished on
    /// what its own status says.
    pub fn live(dir: &Path) -> io::Result<Live> {
        let spec = read_spec(dir)?;
        let mut status = read_status_checked(dir)?;
        let busy = match &status {
            // Starting, or a shim that could not write its status: only
            // a shim no longer running for it makes such a job finished.
            None => {
                now_ms().saturating_sub(spec.created_at_ms) < STARTING_GRACE_MS
                    || procfs::shim_runs_for(dir)
            }
            Some(s) if s.tree_gone => false,
            Some(s) => {
                let alive = procfs::is_same_process(s.shim_pid, s.shim_start);
                if !alive {
                    // It may have written its final state just before
                    // exiting: read again.
                    status = read_status_checked(dir)?;
                }
                alive
            }
        };
        Ok(Live { spec, status, busy })
    }

    pub fn state(live: &Live) -> JobState {
        match &live.status {
            None if live.busy => JobState::Running,
            None => JobState::Lost,
            // Its shim is gone before the job finished, also when the
            // program had ended: what it left may still run, and nothing
            // watches or stops it any more.
            Some(s) if !live.busy && !s.tree_gone => JobState::Lost,
            Some(s) => match s.state {
                State::Running if live.busy => JobState::Running,
                State::Running | State::FailedToStart => JobState::Lost,
                State::Exited => JobState::Exited {
                    code: s.code.unwrap_or(-1),
                },
                State::Signaled => JobState::Signaled {
                    signal: s.signal.unwrap_or(0),
                },
            },
        }
    }

    fn info_of(id: &str, live: &Live) -> JobInfo {
        let status = live.status.as_ref();
        JobInfo {
            job_id: id.to_string(),
            name: live.spec.name.clone(),
            argv_summary: live.spec.summary.clone(),
            state: Self::state(live),
            started_at_ms: status.map_or(live.spec.created_at_ms, |s| s.started_at_ms),
            ended_at_ms: status.and_then(|s| s.ended_at_ms),
            stdout_total: status.map_or(0, |s| s.stdout.total),
            stderr_total: status.map_or(0, |s| s.stderr.total),
            pid: status.and_then(|s| s.pid),
            processes: match status {
                _ if !live.busy => 0,
                Some(s) => s.processes,
                // Starting: the program is about to run.
                None => 1,
            },
            finished: !live.busy,
        }
    }

    /// A job's directory, for a wait on its log.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job.
    pub fn log_dir(&self, id: &str) -> Result<PathBuf, Error> {
        self.dir(id)
    }

    /// A job's info.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job.
    pub fn info(&self, id: &str) -> Result<JobInfo, Error> {
        let dir = self.dir(id)?;
        let live = Self::live(&dir).map_err(|e| read_error(id, &e))?;
        Ok(Self::info_of(id, &live))
    }

    /// Every job directory's ID.
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

    /// The jobs, newest first.
    #[must_use]
    pub fn list(&self, include_finished: bool, limit: u32) -> Vec<JobInfo> {
        let limit = if limit == 0 { 100 } else { limit as usize };
        let mut jobs: Vec<JobInfo> = self
            .ids()
            .into_iter()
            .filter_map(|id| {
                let live = Self::live(&self.root.join(&id)).ok()?;
                Some(Self::info_of(&id, &live))
            })
            .filter(|info| include_finished || !info.finished)
            .collect();
        jobs.sort_by(|a, b| {
            b.started_at_ms
                .cmp(&a.started_at_ms)
                .then_with(|| b.job_id.cmp(&a.job_id))
        });
        jobs.truncate(limit);
        jobs
    }

    /// How many jobs still have a running shim, and how many are finished.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        let mut running = 0;
        let mut finished = 0;
        for id in self.ids() {
            match Self::live(&self.root.join(&id)) {
                Ok(live) if live.busy => running += 1,
                Ok(_) => finished += 1,
                Err(_) => {}
            }
        }
        (running, finished)
    }

    /// Resolves an [`ExecSpec`] into what the shim runs, writing the stdin
    /// and script files into `dir`.
    #[allow(clippy::too_many_lines)]
    fn prepare(
        &self,
        spec: &ExecSpec,
        kind: Kind,
        dir: &Path,
        digest: String,
    ) -> Result<SpecFile, Error> {
        let mut argv: Vec<Vec<u8>> = match &spec.program {
            Program::Argv(argv) => {
                if argv.first().is_none_or(Vec::is_empty) {
                    return Err(err(
                        ErrorKind::InvalidArgument,
                        "argv is empty or its program is empty",
                    ));
                }
                argv.clone()
            }
            Program::Script {
                body,
                interpreter,
                args,
            } => {
                let script = dir.join(SCRIPT);
                atomic_write(&script, body, 0o700, false)
                    .map_err(|e| io_error(&e, "writing the script"))?;
                let script = script.into_os_string().into_encoded_bytes();
                let mut argv = match interpreter {
                    Some(interpreter) if interpreter.first().is_none_or(Vec::is_empty) => {
                        return Err(err(ErrorKind::InvalidArgument, "the interpreter is empty"));
                    }
                    Some(interpreter) => interpreter.clone(),
                    None if body.starts_with(b"#!") => Vec::new(),
                    None => vec![b"/bin/sh".to_vec()],
                };
                argv.push(script);
                argv.extend(args.iter().cloned());
                argv
            }
        };
        for arg in &argv {
            check_bytes("an argument", arg)?;
        }
        let summary = summarize(&argv);
        if spec.login {
            let shell = std::env::var_os("SHELL")
                .filter(|s| !s.is_empty())
                .map_or_else(
                    || b"/bin/sh".to_vec(),
                    std::ffi::OsString::into_encoded_bytes,
                );
            let mut login = vec![shell, b"-lc".to_vec(), b"exec \"$0\" \"$@\"".to_vec()];
            login.append(&mut argv);
            argv = login;
        }
        for (name, value) in &spec.env {
            if name.is_empty() || name.contains(&b'=') {
                return Err(err(
                    ErrorKind::InvalidArgument,
                    "an environment name is empty or holds '='",
                ));
            }
            check_bytes("an environment name", name)?;
            check_bytes("an environment value", value)?;
        }
        for name in &spec.env_remove {
            check_bytes("an environment name", name)?;
        }
        let cwd = resolve(spec.cwd.as_deref().unwrap_or_default());
        let timeout_ms = match kind {
            Kind::Exec => {
                let t = spec.timeout_ms.unwrap_or(self.config.exec_timeout_ms);
                if t == 0 || t > MAX_EXEC_TIMEOUT_MS {
                    return Err(err(
                        ErrorKind::InvalidArgument,
                        format!("timeout_ms is 1..={MAX_EXEC_TIMEOUT_MS}"),
                    ));
                }
                Some(t)
            }
            Kind::Job => {
                if spec.timeout_ms == Some(0) {
                    return Err(err(ErrorKind::InvalidArgument, "timeout_ms is 0"));
                }
                spec.timeout_ms
            }
        };
        if let Some(stdin) = &spec.stdin {
            atomic_write(&dir.join(STDIN), stdin, 0o600, false)
                .map_err(|e| io_error(&e, "writing stdin"))?;
        }
        Ok(SpecFile {
            format: FORMAT,
            kind,
            argv: argv.into_iter().map(B64).collect(),
            env: spec
                .env
                .iter()
                .map(|(n, v)| (B64(n.clone()), B64(v.clone())))
                .collect(),
            env_remove: spec.env_remove.iter().cloned().map(B64).collect(),
            env_clear: spec.env_clear,
            cwd: B64(cwd.into_os_string().into_encoded_bytes()),
            stdin: spec.stdin.is_some(),
            timeout_ms,
            kill_on_timeout: kind == Kind::Job || !spec.keep_on_timeout,
            stop_grace_ms: self.config.stop_grace_ms,
            log_max_bytes: self.config.log_max_bytes,
            name: spec.name.clone(),
            summary,
            created_at_ms: now_ms(),
            spec_sha256: digest,
            cols: None,
            rows: None,
        })
    }

    /// The job a request with a client-chosen ID that exists names: the
    /// same request again, or a conflict.
    fn existing(id: &str, dir: PathBuf, kind: Kind, digest: &str) -> Result<Started, Error> {
        let spec = read_spec(&dir).map_err(|e| {
            err(
                ErrorKind::Conflict,
                format!("job {id} exists but cannot be read ({e}); choose another job_id"),
            )
        })?;
        if spec.kind != kind || spec.spec_sha256 != digest {
            return Err(err(
                ErrorKind::Conflict,
                format!("job {id} exists for another request; choose another job_id"),
            ));
        }
        Ok(Started {
            id: id.to_string(),
            dir,
        })
    }

    /// Creates the job's directory and spec (or finds the job a repeat
    /// names).
    fn create(&self, spec: &ExecSpec, kind: Kind) -> Result<Created, Error> {
        let digest = spec_digest(spec);
        if let Some(id) = &spec.job_id {
            if !valid_id(id) {
                return Err(err(
                    ErrorKind::InvalidArgument,
                    "job_id is `j` and 16 lowercase hex digits",
                ));
            }
            let dir = self.root.join(id);
            if fs::symlink_metadata(&dir).is_ok() {
                return Self::existing(id, dir, kind, &digest).map(Created::Exists);
            }
        }
        let (running, _) = self.counts();
        if running as u64 >= self.config.max_running_jobs {
            return Err(err(
                ErrorKind::Busy,
                format!(
                    "{running} jobs run, the most allowed (max_running_jobs); stop or wait for one"
                ),
            ));
        }
        let id = match &spec.job_id {
            Some(id) => id.clone(),
            None => format!(
                "j{}",
                random_hex(8).map_err(|e| io_error(&e, "random bytes"))?
            ),
        };
        let dir = self.root.join(&id);
        DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| io_error(&e, "creating the job directory"))?;
        let file = match self.prepare(spec, kind, &dir, digest) {
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
            return Err(io_error(&e, "writing the job's spec"));
        }
        Ok(Created::New(id, dir))
    }

    /// Starts a shim for `spec` and waits until it has started the program
    /// (or failed to). A client-chosen job ID that names a kept job of the
    /// same request starts nothing: [`StartError::Exists`].
    async fn start(self: &Arc<Self>, spec: ExecSpec, kind: Kind) -> Result<Started, StartError> {
        // Held until the shim runs, so that a repeat waits for the first.
        let _guard = self.start_lock.lock().await;
        let this = Arc::clone(self);
        let created = blocking(move || this.create(&spec, kind)).await?;
        let (id, dir) = match created {
            Created::New(id, dir) => (id, dir),
            Created::Exists(started) => return Err(StartError::Exists(started)),
        };
        let mut command = tokio::process::Command::new("/proc/self/exe");
        command
            .arg0("ghostd")
            .arg("shim")
            .arg(&dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(e) => {
                let _ = fs::remove_dir_all(&dir);
                return Err(io_error(&e, "starting the shim").into());
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
                    "the shim exited before it started the program",
                )
                .into());
            }
            if begun.elapsed() > Duration::from_secs(10) {
                return Err(err(
                    ErrorKind::Internal,
                    format!("the shim of {id} did not start the program within 10 s"),
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        if status.state == State::FailedToStart {
            let _ = fs::remove_dir_all(&dir);
            return Err(StartError::Failed(
                status
                    .message
                    .unwrap_or_else(|| "the program did not start".into()),
            ));
        }
        Ok(Started { id, dir })
    }

    /// Starts a job.
    ///
    /// # Errors
    ///
    /// When the spec is invalid, too many jobs run, or it cannot start.
    pub async fn job_start(self: &Arc<Self>, spec: ExecSpec) -> Result<String, Error> {
        match self.start(spec, Kind::Job).await {
            Ok(started) | Err(StartError::Exists(started)) => Ok(started.id),
            Err(StartError::Failed(message)) => Err(err(ErrorKind::NotFound, message)),
            Err(StartError::Other(e)) => Err(e),
        }
    }

    /// Runs `spec` to its end or its timeout.
    ///
    /// # Errors
    ///
    /// When the spec is invalid, too many jobs run, or the shim vanishes.
    #[allow(clippy::too_many_lines)]
    pub async fn exec(self: &Arc<Self>, spec: ExecSpec) -> Result<ExecResult, Error> {
        let cap = spec.output_cap.unwrap_or(self.config.exec_output_cap);
        if cap > MAX_OUTPUT_CAP {
            return Err(err(
                ErrorKind::TooLarge,
                format!("output_cap is at most {MAX_OUTPUT_CAP}"),
            ));
        }
        let started = match self.start(spec, Kind::Exec).await {
            // A repeat of the request waits for the job the first started.
            Ok(started) | Err(StartError::Exists(started)) => started,
            Err(StartError::Failed(message)) => {
                return Ok(ExecResult {
                    job_id: String::new(),
                    outcome: Outcome::FailedToStart { message },
                    stdout: Output::default(),
                    stderr: Output::default(),
                    duration_ms: 0,
                    stopped: 0,
                });
            }
            Err(StartError::Other(e)) => return Err(e),
        };
        let dir = started.dir.clone();
        let d = dir.clone();
        let file =
            blocking(move || read_spec(&d).map_err(|e| io_error(&e, "reading the job's spec")))
                .await?;
        let keep = !file.kill_on_timeout;
        let timeout = Duration::from_millis(file.timeout_ms.unwrap_or(self.config.exec_timeout_ms));
        // From the job's creation, also when this answers a repeat.
        let since = Duration::from_millis(now_ms().saturating_sub(file.created_at_ms));
        let begun = Instant::now()
            .checked_sub(since)
            .unwrap_or_else(Instant::now);
        let deadline = begun + timeout;
        // When the shim kills it at the timeout, allow it the grace and a
        // margin before answering without a final state.
        let last = deadline + Duration::from_millis(file.stop_grace_ms) + Duration::from_secs(10);
        // Once the program ended, the shim stops what it left in the job's
        // session (after the settle and the grace): the answer waits for
        // that, so no process of the Exec outlives it.
        let mut ended_seen: Option<Instant> = None;
        let outcome = loop {
            let d = dir.clone();
            let live =
                blocking(move || Self::live(&d).map_err(|e| io_error(&e, "reading the job")))
                    .await?;
            let status = live.status.as_ref();
            let now = Instant::now();
            if keep && live.busy && now >= deadline {
                // Make it a job, unless the shim saw its program end first
                // (a repeat of the request finds the rule set before).
                let d = dir.clone();
                let claimed = blocking(move || {
                    claim_rule(&d, RULE_JOB).map_err(|e| io_error(&e, "writing the rule"))
                })
                .await;
                match claimed {
                    Ok(None) => break Outcome::TimedOut { killed: false },
                    Ok(Some(rule)) if rule == RULE_JOB => {
                        break Outcome::TimedOut { killed: false };
                    }
                    Err(_) if now >= last => break Outcome::TimedOut { killed: false },
                    // It ended as an Exec (wait for its end), or the rule
                    // could not be written yet.
                    Ok(Some(_)) | Err(_) => {}
                }
            }
            match (Self::state(&live), status) {
                (JobState::Running, _) => {
                    if now >= last {
                        break Outcome::TimedOut { killed: false };
                    }
                }
                (state @ (JobState::Exited { .. } | JobState::Signaled { .. }), Some(s)) => {
                    let seen = *ended_seen.get_or_insert(now);
                    let bound = seen
                        + SETTLE
                        + Duration::from_millis(file.stop_grace_ms)
                        + Duration::from_secs(10);
                    if !live.busy || now >= bound {
                        break match state {
                            _ if s.timed_out => Outcome::TimedOut { killed: true },
                            JobState::Exited { code } => Outcome::Exited { code },
                            JobState::Signaled { signal } => Outcome::Signaled { signal },
                            _ => unreachable!(),
                        };
                    }
                }
                _ => {
                    return Err(err(
                        ErrorKind::Internal,
                        format!(
                            "the shim of {} vanished before the job finished; what it left may \
                             still run",
                            started.id
                        ),
                    ));
                }
            }
            tokio::time::sleep(POLL).await;
        };
        let cap = usize::try_from(cap).unwrap_or(usize::MAX);
        let d = dir.clone();
        let (stdout, stderr, status) = blocking(move || {
            let out = read_log(&d, Stream::Stdout, None, cap)
                .map_err(|e| io_error(&e, "reading stdout"))?;
            let err_ = read_log(&d, Stream::Stderr, None, cap)
                .map_err(|e| io_error(&e, "reading stderr"))?;
            Ok((out, err_, read_status(&d)))
        })
        .await?;
        let mut stdout = Output {
            offset: stdout.offset,
            total: stdout.total,
            data: stdout.data,
        };
        let mut stderr = Output {
            offset: stderr.offset,
            total: stderr.total,
            data: stderr.data,
        };
        fit_outputs(&mut stdout, &mut stderr, EXEC_OUTPUT_BUDGET);
        let duration_ms = match status
            .as_ref()
            .and_then(|s| s.ended_at_ms.map(|e| (s.started_at_ms, e)))
        {
            Some((start, end))
                if matches!(
                    outcome,
                    Outcome::Exited { .. }
                        | Outcome::Signaled { .. }
                        | Outcome::TimedOut { killed: true }
                ) =>
            {
                end.saturating_sub(start)
            }
            _ => u64::try_from(begun.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        Ok(ExecResult {
            job_id: started.id,
            outcome,
            stdout,
            stderr,
            duration_ms,
            stopped: status.as_ref().map_or(0, |s| s.stopped),
        })
    }

    /// Waits up to `timeout_ms` (at most 60 s) for the job to be finished:
    /// its program ended and nothing left in its session.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job.
    pub async fn wait(self: &Arc<Self>, id: String, timeout_ms: u64) -> Result<JobInfo, Error> {
        let until = Instant::now() + Duration::from_millis(timeout_ms.min(MAX_WAIT_MS));
        loop {
            let this = Arc::clone(self);
            let i = id.clone();
            let info = blocking(move || this.info(&i)).await?;
            if info.finished || Instant::now() >= until {
                return Ok(info);
            }
            tokio::time::sleep(POLL.min(until.saturating_duration_since(Instant::now()))).await;
        }
    }

    /// A slice of a job's log.
    ///
    /// # Errors
    ///
    /// `NotFound`, `TooLarge` past [`MAX_DATA`], or an I/O failure.
    pub fn log_read(
        &self,
        id: &str,
        stream: Stream,
        offset: Option<u64>,
        max_len: u32,
    ) -> Result<LogSlice, Error> {
        self.log_read_observed(id, stream, offset, max_len, || {})
    }

    /// [`Jobs::log_read`], running `between` after it has seen whether the
    /// job is over and before it reads the log (a test lets the job write
    /// and end there).
    fn log_read_observed(
        &self,
        id: &str,
        stream: Stream,
        offset: Option<u64>,
        max_len: u32,
        between: impl FnOnce(),
    ) -> Result<LogSlice, Error> {
        if max_len as usize > MAX_DATA {
            return Err(err(
                ErrorKind::TooLarge,
                format!("max_len is at most {MAX_DATA}"),
            ));
        }
        let dir = self.dir(id)?;
        // Whether the job is over, seen BEFORE the log is read: a job that
        // writes more and ends in between is answered not ended, and never
        // ended with a total that is not final.
        let live = Self::live(&dir).map_err(|e| read_error(id, &e))?;
        let ended = !live.busy && live.status.is_some();
        between();
        let read = read_log(&dir, stream, offset, max_len as usize)
            .map_err(|e| io_error(&e, "reading the log"))?;
        Ok(LogSlice {
            data: read.data,
            offset: read.offset,
            total: read.total,
            first_available: read.first_available,
            ended,
        })
    }

    /// Sends a signal to the job's process group.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for an unknown signal, `Conflict` when the job
    /// has ended.
    pub fn signal(&self, id: &str, signal: i32) -> Result<(), Error> {
        let signal = Signal::try_from(signal)
            .map_err(|_| err(ErrorKind::InvalidArgument, format!("no signal {signal}")))?;
        let dir = self.dir(id)?;
        let live = Self::live(&dir).map_err(|e| read_error(id, &e))?;
        let (JobState::Running, Some(pgid)) = (
            Self::state(&live),
            live.status.as_ref().and_then(|s| s.pgid),
        ) else {
            return Err(err(ErrorKind::Conflict, format!("job {id} has ended")));
        };
        killpg(pid(pgid), signal).map_err(|e| {
            let mut error = io_error(&io::Error::from(e), "signalling the job");
            if e == nix::errno::Errno::ESRCH {
                error.kind = ErrorKind::Conflict;
            }
            error
        })
    }

    /// Stops the job and everything it started, waiting until all is gone.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown job.
    pub async fn stop(
        self: &Arc<Self>,
        id: String,
        grace_ms: Option<u64>,
    ) -> Result<JobInfo, Error> {
        let dir = self.dir(&id)?;
        let grace = grace_ms.unwrap_or(self.config.stop_grace_ms);
        let d = dir.clone();
        let id_ = id.clone();
        let shim = blocking(move || {
            let live = Jobs::live(&d).map_err(|e| read_error(&id_, &e))?;
            let shim = match (&live.status, live.busy) {
                (Some(s), true) => Some((s.shim_pid, s.shim_start)),
                _ => None,
            };
            if let Some((shim_pid, shim_start)) = shim {
                if let Some(grace) = grace_ms {
                    atomic_write(&d.join(STOP), grace.to_string().as_bytes(), 0o600, false)
                        .map_err(|e| io_error(&e, "writing the stop request"))?;
                }
                if procfs::is_same_process(shim_pid, shim_start) {
                    let _ = kill(pid(shim_pid), Signal::SIGTERM);
                }
            }
            Ok(shim)
        })
        .await?;
        if let Some((shim_pid, shim_start)) = shim {
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

    /// Removes a finished job.
    ///
    /// # Errors
    ///
    /// `Busy` while it runs, `NotFound` for an unknown job.
    pub fn remove(&self, id: &str) -> Result<(), Error> {
        let dir = self.dir(id)?;
        let live = Self::live(&dir).map_err(|e| read_error(id, &e))?;
        if live.busy {
            return Err(err(
                ErrorKind::Busy,
                format!("job {id} still runs; stop it first"),
            ));
        }
        fs::remove_dir_all(&dir).map_err(|e| io_error(&e, "removing the job"))
    }

    /// Removes finished jobs past their retention, then the oldest finished
    /// beyond `max_jobs_kept`. Never a running one, and never one it cannot
    /// read (another ghostd's format): only a status saying it is over, or
    /// a shim that is gone, makes a job finished.
    pub fn gc(&self) -> Collected {
        let now = now_ms();
        let mut finished = Vec::new();
        let mut total = 0u64;
        let mut unreadable = Vec::new();
        for id in self.ids() {
            let dir = self.root.join(&id);
            let live = match Self::live(&dir) {
                Ok(live) => live,
                Err(e) => {
                    if abandoned(&dir) {
                        let _ = fs::remove_dir_all(&dir);
                    } else if e.kind() != io::ErrorKind::NotFound || dir.join(SPEC).exists() {
                        unreadable.push(format!("{id} ({e})"));
                    }
                    continue;
                }
            };
            total += 1;
            if live.busy {
                continue;
            }
            // Its retention starts when it finished, which for a job that
            // kept what its program left can be long after the program's
            // end (older status files: the program's end).
            let finished_at = live.status.as_ref().map_or(live.spec.created_at_ms, |s| {
                s.finished_at_ms
                    .or(s.ended_at_ms)
                    .unwrap_or(s.started_at_ms)
            });
            finished.push((finished_at, live.spec.kind, dir));
        }
        let mut removed = 0;
        finished.sort_by_key(|(finished_at, _, _)| *finished_at);
        let mut kept = Vec::new();
        for (finished_at, kind, dir) in finished {
            let hours = match kind {
                Kind::Exec => self.config.exec_retention_hours,
                Kind::Job => self.config.job_retention_hours,
            };
            if now.saturating_sub(finished_at) >= hours.saturating_mul(3_600_000) {
                if fs::remove_dir_all(&dir).is_ok() {
                    removed += 1;
                    total -= 1;
                }
            } else {
                kept.push(dir);
            }
        }
        for dir in kept {
            if total <= self.config.max_jobs_kept {
                break;
            }
            if fs::remove_dir_all(&dir).is_ok() {
                removed += 1;
                total -= 1;
            }
        }
        Collected {
            removed,
            unreadable,
        }
    }
}

/// What [`Jobs::gc`] did.
pub struct Collected {
    pub removed: usize,
    /// The jobs it left because it cannot read them, with why.
    pub unreadable: Vec<String>,
}

/// A directory the worker died creating: neither a spec nor a status (so
/// no shim ever ran for it), untouched for an hour.
pub fn abandoned(dir: &Path) -> bool {
    !dir.join(SPEC).exists()
        && !dir.join(STATUS).exists()
        && fs::metadata(dir)
            .and_then(|m| m.modified())
            .is_ok_and(|t| t.elapsed().is_ok_and(|e| e > ABANDONED_AFTER))
}

struct Started {
    id: String,
    dir: PathBuf,
}

enum StartError {
    /// The program could not be started (its job is removed).
    Failed(String),
    /// The client's job ID names a job of the same request: started before.
    Exists(Started),
    Other(Error),
}

/// What the blocking part of [`Jobs::start`] did.
enum Created {
    New(String, PathBuf),
    Exists(Started),
}

/// The SHA-256 of a request's spec as encoded on the wire, in hex.
pub fn spec_digest<T: serde::Serialize>(spec: &T) -> String {
    use std::fmt::Write as _;
    let bytes = ghostd_protocol::encode_frame(spec).unwrap_or_default();
    Sha256::digest(&bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

impl From<Error> for StartError {
    fn from(e: Error) -> Self {
        Self::Other(e)
    }
}

/// Trims the two outputs' data from the front (stderr first) so that
/// together they fit `budget`, keeping the offsets true.
fn fit_outputs(stdout: &mut Output, stderr: &mut Output, budget: usize) {
    let over = (stdout.data.len() + stderr.data.len()).saturating_sub(budget);
    let from_err = over.min(stderr.data.len());
    stderr.data.drain(..from_err);
    stderr.offset += from_err as u64;
    let from_out = (over - from_err).min(stdout.data.len());
    stdout.data.drain(..from_out);
    stdout.offset += from_out as u64;
}

/// What [`read_log`] read.
pub struct LogRead {
    pub data: Vec<u8>,
    pub offset: u64,
    pub total: u64,
    pub first_available: u64,
}

/// Reads `[offset, offset + max_len)` of a job's stream (the last
/// `max_len` bytes when `offset` is `None`) across the rotated and the
/// current file. The files are opened under the shared log lock, so they
/// agree with the offsets in `status.json` even while the shim rotates.
///
/// # Errors
///
/// When the lock or a file cannot be opened or read.
pub fn read_log(
    dir: &Path,
    stream: Stream,
    offset: Option<u64>,
    max_len: usize,
) -> io::Result<LogRead> {
    let lock_file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(dir.join(LOG_LOCK))?;
    let lock = Flock::lock(lock_file, FlockArg::LockShared).map_err(|(_, e)| io::Error::from(e))?;
    let status = read_status(dir);
    let open = |name: &str| match File::open(dir.join(name)) {
        Ok(f) => Ok(Some(f)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    };
    let current = open(log_name(stream))?;
    let stream_status = status
        .as_ref()
        .map(|s| s.stream(stream).clone())
        .unwrap_or_default();
    let previous = if stream_status.previous_start.is_some() {
        open(rotated_name(stream))?
    } else {
        None
    };
    drop(lock);
    let current_start = stream_status.current_start;
    let current_len = match &current {
        Some(f) => f.metadata()?.len(),
        None => 0,
    };
    let total = current_start + current_len;
    let (previous_start, previous_len) = match (&previous, stream_status.previous_start) {
        (Some(f), Some(start)) => (start, f.metadata()?.len()),
        _ => (current_start, 0),
    };
    let first_available = if previous.is_some() {
        previous_start
    } else {
        current_start
    };
    let max = max_len as u64;
    let start = match offset {
        None => total.saturating_sub(max).max(first_available),
        Some(o) => o.clamp(first_available, total),
    };
    let end = start.saturating_add(max).min(total);
    let mut data = Vec::with_capacity(usize::try_from(end - start).unwrap_or(0));
    let mut read_part = |file: &File, file_start: u64, file_len: u64| -> io::Result<()> {
        let from = start.max(file_start);
        let to = end.min(file_start + file_len);
        if from < to {
            let mut buf = vec![0u8; usize::try_from(to - from).unwrap_or(0)];
            file.read_exact_at(&mut buf, from - file_start)?;
            data.extend_from_slice(&buf);
        }
        Ok(())
    };
    if let Some(f) = &previous {
        read_part(f, previous_start, previous_len)?;
    }
    if let Some(f) = &current {
        read_part(f, current_start, current_len)?;
    }
    Ok(LogRead {
        data,
        offset: start,
        total,
        first_available,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_log_is_never_called_ended_before_its_total_is_final() {
        let root = tempfile::tempdir().unwrap();
        let jobs = Jobs::new(root.path().to_path_buf(), Config::default());
        let id = "j0000000000000001";
        let dir = root.path().join(id);
        fs::create_dir(&dir).unwrap();
        let spec = SpecFile {
            created_at_ms: now_ms(),
            ..SpecFile::default()
        };
        fs::write(dir.join(SPEC), serde_json::to_vec(&spec).unwrap()).unwrap();
        // Its shim runs: this process stands in for it.
        let me = std::process::id();
        let mut status = StatusFile {
            format: FORMAT,
            shim_pid: me,
            shim_start: procfs::start_time(me).unwrap(),
            ..StatusFile::default()
        };
        crate::jobfiles::write_status(&dir, &status, false).unwrap();
        fs::write(dir.join("stdout.log"), b"one\n").unwrap();
        let slice = jobs
            .log_read_observed(id, Stream::Stdout, Some(0), 100, || {
                // The job prints its last line and ends meanwhile.
                use std::io::Write as _;
                let mut log = OpenOptions::new()
                    .append(true)
                    .open(dir.join("stdout.log"))
                    .unwrap();
                log.write_all(b"two\n").unwrap();
                status.state = State::Exited;
                status.code = Some(0);
                status.stdout.total = 8;
                status.tree_gone = true;
                crate::jobfiles::write_status(&dir, &status, false).unwrap();
            })
            .unwrap();
        assert!(
            !slice.ended || slice.total == 8,
            "ended, but the total {} is not final",
            slice.total
        );
        let last = jobs.log_read(id, Stream::Stdout, Some(0), 100).unwrap();
        assert!(last.ended);
        assert_eq!((last.total, last.data.as_slice()), (8, &b"one\ntwo\n"[..]));
    }

    /// A finished job's files: its program ended `ended_ago_min` minutes
    /// ago, the job finished `finished_ago_min` ago (`None`: an older
    /// status file that does not say).
    fn finished_job(root: &Path, id: &str, ended_ago_min: u64, finished_ago_min: Option<u64>) {
        let dir = root.join(id);
        fs::create_dir(&dir).unwrap();
        let ago = |min: u64| now_ms() - min * 60_000;
        let spec = SpecFile {
            kind: Kind::Job,
            created_at_ms: ago(ended_ago_min + 1),
            ..SpecFile::default()
        };
        fs::write(dir.join(SPEC), serde_json::to_vec(&spec).unwrap()).unwrap();
        let status = StatusFile {
            format: FORMAT,
            state: State::Exited,
            code: Some(0),
            started_at_ms: ago(ended_ago_min + 1),
            ended_at_ms: Some(ago(ended_ago_min)),
            finished_at_ms: finished_ago_min.map(ago),
            tree_gone: true,
            ..StatusFile::default()
        };
        crate::jobfiles::write_status(&dir, &status, false).unwrap();
    }

    #[test]
    fn gc_ages_a_job_from_when_it_finished() {
        let root = tempfile::tempdir().unwrap();
        let config = Config {
            job_retention_hours: 2,
            max_jobs_kept: 2,
            ..Config::default()
        };
        let jobs = Jobs::new(root.path().to_path_buf(), config);
        // A server its program left ran for three hours and just ended.
        finished_job(root.path(), "j000000000000000a", 180, Some(1));
        // An older status file: aged from the program's end.
        finished_job(root.path(), "j000000000000000b", 180, None);
        // Within the retention, but the oldest to finish of three kept.
        finished_job(root.path(), "j000000000000000c", 100, Some(90));
        finished_job(root.path(), "j000000000000000d", 30, Some(30));
        let collected = jobs.gc();
        assert_eq!(collected.removed, 2);
        let mut left: Vec<String> = jobs.ids();
        left.sort();
        assert_eq!(left, ["j000000000000000a", "j000000000000000d"]);
    }

    #[test]
    fn ids() {
        assert!(valid_id("j0123456789abcdef"));
        assert!(!valid_id("j0123456789abcdeF"));
        assert!(!valid_id("j../../etc/passwd"));
        assert!(!valid_id("k0123456789abcdef"));
    }

    #[test]
    fn outputs_fit() {
        let mut out = Output {
            data: vec![1; 10],
            offset: 0,
            total: 10,
        };
        let mut err_ = Output {
            data: vec![2; 10],
            offset: 5,
            total: 15,
        };
        fit_outputs(&mut out, &mut err_, 14);
        assert_eq!(err_.data.len(), 4);
        assert_eq!(err_.offset, 11);
        assert_eq!(out.data.len(), 10);
        fit_outputs(&mut out, &mut err_, 3);
        assert_eq!(err_.data.len(), 0);
        assert_eq!(out.data.len(), 3);
        assert_eq!(out.offset, 7);
    }

    #[test]
    fn summary() {
        let argv: Vec<Vec<u8>> = ["a", "b", "c", "d", "e"]
            .iter()
            .map(|s| s.as_bytes().to_vec())
            .collect();
        assert_eq!(summarize(&argv), "a b c d");
    }
}
