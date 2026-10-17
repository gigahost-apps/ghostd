//! `ghostd shim <job-dir>`: the parent of one job's program.
//!
//! It runs in its own session as a child subreaper, so everything the
//! program starts stays below it even when it double-forks or calls
//! `setsid`. It copies the program's output to the job's rotated logs,
//! keeps `status.json` up to date, and on a stop (SIGTERM from the worker,
//! or the job's timeout) it signals the program's group and every
//! descendant, waits the grace, then SIGKILLs whatever remains until
//! nothing below it is left. The worker can die at any time: the shim does
//! not depend on it.
//!
//! When the program ends by itself, what it left in the job's session
//! (background processes, `nohup`, double forks) depends on the kind:
//!
//! - An Exec leaks no process: the shim stops them the same way, after
//!   [`SETTLE`], and counts them in `stopped`.
//! - A job keeps them: it lives on until none is left in its session (or
//!   a stop or its timeout takes the whole tree), so a server started in
//!   the background is part of the job.
//!
//! Either way the processes that started a session of their own are left:
//! daemons (`setsid`, `start-stop-daemon --background`, `pg_ctl start`,
//! `nginx`, `tmux new -d`) are what a program leaves running on purpose.
//! They are not waited for; when the shim exits they go to init. An Exec
//! with `keep_on_timeout` answered at its timeout follows the job rule from
//! then on (see [`jobfiles::claim_rule`]).

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use ghostd_protocol::v1::Stream;
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, kill, killpg};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;
use signal_hook::consts::{SIGCHLD, SIGHUP, SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

use crate::jobfiles::{
    self, FORMAT, Kind, LOG_LOCK, RULE_EXEC, STDIN, STOP, SpecFile, State, StatusFile,
    StreamStatus, log_name, rotated_name, write_status,
};
use crate::procfs;
use crate::util::now_ms;

pub mod session;
pub use session::{SOCKET, pty_exec, run as run_session};

enum Event {
    Signal(i32),
    PipeClosed,
}

struct Shared {
    dir: PathBuf,
    status: Mutex<StatusFile>,
    dirty: AtomicBool,
    log_max: u64,
}

impl Shared {
    fn status(&self) -> MutexGuard<'_, StatusFile> {
        self.status.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Writes the status as it is now, holding the lock while writing so
    /// that writes never interleave and a later write never carries older
    /// values.
    fn write(&self, sync: bool) {
        let status = self.status();
        self.dirty.store(false, Ordering::Relaxed);
        let _ = write_status(&self.dir, &status, sync);
    }
}

/// After the program ends by itself, how long what it left behind may take
/// to detach (a daemon forks, then its child calls `setsid`) before the
/// rest of the job's session is stopped.
pub const SETTLE: Duration = Duration::from_millis(500);

/// How often the shim counts the job's processes while nothing is being
/// stopped. A count reads the job's own subtree in `/proc` (the children
/// lists), so its cost is that of the job's processes, not of every
/// process on the machine. On a kernel without the lists it reads every
/// process, and then the interval doubles up to [`COUNT_EVERY_MOST`] while
/// the count does not change (once the program ended, a child's end still
/// counts again after [`COUNT_AFTER_CHILD`]).
const COUNT_EVERY: Duration = Duration::from_secs(1);

/// The longest interval between two counts on a kernel without the
/// children lists.
const COUNT_EVERY_MOST: Duration = Duration::from_secs(30);

/// How soon after a child's end (SIGCHLD) the shim counts again, while it
/// waits for what a job's program left: the last one ending finishes the
/// job.
const COUNT_AFTER_CHILD: Duration = Duration::from_millis(50);

/// What happens to what the program leaves in the job's session when it
/// ends by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// Stopped (an Exec).
    Stop,
    /// Waited for (a job).
    Wait,
    /// An Exec with `keep_on_timeout`: decided when the program ends.
    Undecided,
}

/// Decides an Exec with `keep_on_timeout` when its program ends: an Exec
/// unless the worker made it a job at its timeout first. When the rule
/// cannot be claimed or read, nothing is stopped.
fn decide(dir: &Path) -> Rule {
    match jobfiles::claim_rule(dir, RULE_EXEC) {
        Ok(None) => Rule::Stop,
        Ok(Some(rule)) if rule == RULE_EXEC => Rule::Stop,
        _ => Rule::Wait,
    }
}

fn pid_of(raw: u32) -> Pid {
    Pid::from_raw(i32::try_from(raw).unwrap_or(i32::MAX))
}

#[allow(clippy::too_many_lines)]
pub fn run(dir: &Path) -> ExitCode {
    // Our own session: no terminal, no SIGHUP from the caller's session,
    // and nothing the worker's death can reach.
    let _ = nix::unistd::setsid();
    let _ = nix::sys::prctl::set_child_subreaper(true);
    let Ok(spec) = jobfiles::read_spec(dir) else {
        return ExitCode::from(2);
    };
    let (tx, rx) = mpsc::channel::<Event>();
    let Ok(mut signals) = Signals::new([SIGCHLD, SIGTERM, SIGINT, SIGHUP]) else {
        return ExitCode::from(2);
    };
    {
        let tx = tx.clone();
        thread::spawn(move || {
            for signal in signals.forever() {
                if tx.send(Event::Signal(signal)).is_err() {
                    break;
                }
            }
        });
    }
    let me = std::process::id();
    // Ours since the setsid above; the session the job's processes share.
    let session = nix::unistd::getsid(None).map_or(me, |s| u32::try_from(s.as_raw()).unwrap_or(me));
    let mut status = StatusFile {
        format: FORMAT,
        state: State::Running,
        code: None,
        signal: None,
        message: None,
        pid: None,
        pgid: None,
        shim_pid: me,
        shim_start: procfs::start_time(me).unwrap_or(0),
        started_at_ms: now_ms(),
        ended_at_ms: None,
        finished_at_ms: None,
        timed_out: false,
        tree_gone: false,
        processes: 0,
        stopped: 0,
        stdout: StreamStatus::default(),
        stderr: StreamStatus::default(),
        log_error: None,
        cols: None,
        rows: None,
    };
    let mut child = match command(dir, &spec).and_then(|mut c| c.spawn()) {
        Ok(child) => child,
        Err(e) => {
            let program = spec
                .argv
                .first()
                .map(|a| String::from_utf8_lossy(&a.0).into_owned())
                .unwrap_or_default();
            status.state = State::FailedToStart;
            status.message = Some(format!("cannot start {program:?}: {e}"));
            status.ended_at_ms = Some(now_ms());
            status.finished_at_ms = status.ended_at_ms;
            status.tree_gone = true;
            let _ = write_status(dir, &status, true);
            return ExitCode::SUCCESS;
        }
    };
    let program = child.id();
    let started = Instant::now();
    // The program holds its stdin open; the bytes need not stay on disk.
    if spec.stdin {
        let _ = fs::remove_file(dir.join(STDIN));
    }
    status.pid = Some(program);
    status.pgid = Some(program);
    status.processes = 1;
    status.started_at_ms = now_ms();
    let shared = Arc::new(Shared {
        dir: dir.to_path_buf(),
        status: Mutex::new(status),
        dirty: AtomicBool::new(false),
        log_max: spec.log_max_bytes.max(1),
    });
    shared.write(true);
    let mut pipes_open = 0;
    if let Some(out) = child.stdout.take() {
        spawn_copier(&shared, out, Stream::Stdout, tx.clone());
        pipes_open += 1;
    }
    if let Some(err) = child.stderr.take() {
        spawn_copier(&shared, err, Stream::Stderr, tx.clone());
        pipes_open += 1;
    }
    // We reap with waitpid(-1) below, never through `child`.
    drop(child);
    drop(tx);

    let deadline = if spec.kill_on_timeout {
        spec.timeout_ms
            .map(|ms| started + Duration::from_millis(ms))
    } else {
        None
    };
    let mut rule = match (spec.kind, spec.kill_on_timeout) {
        (Kind::Job, _) => Rule::Wait,
        (Kind::Exec, true) => Rule::Stop,
        (Kind::Exec, false) => Rule::Undecided,
    };
    let mut supervise = Supervise {
        shared: &shared,
        me,
        session,
        program,
        program_alive: true,
        children_lists: procfs::has_children_lists(),
        exit: None,
        stop: None,
        leftovers: None,
        count: Count::new(),
    };
    let mut exit_seen: Option<Instant> = None;
    let mut final_written = false;
    let below = loop {
        let busy = supervise.stop.is_some()
            || supervise.leftovers.is_some()
            || (exit_seen.is_some() && !final_written);
        let mut wait = if busy {
            Duration::from_millis(20)
        } else {
            Duration::from_millis(250)
        };
        if supervise.count.child_ended {
            wait = wait.min(COUNT_AFTER_CHILD);
        }
        // A job's timeout holds while anything is left of it; an Exec's
        // while its program runs (its leftovers are stopped anyway).
        let timing = supervise.program_alive || rule == Rule::Wait;
        if let Some(d) = deadline
            && timing
            && supervise.stop.is_none()
        {
            wait = wait.min(d.saturating_duration_since(Instant::now()));
        }
        match rx.recv_timeout(wait) {
            Ok(Event::Signal(SIGTERM | SIGINT)) => {
                // A stop takes everything below us, also what a program
                // that already ended left in its own session.
                if supervise.stop.is_none() {
                    let grace = requested_grace(dir).unwrap_or(spec.stop_grace_ms);
                    supervise.begin_stop(grace);
                }
            }
            // While the program runs, its children's ends change nothing
            // we wait for (its own end is seen by the reap below).
            Ok(Event::Signal(SIGCHLD)) => {
                if !supervise.program_alive {
                    supervise.count.child_ended = true;
                }
            }
            Ok(Event::PipeClosed) => pipes_open -= 1,
            Ok(Event::Signal(_)) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => pipes_open = 0,
        }
        supervise.reap();
        if !supervise.program_alive && exit_seen.is_none() {
            let now = Instant::now();
            exit_seen = Some(now);
            // Count again at once: the program is gone.
            supervise.count.next = now;
            if supervise.stop.is_none() {
                if rule == Rule::Undecided {
                    rule = decide(dir);
                }
                if rule == Rule::Stop {
                    // An Exec leaks nothing: what it left in its session
                    // is stopped after the settle, daemons are left.
                    supervise.leftovers = Some(Leftovers {
                        settle_until: now + SETTLE,
                        grace_ms: spec.stop_grace_ms,
                        stop: None,
                    });
                }
            }
        }
        let timing = supervise.program_alive || rule == Rule::Wait;
        if let Some(d) = deadline
            && timing
            && supervise.stop.is_none()
            && Instant::now() >= d
        {
            shared.status().timed_out = true;
            supervise.begin_stop(spec.stop_grace_ms);
        }
        let progress = supervise.progress();
        // The final state waits for the output to be copied: always when
        // nothing is left that could hold the pipes (they close once the
        // copiers drain them), at most 100 ms when processes remain below
        // us (they may keep them open), and at most 5 s in any case (a
        // process outside the tree could hold them).
        if let Some(seen) = exit_seen
            && !final_written
            && (pipes_open == 0
                || (progress.below > 0 && seen.elapsed() >= Duration::from_millis(100))
                || seen.elapsed() >= Duration::from_secs(5))
        {
            supervise.apply_exit();
            if progress.waiting == 0 && pipes_open == 0 {
                // The usual case: nothing left to stop, one final write.
                supervise.finish();
                shared.write(true);
                return ExitCode::SUCCESS;
            }
            shared.write(true);
            final_written = true;
        }
        if final_written && progress.waiting == 0 {
            break progress.below;
        }
        if shared.dirty.load(Ordering::Relaxed) {
            shared.write(false);
        }
    };
    // What we waited for is gone, so the pipes close unless a detached
    // process still holds them; give the copiers a moment to drain what is
    // left.
    let drain = if below == 0 {
        Duration::from_secs(2)
    } else {
        Duration::from_millis(100)
    };
    let until = Instant::now() + drain;
    while pipes_open > 0 {
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(Event::PipeClosed) => pipes_open -= 1,
            Ok(Event::Signal(_)) => {}
            Err(_) => break,
        }
    }
    supervise.finish();
    shared.write(true);
    ExitCode::SUCCESS
}

fn requested_grace(dir: &Path) -> Option<u64> {
    fs::read_to_string(dir.join(STOP)).ok()?.trim().parse().ok()
}

fn command(dir: &Path, spec: &SpecFile) -> std::io::Result<Command> {
    let (program, args) = spec
        .argv
        .split_first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty argv"))?;
    let mut command = Command::new(OsStr::from_bytes(&program.0));
    command.args(args.iter().map(|a| OsStr::from_bytes(&a.0)));
    if spec.env_clear {
        command.env_clear();
    }
    for name in &spec.env_remove {
        command.env_remove(OsStr::from_bytes(&name.0));
    }
    for (name, value) in &spec.env {
        command.env(OsStr::from_bytes(&name.0), OsStr::from_bytes(&value.0));
    }
    command.current_dir(OsStr::from_bytes(&spec.cwd.0));
    if spec.stdin {
        command.stdin(File::open(dir.join(STDIN))?);
    } else {
        command.stdin(Stdio::null());
    }
    command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    Ok(command)
}

struct StopState {
    kill_at: Instant,
    termed: HashSet<u32>,
}

/// What a program that ended by itself left in the job's session.
struct Leftovers {
    settle_until: Instant,
    grace_ms: u64,
    /// Set once the settle is over and something is left to stop.
    stop: Option<StopState>,
}

/// Where a stop stands.
#[derive(Debug, Clone, Copy)]
struct Progress {
    /// Every process below us, the program included.
    below: usize,
    /// The processes we still wait for: everything during a stop, the
    /// program while it runs, what it left in its session after it ended.
    waiting: usize,
}

/// When the job's processes are counted while nothing is being stopped.
struct Count {
    next: Instant,
    at: Instant,
    /// The interval to the next count.
    every: Duration,
    /// A child ended since the last count.
    child_ended: bool,
    last: Progress,
}

impl Count {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            next: now,
            at: now,
            every: COUNT_EVERY,
            child_ended: false,
            last: Progress {
                below: 1,
                waiting: 1,
            },
        }
    }
}

struct Supervise<'a> {
    shared: &'a Shared,
    me: u32,
    /// The job's session (ours): a process below us in another one
    /// detached itself.
    session: u32,
    program: u32,
    /// Until we reap the program its pid (and so its group id) cannot be
    /// reused, so signalling the group is safe exactly while this is true.
    program_alive: bool,
    /// The kernel lists each thread's children ([`procfs::subtree`]).
    children_lists: bool,
    exit: Option<(State, Option<i32>, Option<i32>, u64)>,
    /// A stop of the whole tree (a `JobStop`, a timeout).
    stop: Option<StopState>,
    /// The program of an Exec ended by itself (and no stop came first).
    leftovers: Option<Leftovers>,
    count: Count,
}

impl Supervise<'_> {
    fn reap(&mut self) {
        loop {
            match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(pid, code)) => {
                    if pid == pid_of(self.program) {
                        self.program_ended(State::Exited, Some(code), None);
                    }
                }
                Ok(WaitStatus::Signaled(pid, signal, _)) => {
                    if pid == pid_of(self.program) {
                        self.program_ended(State::Signaled, None, Some(signal as i32));
                    }
                }
                Ok(WaitStatus::StillAlive) => return,
                Ok(_) | Err(Errno::EINTR) => {}
                Err(_) => return,
            }
        }
    }

    fn program_ended(&mut self, state: State, code: Option<i32>, signal: Option<i32>) {
        self.program_alive = false;
        self.exit = Some((state, code, signal, now_ms()));
    }

    /// Puts the program's end into the status. Done only right before the
    /// final write, so that no throttled write shows the end before the
    /// output totals are complete.
    fn apply_exit(&self) {
        if let Some((state, code, signal, ended)) = self.exit {
            let mut status = self.shared.status();
            status.state = state;
            status.code = code;
            status.signal = signal;
            status.ended_at_ms = Some(ended);
        }
    }

    fn begin_stop(&mut self, grace_ms: u64) {
        let mut termed = HashSet::new();
        if self.program_alive {
            let group = pid_of(self.program);
            let _ = killpg(group, Signal::SIGTERM);
            let _ = killpg(group, Signal::SIGCONT);
        }
        for d in procfs::descendants(self.me) {
            if !(self.program_alive && d.pgid == self.program) {
                let _ = kill(pid_of(d.pid), Signal::SIGTERM);
                let _ = kill(pid_of(d.pid), Signal::SIGCONT);
            }
            termed.insert(d.pid);
        }
        self.stop = Some(StopState {
            kill_at: Instant::now() + Duration::from_millis(grace_ms),
            termed,
        });
    }

    /// The processes below us and the ones in the job's session. When
    /// none is in the session, it looks again at once: a process that
    /// forks and exits while `/proc` is read can hide its child from one
    /// pass, never from the next.
    fn scan(&self) -> (Vec<procfs::Descendant>, Vec<procfs::Descendant>) {
        let mut pass = 0;
        loop {
            let descendants = procfs::descendants(self.me);
            let in_session: Vec<procfs::Descendant> = descendants
                .iter()
                .copied()
                .filter(|d| d.sid == self.session)
                .collect();
            pass += 1;
            if !in_session.is_empty() || pass == 2 {
                return (descendants, in_session);
            }
        }
    }

    /// The processes below us and the ones in the job's session, for a
    /// count while nothing is being stopped: read down our own subtree,
    /// which costs what the job's processes do. A children list can miss a
    /// process while others come and go, so when that finds none left in
    /// the job's session after the program ended (which finishes a job),
    /// the full [`Self::scan`] decides.
    fn count_scan(&self) -> (usize, Vec<procfs::Descendant>) {
        if self.children_lists {
            let below = procfs::subtree(self.me);
            let in_session: Vec<procfs::Descendant> = below
                .iter()
                .copied()
                .filter(|d| d.sid == self.session)
                .collect();
            if self.program_alive || !in_session.is_empty() {
                return (below.len(), in_session);
            }
        }
        let (below, in_session) = self.scan();
        (below.len(), in_session)
    }

    /// Records how many processes are in the job's session: the ones
    /// found there, and the program while it runs (also before it is
    /// seen, as a zombie not yet reaped).
    fn record(&self, in_session: &[procfs::Descendant]) {
        let program = self.program_alive && !in_session.iter().any(|d| d.pid == self.program);
        let count = u32::try_from(in_session.len() + usize::from(program)).unwrap_or(u32::MAX);
        let mut status = self.shared.status();
        if status.processes != count {
            status.processes = count;
            self.shared.dirty.store(true, Ordering::Relaxed);
        }
    }

    /// Puts the end into the status: nothing left in the job's session,
    /// when the job finished, and how many processes an Exec's end
    /// stopped.
    fn finish(&self) {
        let mut status = self.shared.status();
        status.tree_gone = true;
        status.finished_at_ms = Some(now_ms());
        status.processes = 0;
        status.stopped = self
            .leftovers
            .as_ref()
            .and_then(|l| l.stop.as_ref())
            .map_or(0, |s| u32::try_from(s.termed.len()).unwrap_or(u32::MAX));
    }

    /// Signals what appeared since and, past the grace, SIGKILLs all that
    /// is left: everything below us during a stop, what an Exec's program
    /// left in the job's session after it ended by itself. Otherwise counts
    /// the job's processes now and then: while the program runs, and while
    /// a job waits for what its program left.
    fn progress(&mut self) -> Progress {
        let program = usize::from(self.program_alive);
        if self.stop.is_some() {
            let (descendants, in_session) = self.scan();
            self.record(&in_session);
            let Some(stop) = &mut self.stop else {
                unreachable!()
            };
            let killing = Instant::now() >= stop.kill_at;
            if killing && self.program_alive {
                let _ = killpg(pid_of(self.program), Signal::SIGKILL);
            }
            signal_all(stop, &descendants, killing);
            let below = descendants.len() + program;
            return Progress {
                below,
                waiting: below,
            };
        }
        if self.leftovers.is_some() {
            let (descendants, in_session) = self.scan();
            self.record(&in_session);
            let Some(leftovers) = &mut self.leftovers else {
                unreachable!()
            };
            let now = Instant::now();
            if !in_session.is_empty() && now >= leftovers.settle_until {
                let grace = Duration::from_millis(leftovers.grace_ms);
                let stop = leftovers.stop.get_or_insert_with(|| StopState {
                    kill_at: now + grace,
                    termed: HashSet::new(),
                });
                let killing = now >= stop.kill_at;
                signal_all(stop, &in_session, killing);
            }
            return Progress {
                below: descendants.len(),
                waiting: in_session.len(),
            };
        }
        // Nothing to stop: count now and then, and soon after a child
        // ended while a job's program is gone (the last one ending
        // finishes the job).
        let now = Instant::now();
        let due = now >= self.count.next
            || (!self.program_alive
                && self.count.child_ended
                && now >= self.count.at + COUNT_AFTER_CHILD);
        if due {
            let (below, in_session) = self.count_scan();
            self.record(&in_session);
            let in_session_count = in_session.len()
                + usize::from(
                    self.program_alive && !in_session.iter().any(|d| d.pid == self.program),
                );
            let counted = Progress {
                below: below + program,
                waiting: in_session_count,
            };
            self.count.every = if self.children_lists || counted.waiting != self.count.last.waiting
            {
                COUNT_EVERY
            } else {
                (self.count.every * 2).min(COUNT_EVERY_MOST)
            };
            self.count.child_ended = false;
            self.count.at = now;
            self.count.next = now + self.count.every;
            self.count.last = counted;
        }
        if self.program_alive {
            // While it runs, the program is what we wait for.
            return Progress {
                below: self.count.last.below.max(1),
                waiting: self.count.last.waiting.max(1),
            };
        }
        self.count.last
    }
}

/// SIGKILLs `targets` when `killing`, else SIGTERMs (and SIGCONTs) each
/// one not signalled before.
fn signal_all(stop: &mut StopState, targets: &[procfs::Descendant], killing: bool) {
    for d in targets {
        if killing {
            stop.termed.insert(d.pid);
            let _ = kill(pid_of(d.pid), Signal::SIGKILL);
        } else if stop.termed.insert(d.pid) {
            let _ = kill(pid_of(d.pid), Signal::SIGTERM);
            let _ = kill(pid_of(d.pid), Signal::SIGCONT);
        }
    }
}

fn spawn_copier<R: Read + Send + 'static>(
    shared: &Arc<Shared>,
    pipe: R,
    stream: Stream,
    tx: Sender<Event>,
) {
    let shared = Arc::clone(shared);
    thread::spawn(move || {
        copy(&shared, pipe, stream, |_| {});
        let _ = tx.send(Event::PipeClosed);
    });
}

fn open_log(path: &Path) -> Option<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .ok()
}

/// Copies a pipe to its log until EOF. It never stops reading while the
/// pipe is open: when the disk fails, the bytes are dropped (and
/// `log_error` says so) so that the program never blocks on a full pipe.
/// `seen` gets every chunk read, before it is written.
fn copy<R: Read>(shared: &Shared, mut pipe: R, stream: Stream, mut seen: impl FnMut(&[u8])) {
    let path = shared.dir.join(log_name(stream));
    let mut file = open_log(&path);
    let mut size = file
        .as_ref()
        .and_then(|f| f.metadata().ok())
        .map_or(0, |m| m.len());
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        };
        seen(&buf[..n]);
        let mut chunk = &buf[..n];
        while !chunk.is_empty() {
            let mut room = shared.log_max.saturating_sub(size);
            if room == 0 {
                if rotate(shared, stream, &mut file) {
                    size = 0;
                    room = shared.log_max;
                } else {
                    room = u64::MAX;
                }
            }
            let take = usize::try_from(room).unwrap_or(usize::MAX).min(chunk.len());
            let part = &chunk[..take];
            let written = file.as_mut().map(|f| f.write_all(part));
            match written {
                Some(Ok(())) => {
                    size += part.len() as u64;
                    shared.status().stream_mut(stream).total += part.len() as u64;
                }
                Some(Err(e)) => {
                    // Keep the offsets true to what the files hold.
                    size = file
                        .as_ref()
                        .and_then(|f| f.metadata().ok())
                        .map_or(size, |m| m.len());
                    let mut status = shared.status();
                    let s = status.stream_mut(stream);
                    s.total = s.current_start + size;
                    status.log_error = Some(format!("writing {}: {e}", log_name(stream)));
                }
                None => {
                    shared.status().log_error = Some(format!("cannot open {}", log_name(stream)));
                }
            }
            shared.dirty.store(true, Ordering::Relaxed);
            chunk = &chunk[take..];
        }
    }
}

/// Moves the current log to `.1` (replacing the older one) and starts a
/// new one, under the exclusive log lock, writing the new offsets before
/// the lock is released: a reader holding the shared lock always sees
/// files and offsets that agree.
fn rotate(shared: &Shared, stream: Stream, file: &mut Option<File>) -> bool {
    let Ok(lock_file) = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(shared.dir.join(LOG_LOCK))
    else {
        return false;
    };
    let Ok(lock) = Flock::lock(lock_file, FlockArg::LockExclusive) else {
        return false;
    };
    let current = shared.dir.join(log_name(stream));
    if fs::rename(&current, shared.dir.join(rotated_name(stream))).is_err() {
        return false;
    }
    *file = open_log(&current);
    {
        let mut status = shared.status();
        let s = status.stream_mut(stream);
        s.previous_start = Some(s.current_start);
        s.current_start = s.total;
    }
    shared.write(false);
    drop(lock);
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shared(dir: &Path) -> Shared {
        Shared {
            dir: dir.to_path_buf(),
            status: Mutex::new(StatusFile::default()),
            dirty: AtomicBool::new(false),
            log_max: 1 << 20,
        }
    }

    /// A supervisor of `program` for this process standing in for the
    /// shim, in a session no process has.
    fn supervise(shared: &Shared, program: u32) -> Supervise<'_> {
        Supervise {
            shared,
            me: std::process::id(),
            session: u32::MAX,
            program,
            program_alive: true,
            children_lists: true,
            exit: None,
            stop: None,
            leftovers: None,
            count: Count::new(),
        }
    }

    fn full_reads() -> usize {
        procfs::FULL_READS.with(std::cell::Cell::get)
    }

    #[test]
    fn a_count_reads_the_jobs_subtree_and_every_process_only_to_finish() {
        if !procfs::has_children_lists() {
            eprintln!("skipped: this kernel has no /proc/<pid>/task/<tid>/children");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let shared = shared(dir.path());
        let mut program = Command::new("sleep").arg("30").spawn().unwrap();
        let mut supervise = supervise(&shared, program.id());
        // While the program runs, every count reads only our subtree.
        let before = full_reads();
        for _ in 0..3 {
            supervise.count.next = Instant::now();
            assert_eq!(supervise.progress().waiting, 1);
        }
        assert_eq!(full_reads(), before, "a count read every process");
        assert_eq!(shared.status().processes, 1);
        program.kill().unwrap();
        program.wait().unwrap();
        // Once it ended, none left in the session is decided by reading
        // every process (twice: a fork can hide a child from one pass).
        supervise.program_alive = false;
        supervise.count.next = Instant::now();
        assert_eq!(supervise.progress().waiting, 0);
        assert_eq!(full_reads(), before + 2);
        assert_eq!(shared.status().processes, 0);
    }

    #[test]
    fn without_children_lists_an_unchanged_count_backs_off() {
        let dir = tempfile::tempdir().unwrap();
        let shared = shared(dir.path());
        let mut program = Command::new("sleep").arg("30").spawn().unwrap();
        let mut supervise = supervise(&shared, program.id());
        supervise.children_lists = false;
        let mut intervals = Vec::new();
        for _ in 0..8 {
            supervise.count.next = Instant::now();
            assert_eq!(supervise.progress().waiting, 1);
            intervals.push(supervise.count.every.as_secs());
        }
        assert_eq!(intervals, [2, 4, 8, 16, 30, 30, 30, 30]);
        // A change counts again soon.
        program.kill().unwrap();
        program.wait().unwrap();
        supervise.program_alive = false;
        supervise.count.next = Instant::now();
        assert_eq!(supervise.progress().waiting, 0);
        assert_eq!(supervise.count.every, COUNT_EVERY);
    }
}
