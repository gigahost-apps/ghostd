//! `ghostd shim <session-dir> --session`: the holder of one session's PTY.
//!
//! Like a job's shim it runs in its own session as a child subreaper, so
//! the session survives the worker's and the daemon's death, and stopping
//! it stops everything below it. It owns the PTY's master side (it never
//! opens the terminal side, so the master reads end once the session's
//! processes are gone) and starts the program through `ghostd pty-exec`,
//! which makes the terminal the program's controlling one in a session of
//! its own. A reader thread always reads the master, so a program that
//! floods output never blocks: the bytes go to a terminal emulator (the
//! screen, and 1000 lines of scrollback) and to the rotated
//! `stdout.log`. Input goes through a bounded queue to a writer thread, so
//! a program that reads nothing blocks no request.
//!
//! It serves `shim.sock` (0600, its own user only) with the frozen hellos
//! and [`crate::sessproto`]'s messages. When the program ends by itself,
//! what it left in its session is stopped after [`SETTLE`], as for an
//! Exec; a close hangs the session up and stops the whole tree as a job
//! stop. Either way it writes the final screen (`screen.json`), removes its
//! socket, then writes its final status, and exits.

use std::ffi::OsString;
use std::fmt::Write as _;
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Condvar;
use std::sync::mpsc::{SyncSender, TrySendError};

use ghostd_protocol::v2::{Error, ErrorKind, Screen, SessionEnd, Until};
use ghostd_protocol::{FrameDecoder, decode};

use super::{
    Arc, AtomicBool, Command, Count, Duration, ExitCode, File, Instant, Leftovers, Mutex,
    MutexGuard, Ordering, Path, PoisonError, RecvTimeoutError, SETTLE, Shared, Signal, Signals,
    SpecFile, State, StatusFile, Stdio, StreamStatus, Supervise, copy, fs, jobfiles, killpg, mpsc,
    now_ms, pid_of, procfs, thread, write_status,
};
use super::{FORMAT, SIGCHLD, SIGHUP, SIGINT, SIGTERM};
use crate::keys;
use crate::sessproto::{
    ShimAnswer, ShimRequest, ShimResponse, accept_hello, read_frame_blocking, write_answer,
};

/// The shim's socket in the session's directory.
pub const SOCKET: &str = "shim.sock";
/// The final screen, written when the session ends.
pub const SCREEN: &str = "screen.json";
/// The lines kept above the screen.
pub const SCROLLBACK: usize = 1000;
/// The most bytes one send may queue.
pub const MAX_INPUT: usize = 64 * 1024;
/// How many sends may wait for the program to read them.
const INPUT_QUEUE: usize = 64;
/// The longest a read waits.
pub const MAX_READ_WAIT_MS: u64 = 60_000;
/// The terminal sizes a session may have.
pub const COLS: std::ops::RangeInclusive<u16> = 20..=500;
pub const ROWS: std::ops::RangeInclusive<u16> = 5..=200;

enum Event {
    Signal(i32),
    PipeClosed,
    Close(u64),
}

/// What the emulator does not draw: the title, and answers to the
/// program's questions about the terminal.
#[derive(Default)]
struct Hooks {
    title: String,
    replies: Vec<u8>,
}

impl vt100::Callbacks for Hooks {
    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        self.title = String::from_utf8_lossy(title).chars().take(256).collect();
    }

    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        i1: Option<u8>,
        _i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        if self.replies.len() > 4096 {
            return;
        }
        let first = params.first().and_then(|p| p.first()).copied().unwrap_or(0);
        match (c, i1) {
            // Where is the cursor (shells and editors ask at start).
            ('n', None) if first == 6 => {
                let (row, col) = screen.cursor_position();
                let _ = write!(
                    Bytes(&mut self.replies),
                    "\x1b[{};{}R",
                    u32::from(row) + 1,
                    u32::from(col) + 1
                );
            }
            ('n', None) if first == 5 => self.replies.extend_from_slice(b"\x1b[0n"),
            // What terminal is this: a VT100 with advanced video.
            ('c', None) if first == 0 => self.replies.extend_from_slice(b"\x1b[?1;2c"),
            _ => {}
        }
    }
}

/// `fmt::Write` into a byte vector.
struct Bytes<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for Bytes<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

struct Term {
    parser: vt100::Parser<Hooks>,
    seq: u64,
    exited: Option<SessionEnd>,
    /// Nothing will change any more: the final screen is being written.
    over: bool,
}

struct Session {
    term: Mutex<Term>,
    changed: Condvar,
    input: SyncSender<Vec<u8>>,
    master: OwnedFd,
    events: Mutex<mpsc::Sender<Event>>,
    shared: Arc<Shared>,
    program: u32,
    program_alive: AtomicBool,
}

impl Session {
    fn term(&self) -> MutexGuard<'_, Term> {
        self.term.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn err(kind: ErrorKind, message: impl Into<String>) -> Error {
    Error::new(kind, message)
}

/// Compiles a regex for a session read or a wait, bounded in size.
///
/// # Errors
///
/// `InvalidArgument` for a pattern that does not compile.
pub fn regex(pattern: &str) -> Result<regex::Regex, Error> {
    regex::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|e| err(ErrorKind::InvalidArgument, format!("the regex: {e}")))
}

fn trimmed(row: &str) -> &str {
    row.trim_end_matches(' ')
}

fn screen_text(screen: &vt100::Screen) -> String {
    let (_, cols) = screen.size();
    let rows: Vec<String> = screen
        .rows(0, cols)
        .map(|r| trimmed(&r).to_string())
        .collect();
    rows.join("\n")
}

/// The last `want` lines above the screen, oldest first.
fn scrollback_text(screen: &mut vt100::Screen, want: usize) -> String {
    let (rows, cols) = screen.size();
    screen.set_scrollback(usize::MAX);
    let total = screen.scrollback();
    let mut offset = want.min(total);
    let mut lines = Vec::with_capacity(offset);
    while offset > 0 {
        // With the view moved up `offset` lines, row i of the view is the
        // line `offset - i` above the screen.
        screen.set_scrollback(offset);
        let take = offset.min(usize::from(rows));
        lines.extend(
            screen
                .rows(0, cols)
                .take(take)
                .map(|r| trimmed(&r).to_string()),
        );
        offset -= take;
    }
    screen.set_scrollback(0);
    lines.join("\n")
}

fn snapshot(term: &mut Term, scrollback_lines: usize) -> Screen {
    let scrollback = (scrollback_lines > 0)
        .then(|| scrollback_text(term.parser.screen_mut(), scrollback_lines.min(SCROLLBACK)));
    let screen = term.parser.screen();
    let (rows, cols) = screen.size();
    Screen {
        text: screen_text(screen),
        cursor: screen.cursor_position(),
        cols,
        rows,
        title: term.parser.callbacks().title.clone(),
        alternate_screen: screen.alternate_screen(),
        scrollback,
        exited: term.exited,
        changed_since: term.seq,
        until_met: None,
    }
}

/// Whether `until` holds. `start`: the sequence number when the read began.
fn holds(until: &Until, term: &Term, start: u64, regex: Option<&regex::Regex>) -> bool {
    match until {
        Until::Changed { since } => term.seq > since.unwrap_or(start),
        Until::Matches(_) => regex.is_some_and(|r| r.is_match(&screen_text(term.parser.screen()))),
        Until::Exited => term.exited.is_some(),
    }
}

/// Whether `until` holds on a final screen.
///
/// # Errors
///
/// `InvalidArgument` for a regex that does not compile.
pub fn holds_on_final(until: &Until, screen: &Screen) -> Result<bool, Error> {
    Ok(match until {
        Until::Changed { since } => since.is_some_and(|s| screen.changed_since > s),
        Until::Matches(pattern) => regex(pattern)?.is_match(&screen.text),
        Until::Exited => true,
    })
}

fn read(
    session: &Session,
    wait_ms: u64,
    until: Option<&Until>,
    scrollback_lines: u32,
) -> Result<Screen, Error> {
    let compiled = match until {
        Some(Until::Matches(pattern)) => Some(regex(pattern)?),
        _ => None,
    };
    let deadline = Instant::now() + Duration::from_millis(wait_ms.min(MAX_READ_WAIT_MS));
    let mut term = session.term();
    let start = term.seq;
    let met = loop {
        let met = until.map(|u| holds(u, &term, start, compiled.as_ref()));
        let now = Instant::now();
        if met != Some(false) || now >= deadline || term.over {
            break met;
        }
        term = session
            .changed
            .wait_timeout(term, deadline - now)
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    };
    let mut screen = snapshot(&mut term, scrollback_lines as usize);
    screen.until_met = met;
    Ok(screen)
}

fn handle(session: &Session, request: ShimRequest) -> ShimAnswer {
    let alive = session.program_alive.load(Ordering::Relaxed);
    match request {
        ShimRequest::Read {
            wait_ms,
            until,
            scrollback_lines,
        } => read(session, wait_ms, until.as_ref(), scrollback_lines).map(ShimResponse::Screen),
        ShimRequest::Send(input) => {
            let application_cursor = session.term().parser.screen().application_cursor();
            let bytes = keys::encode(&input, application_cursor)?;
            if bytes.len() > MAX_INPUT {
                return Err(err(
                    ErrorKind::TooLarge,
                    format!("one send is at most {MAX_INPUT} bytes"),
                ));
            }
            if !alive {
                return Err(err(ErrorKind::Conflict, "the session's program has exited"));
            }
            match session.input.try_send(bytes) {
                Ok(()) => Ok(ShimResponse::Done),
                Err(TrySendError::Full(_)) => Err(err(
                    ErrorKind::Busy,
                    "the program has not read what was sent before; read the screen and send \
                     later",
                )),
                Err(TrySendError::Disconnected(_)) => Err(err(
                    ErrorKind::Conflict,
                    "the session's terminal takes no more input",
                )),
            }
        }
        ShimRequest::Resize { cols, rows } => {
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
            let size = rustix::termios::Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            rustix::termios::tcsetwinsize(&session.master, size)
                .map_err(|e| err(ErrorKind::Io, format!("resizing the terminal: {e}")))?;
            {
                let mut term = session.term();
                term.parser.screen_mut().set_size(rows, cols);
                term.seq += 1;
            }
            session.changed.notify_all();
            {
                let mut status = session.shared.status();
                status.cols = Some(cols);
                status.rows = Some(rows);
            }
            // At once: a listing right after the answer shows the size.
            session.shared.write(false);
            Ok(ShimResponse::Done)
        }
        ShimRequest::Signal(signal) => {
            let signal = Signal::try_from(signal)
                .map_err(|_| err(ErrorKind::InvalidArgument, format!("no signal {signal}")))?;
            if !alive {
                return Err(err(ErrorKind::Conflict, "the session's program has exited"));
            }
            // The foreground group of the terminal (a job the shell runs),
            // else the program's own.
            let group = rustix::termios::tcgetpgrp(&session.master)
                .ok()
                .and_then(|p| u32::try_from(p.as_raw_nonzero().get()).ok())
                .unwrap_or(session.program);
            killpg(pid_of(group), signal)
                .map_err(|e| err(ErrorKind::Conflict, format!("signalling the session: {e}")))?;
            Ok(ShimResponse::Done)
        }
        ShimRequest::Close { grace_ms } => {
            let events = session
                .events
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let _ = events.send(Event::Close(grace_ms));
            Ok(ShimResponse::Done)
        }
    }
}

/// Serves one connection to the shim's socket.
fn serve(session: &Session, mut stream: UnixStream) {
    let own = rustix::process::getuid();
    match rustix::net::sockopt::socket_peercred(&stream) {
        Ok(cred) if cred.uid == own => {}
        _ => return,
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let mut decoder = FrameDecoder::new();
    if !accept_hello(&mut stream, &mut decoder).unwrap_or(false) {
        return;
    }
    let _ = stream.set_read_timeout(None);
    while let Ok(Some(body)) = read_frame_blocking(&mut stream, &mut decoder) {
        let answer = match decode::<ShimRequest>(&body) {
            Ok(request) => handle(session, request),
            Err(e) => Err(err(ErrorKind::InvalidArgument, format!("undecodable: {e}"))),
        };
        if write_answer(&mut stream, &answer).is_err() {
            return;
        }
    }
}

/// Opens the PTY's master side, sized; answers it and the terminal's path.
fn open_pty(cols: u16, rows: u16) -> std::io::Result<(OwnedFd, std::path::PathBuf)> {
    use rustix::pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt};
    let master = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC)?;
    grantpt(&master)?;
    unlockpt(&master)?;
    let name = ptsname(&master, Vec::new())?;
    rustix::termios::tcsetwinsize(
        &master,
        rustix::termios::Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )?;
    let path = std::path::PathBuf::from(std::ffi::OsStr::from_bytes(name.as_bytes()));
    Ok((master, path))
}

use std::os::unix::ffi::OsStrExt;

/// Starts `ghostd pty-exec <tty> -- argv…` and waits until it has started
/// the program: answers its pid, or why it could not start it.
fn start_program(spec: &SpecFile, tty: &Path) -> Result<u32, String> {
    let (mut report, report_w) =
        std::io::pipe().map_err(|e| format!("a pipe for the start: {e}"))?;
    let mut command = Command::new("/proc/self/exe");
    std::os::unix::process::CommandExt::arg0(&mut command, "ghostd");
    command.arg("pty-exec").arg(tty).arg("--");
    command.args(spec.argv.iter().map(|a| std::ffi::OsStr::from_bytes(&a.0)));
    for name in &spec.env_remove {
        command.env_remove(std::ffi::OsStr::from_bytes(&name.0));
    }
    for (name, value) in &spec.env {
        command.env(
            std::ffi::OsStr::from_bytes(&name.0),
            std::ffi::OsStr::from_bytes(&value.0),
        );
    }
    command
        .current_dir(std::ffi::OsStr::from_bytes(&spec.cwd.0))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(report_w);
    let program = spec
        .argv
        .first()
        .map(|a| String::from_utf8_lossy(&a.0).into_owned())
        .unwrap_or_default();
    let child = command
        .spawn()
        .map_err(|e| format!("cannot start {program:?}: {e}"))?;
    // Our copy of the write end goes with the command: the read below ends
    // when the helper's copy closes, at its exec (close-on-exec) or exit.
    drop(command);
    let mut said = Vec::new();
    let _ = (&mut report).take(4096).read_to_end(&mut said);
    let pid = child.id();
    // Reaped by the supervisor's waitpid(-1), never through `child`.
    drop(child);
    if said.is_empty() {
        Ok(pid)
    } else {
        Err(String::from_utf8_lossy(&said).trim().to_string())
    }
}

/// `ghostd pty-exec <tty> -- argv…`: in a session of its own, makes `tty`
/// the controlling terminal and stdin, stdout and stderr, then execs
/// `argv`. Its stderr on entry is the shim's report pipe: it says there
/// why the program could not start, and the exec closes it.
pub fn pty_exec(tty: &Path, argv: &[OsString]) -> ExitCode {
    let report = |message: String| {
        let _ = std::io::stderr().write_all(message.as_bytes());
        ExitCode::from(127)
    };
    let Some((program, rest)) = argv.split_first() else {
        return report("no program".into());
    };
    if let Err(e) = nix::unistd::setsid() {
        return report(format!("setsid: {e}"));
    }
    let terminal = match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::fcntl::OFlag::O_NOCTTY.bits())
        .open(tty)
    {
        Ok(file) => file,
        Err(e) => return report(format!("opening {}: {e}", tty.display())),
    };
    if let Err(e) = rustix::process::ioctl_tiocsctty(&terminal) {
        return report(format!(
            "making {} the controlling terminal: {e}",
            tty.display()
        ));
    }
    // The report pipe, kept apart and closed by the exec.
    let report_pipe = match rustix::io::fcntl_dupfd_cloexec(std::io::stderr().as_fd(), 3) {
        Ok(fd) => File::from(fd),
        Err(e) => return report(format!("dup: {e}")),
    };
    let dup = rustix::stdio::dup2_stdin(&terminal)
        .and_then(|()| rustix::stdio::dup2_stdout(&terminal))
        .and_then(|()| rustix::stdio::dup2_stderr(&terminal));
    let mut report_pipe = report_pipe;
    if let Err(e) = dup {
        let _ = write!(report_pipe, "dup2: {e}");
        return ExitCode::from(127);
    }
    drop(terminal);
    let e = std::os::unix::process::CommandExt::exec(Command::new(program).args(rest));
    let _ = write!(
        report_pipe,
        "cannot start {:?}: {e}",
        program.to_string_lossy()
    );
    ExitCode::from(127)
}

/// Writes a status that says the session could not start, and answers the
/// shim's exit code.
fn failed(dir: &Path, status: &mut StatusFile, message: String) -> ExitCode {
    status.state = State::FailedToStart;
    status.message = Some(message);
    status.ended_at_ms = Some(now_ms());
    status.finished_at_ms = status.ended_at_ms;
    status.tree_gone = true;
    let _ = fs::remove_file(dir.join(SOCKET));
    let _ = write_status(dir, status, true);
    ExitCode::SUCCESS
}

#[allow(clippy::too_many_lines)]
pub fn run(dir: &Path) -> ExitCode {
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
    let cols = spec.cols.unwrap_or(120);
    let rows = spec.rows.unwrap_or(40);
    let mut status = StatusFile {
        format: FORMAT,
        state: State::Running,
        shim_pid: me,
        shim_start: procfs::start_time(me).unwrap_or(0),
        started_at_ms: now_ms(),
        stdout: StreamStatus::default(),
        stderr: StreamStatus::default(),
        cols: Some(cols),
        rows: Some(rows),
        ..StatusFile::default()
    };
    let (master, tty) = match open_pty(cols, rows) {
        Ok(pty) => pty,
        Err(e) => return failed(dir, &mut status, format!("cannot open a terminal: {e}")),
    };
    let socket = dir.join(SOCKET);
    let _ = fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(e) => {
            return failed(
                dir,
                &mut status,
                format!("cannot listen on {}: {e}", socket.display()),
            );
        }
    };
    let _ = fs::set_permissions(&socket, fs::Permissions::from_mode(0o600));
    let program = match start_program(&spec, &tty) {
        Ok(pid) => pid,
        Err(message) => {
            // Reap the helper that said why.
            let _ = nix::sys::wait::waitpid(None, None);
            return failed(dir, &mut status, message);
        }
    };
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
    let Ok(reader) = master.try_clone() else {
        return ExitCode::from(2);
    };
    let Ok(writer) = master.try_clone() else {
        return ExitCode::from(2);
    };
    let (input, queue) = mpsc::sync_channel::<Vec<u8>>(INPUT_QUEUE);
    let session = Arc::new(Session {
        term: Mutex::new(Term {
            parser: vt100::Parser::new_with_callbacks(rows, cols, SCROLLBACK, Hooks::default()),
            seq: 0,
            exited: None,
            over: false,
        }),
        changed: Condvar::new(),
        input: input.clone(),
        master,
        events: Mutex::new(tx.clone()),
        shared: Arc::clone(&shared),
        program,
        program_alive: AtomicBool::new(true),
    });
    // The program may write before anyone looks: the status says it runs
    // only once everything that serves it is up.
    shared.write(true);
    {
        let session = Arc::clone(&session);
        let tx = tx.clone();
        thread::spawn(move || {
            let shared = Arc::clone(&session.shared);
            copy(
                &shared,
                File::from(reader),
                super::Stream::Stdout,
                |chunk| {
                    let replies = {
                        let mut term = session.term();
                        term.parser.process(chunk);
                        term.seq += 1;
                        std::mem::take(&mut term.parser.callbacks_mut().replies)
                    };
                    session.changed.notify_all();
                    if !replies.is_empty() {
                        let _ = session.input.try_send(replies);
                    }
                },
            );
            let _ = tx.send(Event::PipeClosed);
        });
    }
    thread::spawn(move || {
        let mut terminal = File::from(writer);
        for bytes in queue {
            if terminal.write_all(&bytes).is_err() {
                break;
            }
        }
    });
    drop(input);
    {
        let session = Arc::clone(&session);
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let session = Arc::clone(&session);
                thread::spawn(move || serve(&session, stream));
            }
        });
    }
    drop(tx);

    let mut supervise = Supervise {
        shared: &shared,
        me,
        // The program's session, which `pty-exec` made: what is left in
        // it after the program ends is stopped.
        session: program,
        program,
        program_alive: true,
        children_lists: procfs::has_children_lists(),
        exit: None,
        stop: None,
        leftovers: None,
        count: Count::new(),
    };
    let mut pipes_open = 1;
    let mut exit_seen: Option<Instant> = None;
    let mut final_written = false;
    let hang_up = |supervise: &Supervise| {
        if supervise.program_alive {
            let group = pid_of(supervise.program);
            let _ = killpg(group, Signal::SIGHUP);
            let _ = killpg(group, Signal::SIGCONT);
        }
    };
    loop {
        let busy = supervise.stop.is_some()
            || supervise.leftovers.is_some()
            || (exit_seen.is_some() && !final_written);
        let mut wait = if busy {
            Duration::from_millis(20)
        } else {
            Duration::from_millis(250)
        };
        if supervise.count.child_ended {
            wait = wait.min(super::COUNT_AFTER_CHILD);
        }
        match rx.recv_timeout(wait) {
            Ok(Event::Signal(SIGTERM | SIGINT)) => {
                if supervise.stop.is_none() {
                    hang_up(&supervise);
                    supervise.begin_stop(spec.stop_grace_ms);
                }
            }
            Ok(Event::Close(grace)) => {
                if supervise.stop.is_none() {
                    hang_up(&supervise);
                    supervise.begin_stop(grace);
                }
            }
            Ok(Event::Signal(SIGCHLD)) => {
                if !supervise.program_alive {
                    supervise.count.child_ended = true;
                }
            }
            Ok(Event::PipeClosed) | Err(RecvTimeoutError::Disconnected) => pipes_open = 0,
            Ok(Event::Signal(_)) | Err(RecvTimeoutError::Timeout) => {}
        }
        supervise.reap();
        if !supervise.program_alive && exit_seen.is_none() {
            session.program_alive.store(false, Ordering::Relaxed);
            let now = Instant::now();
            exit_seen = Some(now);
            supervise.count.next = now;
            if supervise.stop.is_none() {
                // As an Exec: what it left in its session is stopped after
                // the settle; what detached into a session of its own stays.
                supervise.leftovers = Some(Leftovers {
                    settle_until: now + SETTLE,
                    grace_ms: spec.stop_grace_ms,
                    stop: None,
                });
            }
        }
        let progress = supervise.progress();
        // The program's end shows once its output is read: at once when
        // the terminal closed, after 100 ms when processes remain that may
        // hold it, after 2 s in any case.
        if let Some(seen) = exit_seen
            && !final_written
            && (pipes_open == 0
                || (progress.below > 0 && seen.elapsed() >= Duration::from_millis(100))
                || seen.elapsed() >= Duration::from_secs(2))
        {
            supervise.apply_exit();
            {
                let end = match supervise.exit {
                    Some((State::Signaled, _, signal, _)) => SessionEnd::Signaled {
                        signal: signal.unwrap_or(0),
                    },
                    Some((_, code, _, _)) => SessionEnd::Exited {
                        code: code.unwrap_or(-1),
                    },
                    None => SessionEnd::Exited { code: -1 },
                };
                session.term().exited = Some(end);
                session.changed.notify_all();
            }
            shared.write(true);
            final_written = true;
        }
        if final_written && progress.waiting == 0 {
            break;
        }
        if shared.dirty.load(Ordering::Relaxed) {
            shared.write(false);
        }
    }
    // What is left could still hold the terminal; give the reader a moment
    // to drain what the program wrote last.
    let until = Instant::now() + Duration::from_millis(if pipes_open == 0 { 0 } else { 200 });
    while pipes_open > 0 {
        match rx.recv_timeout(until.saturating_duration_since(Instant::now())) {
            Ok(Event::PipeClosed) => pipes_open = 0,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let screen = {
        let mut term = session.term();
        term.over = true;
        snapshot(&mut term, SCROLLBACK)
    };
    session.changed.notify_all();
    if let Ok(bytes) = serde_json::to_vec(&screen) {
        let _ = crate::util::atomic_write(&dir.join(SCREEN), &bytes, 0o600, true);
    }
    let _ = fs::remove_file(&socket);
    supervise.finish();
    shared.write(true);
    ExitCode::SUCCESS
}
