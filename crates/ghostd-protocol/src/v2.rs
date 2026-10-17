//! Protocol version 2: version 1's requests plus the host ID check,
//! sessions (persistent PTYs), waits and the machine's state.
//!
//! Every frame from the client is a [`ClientFrame`], every frame from the
//! server a [`ServerFrame`]. A request of version 1 travels wrapped, as
//! [`Request::V1`], and is answered [`Response::V1`]: its types and its
//! meaning are version 1's, unchanged (they are reused from [`crate::v1`],
//! never copied). The new requests follow it.
//!
//! Each request may carry the [`HostId`] the client expects: a server with
//! another ID (or none it can read) answers [`ErrorKind::HostMismatch`]
//! without running anything, so a client that kept a machine's ID finds out
//! when the name or address it connects to now reaches another ghostd state
//! (another machine, or this one with a new state). A copy of the state (a
//! disk image, a backup restored elsewhere) keeps the ID and passes.
//!
//! Do not change anything in this module once released: a change is
//! protocol version 3, in a new module (see the crate's versioning rule).

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::v1;
pub use crate::v1::{
    ExecResult, ExecSpec, FileKind, JobInfo, JobState, LogSlice, MAX_DATA, Outcome, Output,
    Program, SearchMatch, Stat, Stream, UnsupportedVersion, ensure_supported,
};

/// The version this module defines.
pub const VERSION: u32 = 2;

/// A daemon's identity: 16 random bytes it made the first time it started
/// with no state, kept in its state directory. It stays across restarts,
/// updates and reboots, and changes when its ghostd state is new
/// (reinstalled, swapped, another user's daemon); a copy of the state (a
/// disk image, a restored backup) keeps it. Shown as 32 lowercase hex
/// digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HostId(pub [u8; 16]);

impl fmt::Display for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for HostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostId({self})")
    }
}

/// A [`HostId`] that is not 32 hex digits.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("a host ID is 32 hex digits")]
pub struct BadHostId;

impl FromStr for HostId {
    type Err = BadHostId;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(BadHostId);
        }
        let mut out = [0u8; 16];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| BadHostId)?;
        }
        Ok(Self(out))
    }
}

/// A frame from the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientFrame {
    Request {
        id: u64,
        /// The server's [`HostId`] the client expects; a server with
        /// another answers [`ErrorKind::HostMismatch`] and runs nothing.
        expected_host: Option<HostId>,
        body: Request,
    },
}

/// A frame from the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ServerFrame {
    Response {
        id: u64,
        result: Result<Response, Error>,
    },
    /// The server could not decode a frame; it closes the connection after
    /// sending this.
    ProtocolError { message: String },
}

/// What went wrong with a request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[error("{kind:?}: {message}")]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
    /// The `errno` behind it, when a system call failed.
    pub os_code: Option<i32>,
}

impl Error {
    #[must_use]
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            os_code: None,
        }
    }
}

/// Version 1's kinds, in the same order, then the new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    NotFound,
    PermissionDenied,
    AlreadyExists,
    InvalidArgument,
    TooLarge,
    Conflict,
    Busy,
    Io,
    Unsupported,
    Internal,
    /// The request's `expected_host` is not this server's [`HostId`], or
    /// the server cannot read its own: nothing was run.
    HostMismatch,
}

impl From<v1::ErrorKind> for ErrorKind {
    fn from(kind: v1::ErrorKind) -> Self {
        match kind {
            v1::ErrorKind::NotFound => Self::NotFound,
            v1::ErrorKind::PermissionDenied => Self::PermissionDenied,
            v1::ErrorKind::AlreadyExists => Self::AlreadyExists,
            v1::ErrorKind::InvalidArgument => Self::InvalidArgument,
            v1::ErrorKind::TooLarge => Self::TooLarge,
            v1::ErrorKind::Conflict => Self::Conflict,
            v1::ErrorKind::Busy => Self::Busy,
            v1::ErrorKind::Io => Self::Io,
            v1::ErrorKind::Unsupported => Self::Unsupported,
            v1::ErrorKind::Internal => Self::Internal,
        }
    }
}

impl From<v1::Error> for Error {
    fn from(e: v1::Error) -> Self {
        Self {
            kind: e.kind.into(),
            message: e.message,
            os_code: e.os_code,
        }
    }
}

/// A request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// A version 1 request, with version 1's meaning; answered
    /// [`Response::V1`].
    V1(v1::Request),
    /// Answered [`Response::Identity`]; an [`ErrorKind::Io`] error while
    /// the server cannot read its host ID.
    Identify,
    /// Starts a program on a new PTY and answers its ID at once.
    SessionStart(SessionSpec),
    /// Types into the session; answered `V1(Done)` once queued.
    SessionSend { session_id: String, input: Vec<Key> },
    /// The session's screen. With `until`, answers when it holds or at
    /// `wait_ms` (at most 60 s); without, at once.
    SessionRead {
        session_id: String,
        wait_ms: u64,
        until: Option<Until>,
        /// How many lines above the screen to answer in
        /// [`Screen::scrollback`] (0: none; at most 1000).
        scrollback_lines: u32,
    },
    /// Answered `V1(Done)`.
    SessionResize {
        session_id: String,
        cols: u16,
        rows: u16,
    },
    /// Sends `signal` to the PTY's foreground process group; answered
    /// `V1(Done)`.
    SessionSignal { session_id: String, signal: i32 },
    /// Every kept session, live and ended, newest first.
    SessionList,
    /// Hangs the session up and stops everything it started; answers its
    /// info once all is gone. Its final screen and log are kept.
    SessionClose {
        session_id: String,
        grace_ms: Option<u64>,
    },
    /// A slice of the session's raw output, as `JobLogRead`; answered
    /// `V1(LogSlice)`.
    SessionLogRead {
        session_id: String,
        offset: Option<u64>,
        max_len: u32,
    },
    /// Waits on the machine for a condition, polling cheaply.
    Wait(WaitSpec),
    /// Answered [`Response::Machine`].
    MachineState,
}

impl Request {
    /// The lowest protocol version that has this request.
    #[must_use]
    pub fn min_version(&self) -> u32 {
        match self {
            Self::V1(request) => request.min_version(),
            _ => VERSION,
        }
    }
}

impl From<v1::Request> for Request {
    fn from(request: v1::Request) -> Self {
        Self::V1(request)
    }
}

/// What a session runs, for [`Request::SessionStart`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SessionSpec {
    /// `None`: the user's login shell (`$SHELL -l`, else `/bin/sh -l`).
    /// `argv[0]` is looked up in `$PATH` when it has no slash.
    pub argv: Option<Vec<Vec<u8>>>,
    /// Set after `env_remove`, over the daemon's environment; `TERM` is
    /// `xterm-256color` unless set here.
    pub env: Vec<(Vec<u8>, Vec<u8>)>,
    pub env_remove: Vec<Vec<u8>>,
    /// Relative to `$HOME`; `$HOME` when `None`.
    #[serde(with = "serde_bytes")]
    pub cwd: Option<Vec<u8>>,
    /// 20..=500, default 120.
    pub cols: Option<u16>,
    /// 5..=200, default 40.
    pub rows: Option<u16>,
    /// The session's ID chosen by the client (`s` and 16 random lowercase
    /// hex digits), as `ExecSpec::job_id`: the same request again answers
    /// the session it started, another request under its ID is refused
    /// with `Conflict`. `None`: the server chooses.
    pub session_id: Option<String>,
    pub name: Option<String>,
}

/// One thing typed into a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Key {
    /// Its UTF-8 bytes, as they are.
    Text(String),
    Bytes(#[serde(with = "serde_bytes")] Vec<u8>),
    Named(NamedKey),
}

/// A key, sent as an xterm sends it (the arrows, Home and End follow the
/// application cursor-key mode the program set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NamedKey {
    Enter,
    Tab,
    Escape,
    Backspace,
    Delete,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    /// A letter `a`–`z` (either case), `[`, `\`, `]`, `^` or `_`.
    Ctrl(char),
    /// Escape, then the character.
    Alt(char),
}

/// When a [`Request::SessionRead`] answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Until {
    /// The program wrote output after [`Screen::changed_since`] `since`
    /// (`None`: after the request arrived).
    Changed { since: Option<u64> },
    /// A regex (Rust's `regex` syntax) matches the screen's text.
    Matches(String),
    /// The session's program has exited.
    Exited,
}

/// How a session's program ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionEnd {
    Exited { code: i32 },
    Signaled { signal: i32 },
}

/// A session's screen.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Screen {
    /// The rows joined with `\n`, each without its trailing spaces.
    pub text: String,
    /// (row, column), from 0.
    pub cursor: (u16, u16),
    pub cols: u16,
    pub rows: u16,
    /// The title the program set, empty when none.
    pub title: String,
    /// A full-screen program (`vi`, `less`, `top`) switched to the
    /// alternate screen.
    pub alternate_screen: bool,
    /// The lines above the screen, oldest first, when asked for.
    pub scrollback: Option<String>,
    /// Set once the program has exited.
    pub exited: Option<SessionEnd>,
    /// A sequence number bumped on every output and every resize: equal
    /// numbers, the same screen. Give it to [`Until::Changed`].
    pub changed_since: u64,
    /// Whether the request's `until` held when it answered (`None`
    /// without one).
    pub until_met: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub name: Option<String>,
    /// The first four arguments, lossy, at most 200 characters.
    pub argv_summary: String,
    /// The program's state, as a job's.
    pub state: JobState,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub pid: Option<u32>,
    pub cols: u16,
    pub rows: u16,
    /// Every byte of output it produced.
    pub output_total: u64,
    /// Its program has ended, nothing is left of it and its final screen
    /// is written (or it is `Lost`).
    pub finished: bool,
}

/// What a [`Request::Wait`] waits for.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WaitSpec {
    pub condition: Condition,
    /// At most 300 000.
    pub timeout_ms: u64,
    /// How often it looks: default 250, at least 50.
    pub interval_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Condition {
    /// A TCP connection to `host` (default `127.0.0.1`) and `port`
    /// succeeds.
    PortOpen {
        host: Option<String>,
        port: u16,
    },
    /// An `http://` URL answers a GET with `status` (default: any 2xx or
    /// 3xx). No TLS: for `https://`, wait for the port or exec `curl`.
    HttpStatus {
        url: String,
        status: Option<u16>,
    },
    FileExists {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
    },
    /// A regex matches the file's last 1 MiB.
    FileContains {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        regex: String,
    },
    /// A regex matches output written after `from_offset` (default: the
    /// stream's total when the wait began), within 64 KiB of text.
    LogMatches {
        source: LogSource,
        /// A session has one stream: this is ignored for it.
        stream: Stream,
        regex: String,
        from_offset: Option<u64>,
    },
    /// No process `pid` runs (with `start_time`, the clock ticks since
    /// boot of `/proc/<pid>/stat`, not one that reused the pid).
    ProcessGone {
        pid: u32,
        start_time: Option<u64>,
    },
    JobFinished {
        job_id: String,
    },
    SessionExited {
        session_id: String,
    },
}

impl Default for Condition {
    fn default() -> Self {
        Self::FileExists { path: Vec::new() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogSource {
    Job(String),
    Session(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity {
    pub host_id: HostId,
    pub hostname: String,
    /// `/etc/machine-id`.
    pub machine_id: Option<String>,
    /// `/proc/sys/kernel/random/boot_id`: changes on every boot.
    pub boot_id: Option<String>,
    pub program_version: String,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Memory {
    pub total: u64,
    pub available: u64,
    pub swap_total: u64,
    pub swap_free: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disk {
    pub mount: String,
    pub fs: String,
    pub device: String,
    pub total: u64,
    pub free: u64,
    /// As `df` counts it: used over used plus available to the user.
    pub used_pct: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listening {
    pub proto: Proto,
    pub address: String,
    pub port: u16,
    /// Known for the daemon's user's own processes.
    pub pid: Option<u32>,
    pub process: Option<String>,
}

/// The machine's state in one answer. A part that cannot be read is left
/// empty (or `None`) and `notes` says why; the answer never fails as a
/// whole.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct Machine {
    pub hostname: String,
    /// `PRETTY_NAME` of `/etc/os-release`.
    pub os: String,
    /// `uname -r`.
    pub kernel: String,
    pub arch: String,
    pub uptime_s: u64,
    pub load: (f32, f32, f32),
    pub cpus: u32,
    pub memory: Memory,
    pub disks: Vec<Disk>,
    pub listening: Vec<Listening>,
    /// `systemctl --failed`; `None` without systemd.
    pub failing_units: Option<Vec<String>>,
    /// The kernel's last 20 messages at `err` or worse.
    pub kernel_errors: Vec<String>,
    /// The journal's last 20 at `err` or worse.
    pub journal_errors: Vec<String>,
    /// What could not be read, and why.
    pub notes: Vec<String>,
}

/// An answer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Response {
    /// The answer to a [`Request::V1`], and `Done` or `LogSlice` for some
    /// of the new requests.
    V1(v1::Response),
    Identity(Identity),
    SessionStarted {
        session_id: String,
    },
    Screen(Screen),
    Sessions(Vec<SessionInfo>),
    Session(SessionInfo),
    Waited {
        met: bool,
        elapsed_ms: u64,
        /// What it saw last, for people.
        detail: String,
    },
    Machine(Box<Machine>),
}

impl Response {
    /// `V1(Done)`: the request was carried out and has nothing to answer.
    pub const DONE: Self = Self::V1(v1::Response::Done);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrameDecoder, decode, encode_frame};

    #[test]
    fn host_ids_print_and_parse() {
        let id = HostId([0xab; 16]);
        assert_eq!(id.to_string(), "ab".repeat(16));
        assert_eq!(id.to_string().parse::<HostId>().unwrap(), id);
        assert!("ab".parse::<HostId>().is_err());
        assert!("zz".repeat(16).parse::<HostId>().is_err());
        assert!("é".repeat(16).parse::<HostId>().is_err());
    }

    #[test]
    fn version_1_kinds_keep_their_place() {
        // The kinds a version 1 error converts to encode at the same index
        // as in version 1.
        let kinds = [
            v1::ErrorKind::NotFound,
            v1::ErrorKind::PermissionDenied,
            v1::ErrorKind::AlreadyExists,
            v1::ErrorKind::InvalidArgument,
            v1::ErrorKind::TooLarge,
            v1::ErrorKind::Conflict,
            v1::ErrorKind::Busy,
            v1::ErrorKind::Io,
            v1::ErrorKind::Unsupported,
            v1::ErrorKind::Internal,
        ];
        for kind in kinds {
            assert_eq!(
                postcard::to_stdvec(&kind).unwrap(),
                postcard::to_stdvec(&ErrorKind::from(kind)).unwrap()
            );
        }
        assert_eq!(
            postcard::to_stdvec(&ErrorKind::HostMismatch).unwrap(),
            vec![10]
        );
    }

    #[test]
    fn a_wrapped_version_1_request_is_version_1() {
        let request: Request = v1::Request::Ping.into();
        assert_eq!(request.min_version(), 1);
        assert_eq!(Request::Identify.min_version(), 2);
        assert_eq!(Request::MachineState.min_version(), 2);
    }

    fn samples() -> Vec<ClientFrame> {
        let frame = |id, expected_host, body| ClientFrame::Request {
            id,
            expected_host,
            body,
        };
        vec![
            frame(1, None, Request::V1(v1::Request::Ping)),
            frame(
                2,
                Some(HostId([7; 16])),
                Request::V1(v1::Request::Exec(ExecSpec {
                    program: Program::Argv(vec![b"echo".to_vec(), vec![0xff]]),
                    ..ExecSpec::default()
                })),
            ),
            frame(3, None, Request::Identify),
            frame(
                4,
                None,
                Request::SessionStart(SessionSpec {
                    argv: Some(vec![b"sh".to_vec()]),
                    cols: Some(80),
                    session_id: Some("s0123456789abcdef".into()),
                    ..SessionSpec::default()
                }),
            ),
            frame(
                5,
                None,
                Request::SessionSend {
                    session_id: "s1".into(),
                    input: vec![
                        Key::Text("echo hi".into()),
                        Key::Named(NamedKey::Enter),
                        Key::Named(NamedKey::Ctrl('c')),
                        Key::Bytes(vec![0, 0xff]),
                    ],
                },
            ),
            frame(
                6,
                None,
                Request::SessionRead {
                    session_id: "s1".into(),
                    wait_ms: 100,
                    until: Some(Until::Matches("hi".into())),
                    scrollback_lines: 10,
                },
            ),
            frame(
                7,
                None,
                Request::Wait(WaitSpec {
                    condition: Condition::LogMatches {
                        source: LogSource::Job("j1".into()),
                        stream: Stream::Stderr,
                        regex: "ready".into(),
                        from_offset: Some(3),
                    },
                    timeout_ms: 1000,
                    interval_ms: None,
                }),
            ),
            frame(8, None, Request::MachineState),
        ]
    }

    #[test]
    fn round_trip() {
        for frame in samples() {
            let bytes = encode_frame(&frame).unwrap();
            let mut d = FrameDecoder::new();
            d.feed(&bytes);
            let body = d.next_frame().unwrap().unwrap();
            assert_eq!(decode::<ClientFrame>(&body).unwrap(), frame);
        }
        let answers = vec![
            ServerFrame::Response {
                id: 1,
                result: Ok(Response::DONE),
            },
            ServerFrame::Response {
                id: 2,
                result: Err(Error::new(ErrorKind::HostMismatch, "m")),
            },
            ServerFrame::Response {
                id: 3,
                result: Ok(Response::Screen(Screen {
                    text: "$ ".into(),
                    cursor: (0, 2),
                    cols: 80,
                    rows: 24,
                    exited: Some(SessionEnd::Exited { code: 0 }),
                    ..Screen::default()
                })),
            },
            ServerFrame::Response {
                id: 4,
                result: Ok(Response::Machine(Box::new(Machine {
                    load: (0.5, 1.0, 1.5),
                    failing_units: Some(vec!["a.service".into()]),
                    ..Machine::default()
                }))),
            },
            ServerFrame::ProtocolError {
                message: "x".into(),
            },
        ];
        for answer in answers {
            let body = postcard::to_stdvec(&answer).unwrap();
            assert_eq!(decode::<ServerFrame>(&body).unwrap(), answer);
        }
    }

    #[test]
    fn a_wrapped_request_carries_version_1_bytes() {
        // V1 is variant 0, then version 1's own encoding: nothing of
        // version 1 is re-encoded differently.
        let inner = v1::Request::JobStatus {
            job_id: "j1".into(),
        };
        let mut expected = vec![0];
        expected.extend(postcard::to_stdvec(&inner).unwrap());
        assert_eq!(postcard::to_stdvec(&Request::V1(inner)).unwrap(), expected);
    }

    /// A tiny deterministic generator (xorshift64*), as in version 1's
    /// test.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 >> 12;
            self.0 ^= self.0 << 25;
            self.0 ^= self.0 >> 27;
            self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
        }
    }

    #[test]
    fn random_input_never_panics() {
        let mut rng = Rng(0x2545_f491_4f6c_dd1d);
        let valid: Vec<Vec<u8>> = samples()
            .iter()
            .map(|f| postcard::to_stdvec(f).unwrap())
            .collect();
        for i in 0..100_000 {
            let len = usize::try_from(rng.next() % 64).unwrap();
            let mut input: Vec<u8> = (0..len).map(|_| rng.next().to_le_bytes()[0]).collect();
            if i % 3 == 0 {
                // Mutate a valid frame, to reach deeper into the decoders.
                let pick = usize::try_from(rng.next()).unwrap() % valid.len();
                input.clone_from(&valid[pick]);
                let at = usize::try_from(rng.next()).unwrap() % input.len();
                input[at] = rng.next().to_le_bytes()[0];
            }
            let _ = decode::<ClientFrame>(&input);
            let _ = decode::<ServerFrame>(&input);
            let mut d = FrameDecoder::new();
            d.feed(&input);
            while let Ok(Some(body)) = d.next_frame() {
                let _ = decode::<ClientFrame>(&body);
                let _ = decode::<ServerFrame>(&body);
            }
        }
    }
}
