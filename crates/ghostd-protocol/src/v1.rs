//! Protocol version 1: the messages after the hellos.
//!
//! Every frame from the client is a [`ClientFrame`], every frame from the
//! server a [`ServerFrame`]. Requests run concurrently on the server and
//! their responses may come back in any order; the `id` pairs them. Only
//! an upload's chunks, end and abort run one at a time, in the order they
//! arrive, so that chunks may be sent without waiting for each answer.
//!
//! Everything a Unix system may hold as non-UTF-8 bytes (arguments,
//! environment names and values, paths, file contents, output) is bytes
//! here. Text is only used for messages meant for people.
//!
//! Do not change anything in this module: a change is protocol version 2,
//! in a new module (see the crate's versioning rule).

use serde::{Deserialize, Serialize};

/// The version this module defines.
pub const VERSION: u32 = 1;

/// The largest data a single file read, write, upload chunk or log read
/// carries: 8 MiB.
pub const MAX_DATA: usize = 8 * 1024 * 1024;

/// A frame from the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientFrame {
    Request { id: u64, body: Request },
}

/// A frame from the server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

/// A request is newer than the version both sides agreed on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "this request needs protocol version {required}, the connection speaks {agreed}: update ghostd"
)]
pub struct UnsupportedVersion {
    pub required: u32,
    pub agreed: u32,
}

/// Refuses a request that needs a newer version than the agreed one.
///
/// # Errors
///
/// [`UnsupportedVersion`] when `required > agreed`.
pub fn ensure_supported(required: u32, agreed: u32) -> Result<(), UnsupportedVersion> {
    if required > agreed {
        Err(UnsupportedVersion { required, agreed })
    } else {
        Ok(())
    }
}

/// A request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Request {
    /// Answered [`Response::Pong`].
    Ping,
    /// Runs a program to its end (or its timeout) and answers its result.
    Exec(ExecSpec),
    /// Starts a program as a job and answers its ID at once.
    JobStart(ExecSpec),
    /// The jobs, newest first. `limit` 0 means 100. Without
    /// `include_finished`, only the jobs not [`JobInfo::finished`].
    JobList {
        include_finished: bool,
        limit: u32,
    },
    JobStatus {
        job_id: String,
    },
    /// Waits for the job to be [`JobInfo::finished`], at most `timeout_ms`
    /// (capped at 60 s).
    JobWait {
        job_id: String,
        timeout_ms: u64,
    },
    /// A slice of a job's output. `offset` `None` reads the last `max_len`
    /// bytes; `max_len` is at most [`MAX_DATA`].
    JobLogRead {
        job_id: String,
        stream: Stream,
        offset: Option<u64>,
        max_len: u32,
    },
    /// Sends `signal` to the program's process group.
    JobSignal {
        job_id: String,
        signal: i32,
    },
    /// Stops the job and everything it started; answers once all is gone.
    JobStop {
        job_id: String,
        grace_ms: Option<u64>,
    },
    /// Removes a [`JobInfo::finished`] job and its logs (`Busy` before).
    JobRemove {
        job_id: String,
    },
    FileStat {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        follow: bool,
    },
    FileRead {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        offset: u64,
        len: u32,
    },
    /// Replaces a file atomically.
    FileWrite {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        mode: Option<u32>,
        create_dirs: bool,
    },
    UploadBegin {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        mode: Option<u32>,
        create_dirs: bool,
    },
    UploadChunk {
        handle: u64,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
    },
    UploadEnd {
        handle: u64,
        sha256: Option<[u8; 32]>,
    },
    UploadAbort {
        handle: u64,
    },
    FileEdit {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        #[serde(with = "serde_bytes")]
        old: Vec<u8>,
        #[serde(with = "serde_bytes")]
        new: Vec<u8>,
        replace_all: bool,
    },
    /// `depth` 0 means 1 (at most 16); `max_entries` 0 means 1000 (at most
    /// 100 000).
    FileList {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        depth: u32,
        max_entries: u32,
    },
    /// A regex search with ripgrep's defaults. `max_matches` 0 means 200
    /// (at most 10 000).
    FileSearch {
        pattern: String,
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        globs: Vec<String>,
        case_insensitive: bool,
        hidden: bool,
        max_matches: u32,
    },
    FileHash {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
    },
    FileRemove {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        recursive: bool,
    },
    FileRename {
        #[serde(with = "serde_bytes")]
        from: Vec<u8>,
        #[serde(with = "serde_bytes")]
        to: Vec<u8>,
        overwrite: bool,
    },
    FileMkdir {
        #[serde(with = "serde_bytes")]
        path: Vec<u8>,
        parents: bool,
        mode: Option<u32>,
    },
}

impl Request {
    /// The lowest protocol version that has this request.
    #[must_use]
    pub fn min_version(&self) -> u32 {
        1
    }
}

/// What to run, for [`Request::Exec`] and [`Request::JobStart`].
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ExecSpec {
    pub program: Program,
    /// Bytes for the program's stdin; `None` gives it `/dev/null`.
    #[serde(with = "serde_bytes")]
    pub stdin: Option<Vec<u8>>,
    /// Set after `env_clear` and `env_remove`.
    pub env: Vec<(Vec<u8>, Vec<u8>)>,
    pub env_remove: Vec<Vec<u8>>,
    pub env_clear: bool,
    /// Relative to `$HOME`; `$HOME` when `None`.
    #[serde(with = "serde_bytes")]
    pub cwd: Option<Vec<u8>>,
    /// Runs it through the user's login shell, as positional parameters.
    pub login: bool,
    pub timeout_ms: Option<u64>,
    /// Exec only: how many of the last bytes of each stream to answer.
    pub output_cap: Option<u64>,
    /// Exec only: leave the program running as a job at the timeout.
    pub keep_on_timeout: bool,
    pub name: Option<String>,
    /// The job's ID chosen by the client (`j` and 16 random lowercase hex
    /// digits), so that it knows the ID before any answer comes: after a
    /// lost answer it finds the job by it on any connection, and sending
    /// the same request again starts nothing new (`JobStart` answers the
    /// job, `Exec` waits for it and answers its result; another request
    /// under a kept job's ID is refused with `Conflict`). `None`: the
    /// server chooses.
    pub job_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Program {
    /// `argv[0]` is looked up in `$PATH` when it has no slash. Non-empty.
    Argv(Vec<Vec<u8>>),
    /// A script written to a file and run with `interpreter` (default: its
    /// `#!` line, else `/bin/sh`), followed by `args`.
    Script {
        #[serde(with = "serde_bytes")]
        body: Vec<u8>,
        interpreter: Option<Vec<Vec<u8>>>,
        args: Vec<Vec<u8>>,
    },
}

impl Default for Program {
    fn default() -> Self {
        Self::Argv(Vec::new())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecResult {
    pub job_id: String,
    pub outcome: Outcome,
    pub stdout: Output,
    pub stderr: Output,
    pub duration_ms: u64,
    /// How many processes the program left in the job's session were
    /// stopped after it ended by itself (0 normally). A plain background
    /// process (`cmd &`, `nohup cmd &`) does not outlive an Exec: start it
    /// with [`Request::JobStart`], or detach it into a session of its own
    /// (`setsid`, a daemon's own forking), which is left running.
    pub stopped: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    Exited {
        code: i32,
    },
    Signaled {
        signal: i32,
    },
    /// `killed` false: the program still runs as the job `job_id`.
    TimedOut {
        killed: bool,
    },
    FailedToStart {
        message: String,
    },
}

/// The last bytes of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Output {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// The absolute offset of `data`'s first byte in the stream; more than
    /// 0 means the earlier bytes are in the job's log.
    pub offset: u64,
    /// All bytes the stream produced.
    pub total: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// The state of a job's program (not of what it left running: see
/// [`JobInfo::finished`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JobState {
    Running,
    Exited {
        code: i32,
    },
    Signaled {
        signal: i32,
    },
    /// Its shim is gone without a final state; nothing is killed for it.
    Lost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobInfo {
    pub job_id: String,
    pub name: Option<String>,
    /// The first four arguments, lossy, at most 200 characters.
    pub argv_summary: String,
    pub state: JobState,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub stdout_total: u64,
    pub stderr_total: u64,
    pub pid: Option<u32>,
    /// The processes still in the job's session, the program included
    /// (0 once finished). A job lives as long as any is left: what the
    /// program leaves in the background when it ends belongs to the job.
    pub processes: u32,
    /// Nothing is left in the job's session and the final state is
    /// written (or the job is [`JobState::Lost`]). `state` is the
    /// program's: it can be `Exited` while the job is not finished yet.
    /// Processes that started a session of their own are not waited for.
    pub finished: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogSlice {
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// The absolute offset of `data`'s first byte.
    pub offset: u64,
    pub total: u64,
    /// The lowest offset still kept (older bytes were rotated away).
    pub first_available: u64,
    /// The job is [`JobInfo::finished`] and `total` is final.
    pub ended: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stat {
    pub kind: FileKind,
    pub size: u64,
    /// The permission bits (`st_mode & 0o7777`).
    pub mode: u32,
    pub mtime_ms: i64,
    pub uid: u32,
    pub gid: u32,
    #[serde(with = "serde_bytes")]
    pub link_target: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchMatch {
    #[serde(with = "serde_bytes")]
    pub path: Vec<u8>,
    pub line_number: u64,
    /// The line, without its line terminator, at most 4 KiB.
    #[serde(with = "serde_bytes")]
    pub line: Vec<u8>,
}

/// An answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Response {
    Pong,
    Exec(ExecResult),
    JobStarted {
        job_id: String,
    },
    Jobs(Vec<JobInfo>),
    Job(JobInfo),
    LogSlice(LogSlice),
    /// The request was carried out and has nothing to answer.
    Done,
    Stat(Stat),
    FileData {
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        size: u64,
        eof: bool,
    },
    Written {
        size: u64,
        sha256: [u8; 32],
    },
    Upload {
        handle: u64,
    },
    Edited {
        replacements: u64,
        sha256: [u8; 32],
    },
    /// Paths relative to the listed directory, depth first, each
    /// directory's entries sorted by name.
    Listing {
        entries: Vec<(Vec<u8>, Stat)>,
        truncated: bool,
    },
    Matches {
        matches: Vec<SearchMatch>,
        truncated: bool,
    },
    Hash {
        size: u64,
        sha256: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrameDecoder, decode, encode_frame};

    #[test]
    fn round_trip() {
        let frame = ClientFrame::Request {
            id: 7,
            body: Request::Exec(ExecSpec {
                program: Program::Argv(vec![b"echo".to_vec(), vec![0xff, 0, b'\'']]),
                stdin: Some(b"in".to_vec()),
                env: vec![(b"A".to_vec(), b"\xfe".to_vec())],
                ..ExecSpec::default()
            }),
        };
        let bytes = encode_frame(&frame).unwrap();
        let mut d = FrameDecoder::new();
        d.feed(&bytes);
        let body = d.next_frame().unwrap().unwrap();
        assert_eq!(decode::<ClientFrame>(&body).unwrap(), frame);
    }

    /// A tiny deterministic generator (xorshift64*), so the test needs no
    /// dependency and always feeds the same inputs.
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
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        let valid = encode_frame(&ClientFrame::Request {
            id: 1,
            body: Request::FileWrite {
                path: b"a".to_vec(),
                data: b"b".to_vec(),
                mode: Some(0o644),
                create_dirs: true,
            },
        })
        .unwrap();
        for i in 0..100_000 {
            let len = usize::try_from(rng.next() % 64).unwrap();
            let mut input: Vec<u8> = (0..len).map(|_| rng.next().to_le_bytes()[0]).collect();
            if i % 3 == 0 {
                // Mutate a valid frame, to reach deeper into the decoders.
                input = valid.clone();
                let at = usize::try_from(rng.next()).unwrap() % input.len();
                input[at] = rng.next().to_le_bytes()[0];
            }
            let _ = decode::<ClientFrame>(&input);
            let _ = decode::<ServerFrame>(&input);
            let _ = decode::<crate::ClientHello>(&input);
            let mut d = FrameDecoder::new();
            d.feed(&input);
            while let Ok(Some(body)) = d.next_frame() {
                let _ = decode::<ClientFrame>(&body);
            }
        }
    }
}
