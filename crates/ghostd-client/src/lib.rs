//! A client connection to `ghostd`.
//!
//! [`Connection::spawn`] runs a command whose stdin and stdout reach a
//! `ghostd stdio` (typically `ssh -T host /full/path/ghostd stdio`),
//! [`Connection::from_io`] uses any byte stream. Either
//! scans for the marker (skipping a login shell's banner), negotiates the
//! protocol version and then answers [`Connection::call`]s, many at once,
//! over the one stream.
//!
//! It speaks protocol versions 1 and 2. A call takes a version 1 request
//! (answered with version 1's response) or a version 2 one; on a
//! connection agreed at version 1 a version 2 request that exists in
//! version 1 ([`v2::Request::V1`]) is sent as version 1, and any other is
//! refused before anything is sent. The expected host ID
//! ([`Connection::set_expected_host`]) needs version 2: with version 1 it
//! is not sent, and [`Connection::host_check`] says so.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ghostd_protocol::v2::HostId;
use ghostd_protocol::{
    ClientHello, FrameDecoder, FrameError, HelloAnswer, MAX_FRAME, MAX_HELLO_FRAME, MarkerScan,
    MarkerScanner, PROTOCOL_MAX, PROTOCOL_MIN, ServerHello, decode, encode_frame,
};
use ghostd_protocol::{v1, v2};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

/// How much of a spawned command's stderr is kept for error messages.
const STDERR_KEPT: usize = 4096;

/// What can go wrong on a connection.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The stream ended, or 1 MiB came, without the ghostd marker.
    #[error("no ghostd hello ({reason}); the other side said: {}", shown(.discarded, .stderr))]
    NoHello {
        reason: String,
        /// The first 200 bytes that came before, lossy.
        discarded: String,
        /// The tail of the spawned command's stderr (`ssh`'s errors).
        stderr: String,
    },
    /// The two sides speak no protocol version in common.
    #[error(
        "no common protocol version: ghostd speaks {server_min}..={server_max}, this client {client_min}..={client_max}; update {update} ({message})"
    )]
    Refused {
        client_min: u32,
        client_max: u32,
        server_min: u32,
        server_max: u32,
        /// `ghostd` or `this client`: the side whose maximum is lower.
        update: &'static str,
        message: String,
    },
    /// The server broke the protocol (or reported that we did).
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The request needs a newer version than the connection speaks.
    #[error(transparent)]
    Unsupported(#[from] v1::UnsupportedVersion),
    /// The server answered the request with an error (a version 1 error
    /// converted).
    #[error("{0}")]
    Remote(v2::Error),
    /// The connection is closed; every pending and later call fails.
    #[error("connection closed: {0}")]
    Closed(String),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

fn shown(discarded: &str, stderr: &str) -> String {
    let mut parts = Vec::new();
    if !discarded.trim().is_empty() {
        parts.push(format!("{:?}", discarded.trim()));
    }
    if !stderr.trim().is_empty() {
        parts.push(format!("stderr {:?}", stderr.trim()));
    }
    if parts.is_empty() {
        "nothing".to_string()
    } else {
        parts.join(", ")
    }
}

/// The version range and program version a client announces.
#[derive(Debug, Clone)]
pub struct Options {
    pub min: u32,
    pub max: u32,
    pub program_version: String,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
            program_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

type Answer = Result<Result<v2::Response, v2::Error>, ClientError>;

mod sealed {
    pub trait Sealed {}
    impl Sealed for ghostd_protocol::v1::Request {}
    impl Sealed for ghostd_protocol::v2::Request {}
}

/// A request [`Connection::call`] sends: a version 1 one (answered with a
/// version 1 response) or a version 2 one.
pub trait Call: sealed::Sealed {
    type Response;
    #[doc(hidden)]
    fn into_v2(self) -> v2::Request;
    #[doc(hidden)]
    fn from_v2(response: v2::Response) -> Result<Self::Response, ClientError>;
}

impl Call for v1::Request {
    type Response = v1::Response;

    fn into_v2(self) -> v2::Request {
        v2::Request::V1(self)
    }

    fn from_v2(response: v2::Response) -> Result<v1::Response, ClientError> {
        match response {
            v2::Response::V1(response) => Ok(response),
            other => Err(ClientError::Protocol(format!(
                "a version 2 answer to a version 1 request: {other:?}"
            ))),
        }
    }
}

impl Call for v2::Request {
    type Response = v2::Response;

    fn into_v2(self) -> v2::Request {
        self
    }

    fn from_v2(response: v2::Response) -> Result<v2::Response, ClientError> {
        Ok(response)
    }
}

#[derive(Default)]
struct Pending {
    waiting: HashMap<u64, oneshot::Sender<Answer>>,
    closed: Option<String>,
}

type Writer = Box<dyn AsyncWrite + Send + Unpin>;

/// Frames queued for the writer task.
const OUTGOING_QUEUE: usize = 16;

/// What the writer task writes.
enum Outgoing {
    /// One whole encoded frame.
    Frame(Vec<u8>),
    /// Shuts the sending side down after the frames queued before it.
    Shutdown(oneshot::Sender<std::io::Result<()>>),
}

/// A connection to a `ghostd`.
///
/// Calls are cancel-safe: one writer task writes every frame whole, so a
/// call dropped halfway (a timeout around it, a cancelled tool call) never
/// leaves part of a frame on the stream, and its answer, when it comes, is
/// dropped.
pub struct Connection {
    outgoing: mpsc::Sender<Outgoing>,
    pending: Arc<Mutex<Pending>>,
    next_id: AtomicU64,
    version: u32,
    server_version: String,
    expected_host: Mutex<Option<HostId>>,
    reader: JoinHandle<()>,
    writer: JoinHandle<()>,
    child: Option<Child>,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("version", &self.version)
            .field("server_version", &self.server_version)
            .finish_non_exhaustive()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}

/// Forgets a call's pending entry when the call ends, answered or dropped.
struct Forget<'a> {
    pending: &'a Mutex<Pending>,
    id: u64,
}

impl Drop for Forget<'_> {
    fn drop(&mut self) {
        lock(self.pending).waiting.remove(&self.id);
    }
}

impl Connection {
    /// Connects over a byte stream.
    ///
    /// # Errors
    ///
    /// When the hello does not come or no version is in common.
    pub async fn from_io<R, W>(reader: R, writer: W) -> Result<Self, ClientError>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        Self::from_io_with(reader, writer, Options::default()).await
    }

    /// Connects over a byte stream announcing `options`' version range
    /// (for tests and compatibility checks).
    ///
    /// # Errors
    ///
    /// When the hello does not come or no version is in common.
    pub async fn from_io_with<R, W>(
        mut reader: R,
        writer: W,
        options: Options,
    ) -> Result<Self, ClientError>
    where
        R: AsyncRead + Send + Unpin + 'static,
        W: AsyncWrite + Send + Unpin + 'static,
    {
        let mut writer: Writer = Box::new(writer);
        let (version, server_version, decoder) =
            handshake(&mut reader, &mut writer, &options).await?;
        let pending = Arc::new(Mutex::new(Pending::default()));
        let reader = tokio::spawn(read_loop(reader, decoder, version, Arc::clone(&pending)));
        let (outgoing, queue) = mpsc::channel(OUTGOING_QUEUE);
        let writer = tokio::spawn(write_loop(writer, queue, Arc::clone(&pending)));
        Ok(Self {
            outgoing,
            pending,
            next_id: AtomicU64::new(1),
            version,
            server_version,
            expected_host: Mutex::new(None),
            reader,
            writer,
            child: None,
        })
    }

    /// Spawns `argv` (for example `["ssh", "-T", "host", "ghostd", "stdio"]`)
    /// and connects over its stdin and stdout.
    ///
    /// # Errors
    ///
    /// When it cannot be spawned, or its hello does not come (the error
    /// then holds the tail of its stderr).
    pub async fn spawn<S: AsRef<OsStr>>(argv: &[S]) -> Result<Self, ClientError> {
        let Some((program, rest)) = argv.split_first() else {
            return Err(ClientError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "an empty command",
            )));
        };
        let mut command = Command::new(program);
        command.args(rest);
        Self::spawn_command(command, Options::default()).await
    }

    /// Spawns a prepared command (its stdio is replaced) and connects over
    /// its stdin and stdout.
    ///
    /// # Errors
    ///
    /// As [`Connection::spawn`].
    pub async fn spawn_command(
        mut command: Command,
        options: Options,
    ) -> Result<Self, ClientError> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn()?;
        let stdin = child.stdin.take().ok_or_else(|| no_pipe("stdin"))?;
        let stdout = child.stdout.take().ok_or_else(|| no_pipe("stdout"))?;
        let stderr = child.stderr.take().ok_or_else(|| no_pipe("stderr"))?;
        let tail = Arc::new(Mutex::new(Vec::new()));
        let stderr_task = tokio::spawn(keep_tail(stderr, Arc::clone(&tail)));
        match Self::from_io_with(stdout, stdin, options).await {
            Ok(mut connection) => {
                connection.child = Some(child);
                Ok(connection)
            }
            Err(mut error) => {
                // Give the command a moment to exit and say why.
                let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                let _ = tokio::time::timeout(Duration::from_secs(1), stderr_task).await;
                let text = {
                    let tail = tail
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    String::from_utf8_lossy(&tail).into_owned()
                };
                if let ClientError::NoHello { stderr, .. } = &mut error {
                    *stderr = text;
                } else if !text.trim().is_empty() {
                    error = match error {
                        ClientError::Closed(m) => {
                            ClientError::Closed(format!("{m}; stderr {:?}", text.trim()))
                        }
                        ClientError::Protocol(m) => {
                            ClientError::Protocol(format!("{m}; stderr {:?}", text.trim()))
                        }
                        other => other,
                    };
                }
                let _ = child.start_kill();
                Err(error)
            }
        }
    }

    /// The protocol version both sides agreed on.
    #[must_use]
    pub fn version(&self) -> u32 {
        self.version
    }

    /// The server program's version from its hello.
    #[must_use]
    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    /// Whether the server checks the expected host ID
    /// ([`Connection::set_expected_host`]): from protocol version 2.
    #[must_use]
    pub fn host_check(&self) -> bool {
        self.version >= v2::VERSION
    }

    /// The server's host ID every later call names as the one it expects
    /// (`None`: no check). A server with another ID answers
    /// [`v2::ErrorKind::HostMismatch`] and runs nothing. Not sent on a
    /// version 1 connection (see [`Connection::host_check`]).
    pub fn set_expected_host(&self, host: Option<HostId>) {
        *self
            .expected_host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = host;
    }

    /// The host ID set by [`Connection::set_expected_host`].
    #[must_use]
    pub fn expected_host(&self) -> Option<HostId> {
        *self
            .expected_host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Sends a request and waits for its answer. Many calls may run at
    /// once; answers are paired by request ID. Dropping the future (a
    /// timeout) is safe: the request is then either not sent at all or
    /// sent whole, and the connection stays usable. It carries the
    /// expected host ID when one is set and the connection speaks
    /// version 2.
    ///
    /// # Errors
    ///
    /// [`ClientError::Remote`] for the server's error answer, others when
    /// the request is too new for the connection or the connection fails.
    pub async fn call<R: Call>(&self, request: R) -> Result<R::Response, ClientError> {
        let expected = self.expected_host();
        self.call_expecting(request, expected).await
    }

    /// [`Connection::call`] naming `expected_host` for this call only.
    ///
    /// # Errors
    ///
    /// As [`Connection::call`].
    pub async fn call_expecting<R: Call>(
        &self,
        request: R,
        expected_host: Option<HostId>,
    ) -> Result<R::Response, ClientError> {
        let request = request.into_v2();
        v1::ensure_supported(request.min_version(), self.version)?;
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let encoded = if self.version >= v2::VERSION {
            encode_frame(&v2::ClientFrame::Request {
                id,
                expected_host,
                body: request,
            })
        } else {
            let v2::Request::V1(body) = request else {
                // ensure_supported let only version 1 requests through.
                return Err(ClientError::Unsupported(v1::UnsupportedVersion {
                    required: v2::VERSION,
                    agreed: self.version,
                }));
            };
            encode_frame(&v1::ClientFrame::Request { id, body })
        };
        let frame = encoded.map_err(|e| ClientError::Protocol(e.to_string()))?;
        let (tx, rx) = oneshot::channel();
        {
            let mut pending = lock(&self.pending);
            if let Some(reason) = &pending.closed {
                return Err(ClientError::Closed(reason.clone()));
            }
            pending.waiting.insert(id, tx);
        }
        let _forget = Forget {
            pending: &self.pending,
            id,
        };
        // A queued frame is written whole by the writer task; a send
        // cancelled while it waits for room queues nothing.
        if self.outgoing.send(Outgoing::Frame(frame)).await.is_err() {
            return Err(self.closed_error());
        }
        match rx.await {
            Ok(Ok(Ok(response))) => R::from_v2(response),
            Ok(Ok(Err(remote))) => Err(ClientError::Remote(remote)),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(self.closed_error()),
        }
    }

    fn closed_error(&self) -> ClientError {
        ClientError::Closed(
            lock(&self.pending)
                .closed
                .clone()
                .unwrap_or_else(|| "the connection stopped".into()),
        )
    }

    /// Closes the sending side once the requests sent before are written;
    /// the server ends the connection once the pending calls are answered.
    ///
    /// # Errors
    ///
    /// When the stream cannot be shut down.
    pub async fn shutdown(&self) -> Result<(), ClientError> {
        let (done, result) = oneshot::channel();
        if self.outgoing.send(Outgoing::Shutdown(done)).await.is_err() {
            return Err(self.closed_error());
        }
        result.await.map_err(|_| self.closed_error())??;
        Ok(())
    }
}

/// Writes the queued frames, each whole, in the order they were queued.
async fn write_loop(
    mut writer: Writer,
    mut queue: mpsc::Receiver<Outgoing>,
    pending: Arc<Mutex<Pending>>,
) {
    while let Some(out) = queue.recv().await {
        match out {
            Outgoing::Frame(frame) => {
                let written = match writer.write_all(&frame).await {
                    Ok(()) => writer.flush().await,
                    Err(e) => Err(e),
                };
                if let Err(e) = written {
                    close(&pending, &format!("cannot send: {e}"));
                    return;
                }
            }
            Outgoing::Shutdown(done) => {
                let _ = done.send(writer.shutdown().await);
            }
        }
    }
}

/// Marks the connection closed and fails every pending call.
fn close(pending: &Mutex<Pending>, reason: &str) {
    let waiting = {
        let mut pending = lock(pending);
        if pending.closed.is_none() {
            pending.closed = Some(reason.to_string());
        }
        std::mem::take(&mut pending.waiting)
    };
    for (_, tx) in waiting {
        let _ = tx.send(Err(ClientError::Closed(reason.to_string())));
    }
}

fn no_pipe(name: &str) -> ClientError {
    ClientError::Io(std::io::Error::other(format!("no {name} pipe")))
}

fn lock(pending: &Mutex<Pending>) -> std::sync::MutexGuard<'_, Pending> {
    pending
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

async fn keep_tail<R: AsyncRead + Unpin>(mut stderr: R, tail: Arc<Mutex<Vec<u8>>>) {
    let mut buf = vec![0u8; 4096];
    loop {
        match stderr.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                let mut tail = tail
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                tail.extend_from_slice(&buf[..n]);
                if tail.len() > STDERR_KEPT {
                    let cut = tail.len() - STDERR_KEPT;
                    tail.drain(..cut);
                }
            }
        }
    }
}

async fn read_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    decoder: &mut FrameDecoder,
    buf: &mut [u8],
) -> Result<Option<Vec<u8>>, ClientError> {
    loop {
        if let Some(frame) = decoder
            .next_frame()
            .map_err(|e: FrameError| ClientError::Protocol(e.to_string()))?
        {
            return Ok(Some(frame));
        }
        let n = reader.read(buf).await?;
        if n == 0 {
            return Ok(None);
        }
        decoder.feed(&buf[..n]);
    }
}

async fn handshake<R: AsyncRead + Unpin>(
    reader: &mut R,
    writer: &mut Writer,
    options: &Options,
) -> Result<(u32, String, FrameDecoder), ClientError> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut scanner = MarkerScanner::new();
    let rest = loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Err(ClientError::NoHello {
                reason: "the stream ended first".into(),
                discarded: scanner.discarded_text(),
                stderr: String::new(),
            });
        }
        match scanner.feed(&buf[..n]) {
            MarkerScan::NeedMore => {}
            MarkerScan::Found { rest } => break rest,
            MarkerScan::TooMuch => {
                return Err(ClientError::NoHello {
                    reason: "1 MiB came without it".into(),
                    discarded: scanner.discarded_text(),
                    stderr: String::new(),
                });
            }
        }
    };
    let mut decoder = FrameDecoder::with_max(MAX_HELLO_FRAME);
    decoder.feed(&rest);
    let closed = || ClientError::Closed("the stream ended during the hello".into());
    let body = read_frame(reader, &mut decoder, &mut buf)
        .await?
        .ok_or_else(closed)?;
    let hello: ServerHello = decode(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
    let ours = ClientHello {
        program_version: options.program_version.clone(),
        min: options.min,
        max: options.max,
    };
    let frame = encode_frame(&ours).map_err(|e| ClientError::Protocol(e.to_string()))?;
    writer.write_all(&frame).await?;
    writer.flush().await?;
    let body = read_frame(reader, &mut decoder, &mut buf)
        .await?
        .ok_or_else(closed)?;
    let answer: HelloAnswer = decode(&body).map_err(|e| ClientError::Protocol(e.to_string()))?;
    match answer {
        HelloAnswer::Welcome { version } => {
            if version < options.min || version > options.max {
                return Err(ClientError::Protocol(format!(
                    "the server chose version {version}, outside this client's {}..={}",
                    options.min, options.max
                )));
            }
            decoder.set_max(MAX_FRAME);
            Ok((version, hello.program_version, decoder))
        }
        HelloAnswer::Refused {
            server_min,
            server_max,
            message,
        } => Err(ClientError::Refused {
            client_min: options.min,
            client_max: options.max,
            server_min,
            server_max,
            update: if ghostd_protocol::outdated_side(
                (server_min, server_max),
                (options.min, options.max),
            ) {
                "ghostd"
            } else {
                "this client"
            },
            message,
        }),
    }
}

/// A server frame of either version, as version 2's.
fn decode_server_frame(body: &[u8], version: u32) -> Result<v2::ServerFrame, FrameError> {
    if version >= v2::VERSION {
        return decode::<v2::ServerFrame>(body);
    }
    Ok(match decode::<v1::ServerFrame>(body)? {
        v1::ServerFrame::Response { id, result } => v2::ServerFrame::Response {
            id,
            result: result.map(v2::Response::V1).map_err(v2::Error::from),
        },
        v1::ServerFrame::ProtocolError { message } => v2::ServerFrame::ProtocolError { message },
    })
}

async fn read_loop<R: AsyncRead + Unpin>(
    mut reader: R,
    mut decoder: FrameDecoder,
    version: u32,
    pending: Arc<Mutex<Pending>>,
) {
    let mut buf = vec![0u8; 64 * 1024];
    let failure = loop {
        let body = match read_frame(&mut reader, &mut decoder, &mut buf).await {
            Ok(Some(body)) => body,
            Ok(None) => break ClientError::Closed("the server closed the connection".into()),
            Err(e) => break e,
        };
        match decode_server_frame(&body, version) {
            Ok(v2::ServerFrame::Response { id, result }) => {
                let waiter = lock(&pending).waiting.remove(&id);
                if let Some(tx) = waiter {
                    let _ = tx.send(Ok(result));
                }
            }
            Ok(v2::ServerFrame::ProtocolError { message }) => {
                break ClientError::Protocol(format!("the server reported: {message}"));
            }
            Err(e) => break ClientError::Protocol(e.to_string()),
        }
    };
    close(&pending, &failure.to_string());
}
