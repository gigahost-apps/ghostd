//! `ghostd worker`: serves the Unix socket. Started and restarted by the
//! supervisor; jobs live in their shims, so the worker can die at any time
//! without losing one.

use std::fs::{self, OpenOptions};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use ghostd_protocol::v1::{self, ClientFrame, Error, ErrorKind, Request, Response, ServerFrame};
use ghostd_protocol::{
    ClientHello, FrameDecoder, HelloAnswer, MARKER, MAX_FRAME, MAX_HELLO_FRAME, PROTOCOL_MAX,
    PROTOCOL_MIN, RelayInfo, ServerHello, decode, encode_frame, negotiate, outdated_side,
};
use nix::fcntl::{Flock, FlockArg};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::config::Config;
use crate::files::{self, SearchSpec, Uploads};
use crate::jobs::Jobs;
use crate::logfile::log;
use crate::paths::Paths;
use crate::util::err;

/// Requests in flight on one connection; more are answered `Busy`.
pub const MAX_IN_FLIGHT: usize = 64;
/// Answers queued for a connection's writer; a client that does not read
/// holds up its own handlers, not the daemon's memory.
const OUTGOING_QUEUE: usize = 16;
/// How often the worker checks that its socket is still the one it bound.
const SOCKET_CHECK: Duration = Duration::from_secs(10);
/// How long a connection may take to say hello.
const HELLO_TIMEOUT: Duration = Duration::from_secs(30);
/// How often finished jobs are collected.
const GC_EVERY: Duration = Duration::from_mins(10);

/// Whether a peer may use this daemon: only its own user.
#[must_use]
pub fn peer_allowed(peer_uid: u32, own_uid: u32) -> bool {
    peer_uid == own_uid
}

struct Shared {
    paths: Paths,
    jobs: Arc<Jobs>,
    uid: u32,
}

pub fn run(paths: &Paths) -> ExitCode {
    // Die with the supervisor: a worker it no longer watches must not keep
    // serving beside the next daemon's.
    let parent = nix::unistd::getppid();
    let _ = nix::sys::prctl::set_pdeathsig(nix::sys::signal::Signal::SIGTERM);
    if nix::unistd::getppid() != parent || parent.as_raw() == 1 {
        return ExitCode::from(1);
    }
    let config = match Config::load(&paths.config) {
        Ok(config) => config,
        Err(e) => {
            log(paths, &format!("worker: configuration: {e}"));
            return ExitCode::from(1);
        }
    };
    if let Err(e) = paths.ensure() {
        log(paths, &format!("worker: directories: {e}"));
        return ExitCode::from(1);
    }
    // One worker serves the socket: a second waits for the first to go.
    let lock_file = match OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(paths.worker_lock())
    {
        Ok(file) => file,
        Err(e) => {
            log(paths, &format!("worker: lock: {e}"));
            return ExitCode::from(1);
        }
    };
    let mut lock_file = Some(lock_file);
    let mut lock = None;
    for _ in 0..100 {
        match Flock::lock(
            lock_file.take().expect("the lock file"),
            FlockArg::LockExclusiveNonblock,
        ) {
            Ok(l) => {
                lock = Some(l);
                break;
            }
            Err((file, _)) => {
                lock_file = Some(file);
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
    let Some(_lock) = lock else {
        log(paths, "worker: another worker holds the socket");
        return ExitCode::from(1);
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log(paths, &format!("worker: runtime: {e}"));
            return ExitCode::from(1);
        }
    };
    let shared = Arc::new(Shared {
        paths: paths.clone(),
        jobs: Arc::new(Jobs::new(paths.jobs(), config)),
        uid: nix::unistd::getuid().as_raw(),
    });
    runtime.block_on(serve(shared))
}

async fn serve(shared: Arc<Shared>) -> ExitCode {
    let socket = shared.paths.socket();
    if let Ok(meta) = fs::symlink_metadata(&socket) {
        if meta.file_type().is_socket() {
            let _ = fs::remove_file(&socket);
        } else {
            log(
                &shared.paths,
                &format!("worker: {} is not a socket", socket.display()),
            );
            return ExitCode::from(1);
        }
    }
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(e) => {
            log(
                &shared.paths,
                &format!("worker: bind {}: {e}", socket.display()),
            );
            return ExitCode::from(1);
        }
    };
    let _ = fs::set_permissions(&socket, fs::Permissions::from_mode(0o600));
    let bound = fs::symlink_metadata(&socket)
        .map(|m| (m.dev(), m.ino()))
        .ok();
    let mut socket_check = tokio::time::interval(SOCKET_CHECK);
    log(
        &shared.paths,
        &format!("worker: serving {}", socket.display()),
    );
    {
        let jobs = Arc::clone(&shared.jobs);
        let paths = shared.paths.clone();
        tokio::spawn(async move {
            loop {
                let j = Arc::clone(&jobs);
                if let Ok(collected) = tokio::task::spawn_blocking(move || j.gc()).await {
                    if collected.removed > 0 {
                        log(
                            &paths,
                            &format!("worker: removed {} finished jobs", collected.removed),
                        );
                    }
                    if !collected.unreadable.is_empty() {
                        log(
                            &paths,
                            &format!(
                                "worker: left {} job directories it cannot read: {}",
                                collected.unreadable.len(),
                                collected.unreadable.join(", ")
                            ),
                        );
                    }
                }
                tokio::time::sleep(GC_EVERY).await;
            }
        });
    }
    let Ok(mut term) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    else {
        return ExitCode::from(1);
    };
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    let uid = stream.peer_cred().map(|c| c.uid());
                    match uid {
                        Ok(uid) if peer_allowed(uid, shared.uid) => {
                            tokio::spawn(connection(stream, Arc::clone(&shared)));
                        }
                        Ok(uid) => {
                            log(&shared.paths, &format!("worker: refused a connection from uid {uid}"));
                        }
                        Err(e) => log(&shared.paths, &format!("worker: peer credentials: {e}")),
                    }
                }
                Err(e) => {
                    log(&shared.paths, &format!("worker: accept: {e}"));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            },
            _ = term.recv() => break,
            _ = socket_check.tick() => {
                // The runtime directory can be removed under us (a login
                // manager clears $XDG_RUNTIME_DIR when the last session
                // ends) or the socket replaced: a daemon nobody can reach
                // stops instead of lingering beside the next one.
                let now = fs::symlink_metadata(&socket).map(|m| (m.dev(), m.ino())).ok();
                if now != bound {
                    log(&shared.paths, &format!("worker: {} is gone or replaced; stopping", socket.display()));
                    return ExitCode::SUCCESS;
                }
            }
        }
    }
    let _ = fs::remove_file(&socket);
    log(&shared.paths, "worker: stopped");
    ExitCode::SUCCESS
}

/// Reads one frame of at most the decoder's cap; `None` at EOF.
async fn read_frame(
    reader: &mut OwnedReadHalf,
    decoder: &mut FrameDecoder,
    buf: &mut [u8],
) -> Result<Option<Vec<u8>>, String> {
    loop {
        if let Some(frame) = decoder.next_frame().map_err(|e| e.to_string())? {
            return Ok(Some(frame));
        }
        let n = reader.read(buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Ok(None);
        }
        decoder.feed(&buf[..n]);
    }
}

async fn hello(
    reader: &mut OwnedReadHalf,
    writer: &mut OwnedWriteHalf,
    decoder: &mut FrameDecoder,
    buf: &mut [u8],
) -> Result<Option<(RelayInfo, u32)>, String> {
    let Some(body) = read_frame(reader, decoder, buf).await? else {
        return Ok(None);
    };
    let relay: RelayInfo = decode(&body).map_err(|e| format!("relay preamble: {e}"))?;
    let mut opening = MARKER.to_vec();
    opening.extend(
        encode_frame(&ServerHello {
            program_version: env!("CARGO_PKG_VERSION").to_string(),
            min: PROTOCOL_MIN,
            max: PROTOCOL_MAX,
        })
        .map_err(|e| e.to_string())?,
    );
    writer
        .write_all(&opening)
        .await
        .map_err(|e| e.to_string())?;
    let Some(body) = read_frame(reader, decoder, buf).await? else {
        return Ok(None);
    };
    let client: ClientHello = decode(&body).map_err(|e| format!("client hello: {e}"))?;
    let ours = (PROTOCOL_MIN, PROTOCOL_MAX);
    let theirs = (client.min, client.max);
    let (answer, version) = if let Some(version) = negotiate(ours, theirs) {
        (HelloAnswer::Welcome { version }, Some(version))
    } else {
        let update = if outdated_side(ours, theirs) {
            "update ghostd"
        } else {
            "update the client"
        };
        (
            HelloAnswer::Refused {
                server_min: PROTOCOL_MIN,
                server_max: PROTOCOL_MAX,
                message: format!(
                    "no common protocol version: ghostd {} speaks {}..={}, the client {} speaks {}..={}; {update}",
                    env!("CARGO_PKG_VERSION"),
                    PROTOCOL_MIN,
                    PROTOCOL_MAX,
                    client.program_version,
                    client.min,
                    client.max
                ),
            },
            None,
        )
    };
    writer
        .write_all(&encode_frame(&answer).map_err(|e| e.to_string())?)
        .await
        .map_err(|e| e.to_string())?;
    Ok(version.map(|v| (relay, v)))
}

/// What the writer task sends.
enum Outgoing {
    Frame(ServerFrame),
    /// A protocol error: sent, then the connection is closed.
    Fatal(String),
}

#[allow(clippy::too_many_lines)]
async fn connection(stream: UnixStream, shared: Arc<Shared>) {
    let (mut reader, mut writer) = stream.into_split();
    let mut decoder = FrameDecoder::with_max(MAX_HELLO_FRAME);
    let mut buf = vec![0u8; 64 * 1024];
    let greeted = tokio::time::timeout(
        HELLO_TIMEOUT,
        hello(&mut reader, &mut writer, &mut decoder, &mut buf),
    )
    .await;
    let (relay, version) = match greeted {
        Ok(Ok(Some(done))) => done,
        Ok(Ok(None)) => return,
        Ok(Err(e)) => {
            log(&shared.paths, &format!("worker: hello: {e}"));
            return;
        }
        Err(_) => {
            log(&shared.paths, "worker: hello timed out");
            return;
        }
    };
    // Only version 1 exists; a `v2` module would be dispatched on the
    // agreed version here.
    debug_assert_eq!(version, v1::VERSION);
    decoder.set_max(MAX_FRAME);
    let (tx, mut rx) = mpsc::channel::<Outgoing>(OUTGOING_QUEUE);
    let writer_task = tokio::spawn(async move {
        while let Some(out) = rx.recv().await {
            let (frame, fatal) = match out {
                Outgoing::Frame(frame) => (frame, false),
                Outgoing::Fatal(message) => (ServerFrame::ProtocolError { message }, true),
            };
            let bytes = match encode_frame(&frame) {
                Ok(bytes) => bytes,
                Err(e) => {
                    let ServerFrame::Response { id, .. } = frame else {
                        continue;
                    };
                    let refusal = ServerFrame::Response {
                        id,
                        result: Err(err(
                            ErrorKind::TooLarge,
                            format!("the answer does not fit a frame ({e}); ask for less"),
                        )),
                    };
                    let Ok(bytes) = encode_frame(&refusal) else {
                        continue;
                    };
                    bytes
                }
            };
            if writer.write_all(&bytes).await.is_err() {
                return;
            }
            if fatal {
                let _ = writer.shutdown().await;
                return;
            }
        }
        let _ = writer.shutdown().await;
    });
    let label = relay.client_label.clone().unwrap_or_else(|| "-".into());
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT));
    let uploads = Arc::new(Uploads::default());
    // An upload's chunks, its end and its abort are carried out one at a
    // time in the order they arrive, so that a client may send the chunks
    // without waiting for each answer. Everything else runs concurrently.
    let (upload_tx, mut upload_rx) =
        mpsc::channel::<(u64, Request, OwnedSemaphorePermit)>(MAX_IN_FLIGHT);
    let upload_task = {
        let tx = tx.clone();
        let shared = Arc::clone(&shared);
        let uploads = Arc::clone(&uploads);
        tokio::spawn(async move {
            while let Some((id, request, permit)) = upload_rx.recv().await {
                let result = handle(&shared, &uploads, request).await;
                let _ = tx
                    .send(Outgoing::Frame(ServerFrame::Response { id, result }))
                    .await;
                drop(permit);
            }
        })
    };
    loop {
        let body = match read_frame(&mut reader, &mut decoder, &mut buf).await {
            Ok(Some(body)) => body,
            Ok(None) => break,
            Err(e) => {
                log(&shared.paths, &format!("worker: client {label}: {e}"));
                let _ = tx.send(Outgoing::Fatal(e)).await;
                break;
            }
        };
        let (id, request) = match decode::<ClientFrame>(&body) {
            Ok(ClientFrame::Request { id, body }) => (id, body),
            Err(e) => {
                log(&shared.paths, &format!("worker: client {label}: {e}"));
                let _ = tx.send(Outgoing::Fatal(e.to_string())).await;
                break;
            }
        };
        let Ok(permit) = Arc::clone(&in_flight).try_acquire_owned() else {
            let busy = ServerFrame::Response {
                id,
                result: Err(err(
                    ErrorKind::Busy,
                    format!("{MAX_IN_FLIGHT} requests are in flight on this connection"),
                )),
            };
            let _ = tx.send(Outgoing::Frame(busy)).await;
            continue;
        };
        if matches!(
            request,
            Request::UploadChunk { .. } | Request::UploadEnd { .. } | Request::UploadAbort { .. }
        ) {
            // The permits bound the queue: this never waits.
            let _ = upload_tx.send((id, request, permit)).await;
            continue;
        }
        let tx = tx.clone();
        let shared = Arc::clone(&shared);
        let uploads = Arc::clone(&uploads);
        tokio::spawn(async move {
            let result = handle(&shared, &uploads, request).await;
            let _ = tx
                .send(Outgoing::Frame(ServerFrame::Response { id, result }))
                .await;
            drop(permit);
        });
    }
    // Answer what is in flight, then close.
    drop(upload_tx);
    let all = u32::try_from(MAX_IN_FLIGHT).unwrap_or(u32::MAX);
    let _ = in_flight.acquire_many(all).await;
    let _ = upload_task.await;
    drop(tx);
    let _ = writer_task.await;
    drop(uploads);
}

async fn blocking<F>(f: F) -> Result<Response, Error>
where
    F: FnOnce() -> Result<Response, Error> + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| err(ErrorKind::Internal, format!("a task failed: {e}")))?
}

#[allow(clippy::too_many_lines)]
async fn handle(
    shared: &Shared,
    uploads: &Arc<Uploads>,
    request: Request,
) -> Result<Response, Error> {
    let jobs = Arc::clone(&shared.jobs);
    match request {
        Request::Ping => Ok(Response::Pong),
        Request::Exec(spec) => jobs.exec(spec).await.map(Response::Exec),
        Request::JobStart(spec) => jobs
            .job_start(spec)
            .await
            .map(|job_id| Response::JobStarted { job_id }),
        Request::JobList {
            include_finished,
            limit,
        } => blocking(move || Ok(Response::Jobs(jobs.list(include_finished, limit)))).await,
        Request::JobStatus { job_id } => {
            blocking(move || jobs.info(&job_id).map(Response::Job)).await
        }
        Request::JobWait { job_id, timeout_ms } => {
            jobs.wait(job_id, timeout_ms).await.map(Response::Job)
        }
        Request::JobLogRead {
            job_id,
            stream,
            offset,
            max_len,
        } => {
            blocking(move || {
                jobs.log_read(&job_id, stream, offset, max_len)
                    .map(Response::LogSlice)
            })
            .await
        }
        Request::JobSignal { job_id, signal } => {
            blocking(move || jobs.signal(&job_id, signal).map(|()| Response::Done)).await
        }
        Request::JobStop { job_id, grace_ms } => {
            jobs.stop(job_id, grace_ms).await.map(Response::Job)
        }
        Request::JobRemove { job_id } => {
            blocking(move || jobs.remove(&job_id).map(|()| Response::Done)).await
        }
        Request::FileStat { path, follow } => blocking(move || files::stat(&path, follow)).await,
        Request::FileRead { path, offset, len } => {
            blocking(move || files::read(&path, offset, len)).await
        }
        Request::FileWrite {
            path,
            data,
            mode,
            create_dirs,
        } => blocking(move || files::write(&path, &data, mode, create_dirs)).await,
        Request::UploadBegin {
            path,
            mode,
            create_dirs,
        } => {
            let uploads = Arc::clone(uploads);
            blocking(move || uploads.begin(&path, mode, create_dirs)).await
        }
        Request::UploadChunk {
            handle,
            offset,
            data,
        } => {
            let uploads = Arc::clone(uploads);
            blocking(move || uploads.chunk(handle, offset, &data)).await
        }
        Request::UploadEnd { handle, sha256 } => {
            let uploads = Arc::clone(uploads);
            blocking(move || uploads.end(handle, sha256)).await
        }
        Request::UploadAbort { handle } => {
            let uploads = Arc::clone(uploads);
            blocking(move || uploads.abort(handle)).await
        }
        Request::FileEdit {
            path,
            old,
            new,
            replace_all,
        } => blocking(move || files::edit(&path, &old, &new, replace_all)).await,
        Request::FileList {
            path,
            depth,
            max_entries,
        } => blocking(move || files::list(&path, depth, max_entries)).await,
        Request::FileSearch {
            pattern,
            path,
            globs,
            case_insensitive,
            hidden,
            max_matches,
        } => {
            blocking(move || {
                files::search(&SearchSpec {
                    pattern: &pattern,
                    path: &path,
                    globs: &globs,
                    case_insensitive,
                    hidden,
                    max_matches,
                })
            })
            .await
        }
        Request::FileHash { path } => blocking(move || files::hash(&path)).await,
        Request::FileRemove { path, recursive } => {
            blocking(move || files::remove(&path, recursive)).await
        }
        Request::FileRename {
            from,
            to,
            overwrite,
        } => blocking(move || files::rename(&from, &to, overwrite)).await,
        Request::FileMkdir {
            path,
            parents,
            mode,
        } => blocking(move || files::mkdir(&path, parents, mode)).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_own_uid() {
        assert!(peer_allowed(1000, 1000));
        assert!(!peer_allowed(0, 1000));
        assert!(!peer_allowed(1001, 1000));
    }
}
