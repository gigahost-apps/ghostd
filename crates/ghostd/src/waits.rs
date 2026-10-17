//! `Wait`: a condition looked at on the machine until it holds or the
//! timeout, so that one request replaces a client's polling loop. Each look
//! is bounded: a connection attempt or an HTTP request takes at most 5 s, a
//! file is read at most 1 MiB from its end, a log at most 1 MiB per read
//! with 64 KiB carried over between reads. Nothing runs a shell.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ghostd_protocol::v2::{Condition, Error, ErrorKind, JobState, LogSource, Stream, WaitSpec};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::jobs::{Jobs, read_log};
use crate::procfs;
use crate::sessions::Sessions;
use crate::util::resolve;

/// The longest a wait waits.
pub const MAX_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_INTERVAL_MS: u64 = 250;
const MIN_INTERVAL_MS: u64 = 50;
/// How long one connection attempt or HTTP request may take.
const TRY_TIMEOUT: Duration = Duration::from_secs(5);
/// How much of a file's end `FileContains` reads.
const FILE_TAIL: u64 = 1024 * 1024;
/// How much of a log one read takes.
const LOG_CHUNK: usize = 1024 * 1024;
/// How much of what a log showed before is kept for a match across reads.
const LOG_CARRY: usize = 64 * 1024;
/// How much of an HTTP answer is read for its status line.
const STATUS_LINE_MAX: usize = 8 * 1024;

fn err(kind: ErrorKind, message: impl Into<String>) -> Error {
    Error::new(kind, message)
}

fn invalid(message: impl Into<String>) -> Error {
    err(ErrorKind::InvalidArgument, message)
}

fn bytes_regex(pattern: &str) -> Result<regex::bytes::Regex, Error> {
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|e| invalid(format!("the regex: {e}")))
}

/// What one look found.
struct Look {
    met: bool,
    detail: String,
    /// Nothing can change any more (a log whose job finished).
    settled: bool,
}

impl Look {
    fn met(detail: impl Into<String>) -> Self {
        Self {
            met: true,
            detail: detail.into(),
            settled: true,
        }
    }

    fn not_yet(detail: impl Into<String>) -> Self {
        Self {
            met: false,
            detail: detail.into(),
            settled: false,
        }
    }
}

/// An `http://` URL, taken apart.
#[derive(Debug, PartialEq, Eq)]
struct Url {
    /// To connect to (an IPv6 address without its brackets).
    host: String,
    port: u16,
    /// For the `Host` header.
    authority: String,
    /// The path and query.
    target: String,
}

fn parse_url(url: &str) -> Result<Url, Error> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Err(invalid(
            "HttpStatus speaks plain http:// only (no TLS): wait with PortOpen, or exec curl",
        ));
    }
    let Some(rest) = lower.starts_with("http://").then(|| &url[7..]) else {
        return Err(invalid("the URL is not an http:// URL"));
    };
    if url
        .bytes()
        .any(|b| b.is_ascii_control() || b == b' ' || !b.is_ascii())
    {
        return Err(invalid(
            "the URL holds a space, a control character or non-ASCII; percent-encode it",
        ));
    }
    let rest = rest.split('#').next().unwrap_or_default();
    let split = rest.find(['/', '?']).unwrap_or(rest.len());
    let (authority, target) = rest.split_at(split);
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid("the URL needs a host, and no user"));
    }
    let target = match target {
        "" => "/".to_string(),
        t if t.starts_with('?') => format!("/{t}"),
        t => t.to_string(),
    };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6
            .split_once(']')
            .ok_or_else(|| invalid("an unclosed [ in the URL's host"))?;
        let port = match after {
            "" => None,
            p => Some(
                p.strip_prefix(':')
                    .ok_or_else(|| invalid("junk after the URL's host"))?,
            ),
        };
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (authority.to_string(), None),
        }
    };
    let port = match port {
        None => 80,
        Some(p) => p
            .parse::<u16>()
            .ok()
            .filter(|&p| p > 0)
            .ok_or_else(|| invalid(format!("the URL's port {p:?} is not a port")))?,
    };
    if host.is_empty() {
        return Err(invalid("the URL needs a host"));
    }
    Ok(Url {
        host,
        port,
        authority: authority.to_string(),
        target,
    })
}

/// The status code of an HTTP answer's first line, `None` when it is not
/// one.
fn status_code(head: &[u8]) -> Option<u16> {
    let line = head.split(|&b| b == b'\n').next()?;
    let line = std::str::from_utf8(line).ok()?.trim_end_matches('\r');
    let mut parts = line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    code.parse().ok()
}

async fn connect(host: &str, port: u16, budget: Duration) -> Result<tokio::net::TcpStream, String> {
    match tokio::time::timeout(budget, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err(format!("no answer within {} ms", budget.as_millis())),
    }
}

async fn http_status(url: &Url, budget: Duration) -> Result<u16, String> {
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: ghostd\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        url.target, url.authority
    );
    let attempt = async {
        let mut stream = connect(&url.host, url.port, budget).await?;
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut head = Vec::new();
        let mut buf = [0u8; 2048];
        while !head.contains(&b'\n') && head.len() < STATUS_LINE_MAX {
            let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        status_code(&head).ok_or_else(|| {
            let shown: String = String::from_utf8_lossy(&head[..head.len().min(60)])
                .chars()
                .filter(|c| !c.is_control())
                .collect();
            format!("no HTTP status line (got {shown:?})")
        })
    };
    match tokio::time::timeout(budget, attempt).await {
        Ok(result) => result,
        Err(_) => Err(format!("no answer within {} ms", budget.as_millis())),
    }
}

/// A condition with what it found out so far.
enum Check {
    Port { host: String, port: u16 },
    Http { url: Url, status: Option<u16> },
    FileExists(PathBuf),
    FileContains(PathBuf, regex::bytes::Regex),
    Log(LogCheck),
    ProcessGone { pid: u32, start_time: Option<u64> },
    JobFinished(String),
    SessionExited(String),
}

struct LogCheck {
    dir: PathBuf,
    stream: Stream,
    regex: regex::bytes::Regex,
    /// The next offset to read.
    pos: u64,
    /// The end of what was read before, for a match across reads.
    carry: Vec<u8>,
    source: LogSource,
    /// `job <id>` or `session <id>`, for the details.
    what: String,
}

impl LogCheck {
    /// Reads what the log has after `pos`, at most a few MiB per look.
    fn look(&mut self) -> Result<Look, Error> {
        let mut read_now = 0usize;
        loop {
            let read =
                read_log(&self.dir, self.stream, Some(self.pos), LOG_CHUNK).map_err(|e| {
                    err(
                        ErrorKind::Io,
                        format!("reading the log of {}: {e}", self.what),
                    )
                })?;
            if read.offset > self.pos {
                // Rotated away meanwhile: what is gone was never seen.
                self.carry.clear();
            }
            let caught_up = read.offset + read.data.len() as u64 >= read.total;
            self.pos = read.offset + read.data.len() as u64;
            read_now += read.data.len();
            let mut window = std::mem::take(&mut self.carry);
            window.extend_from_slice(&read.data);
            if let Some(m) = self.regex.find(&window) {
                let text: String = String::from_utf8_lossy(m.as_bytes())
                    .chars()
                    .take(200)
                    .collect();
                return Ok(Look::met(format!(
                    "the log of {} matched {text:?}",
                    self.what
                )));
            }
            let keep = window.len().saturating_sub(LOG_CARRY);
            self.carry = window.split_off(keep);
            if caught_up || read.data.is_empty() || read_now >= 4 * LOG_CHUNK {
                return Ok(Look::not_yet(format!(
                    "the log of {} has no match up to offset {}",
                    self.what, self.pos
                )));
            }
        }
    }
}

fn file_tail_matches(path: &PathBuf, regex: &regex::bytes::Regex) -> Look {
    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => return Look::not_yet(format!("{}: {e}", path.display())),
    };
    let len = file.metadata().map_or(0, |m| m.len());
    let from = len.saturating_sub(FILE_TAIL);
    if file.seek(SeekFrom::Start(from)).is_err() {
        return Look::not_yet(format!("{}: cannot seek", path.display()));
    }
    let mut data = Vec::new();
    if let Err(e) = file.take(FILE_TAIL).read_to_end(&mut data) {
        return Look::not_yet(format!("{}: {e}", path.display()));
    }
    if regex.is_match(&data) {
        Look::met(format!("{} matches", path.display()))
    } else {
        Look::not_yet(format!("{} has no match", path.display()))
    }
}

struct Waiter {
    jobs: Arc<Jobs>,
    sessions: Arc<Sessions>,
}

impl Waiter {
    fn check(&self, condition: Condition) -> Result<Check, Error> {
        Ok(match condition {
            Condition::PortOpen { host, port } => {
                let host = host.unwrap_or_else(|| "127.0.0.1".into());
                let host = host
                    .strip_prefix('[')
                    .and_then(|h| h.strip_suffix(']'))
                    .unwrap_or(&host)
                    .to_string();
                if host.is_empty() || port == 0 {
                    return Err(invalid("PortOpen needs a host and a port above 0"));
                }
                Check::Port { host, port }
            }
            Condition::HttpStatus { url, status } => Check::Http {
                url: parse_url(&url)?,
                status,
            },
            Condition::FileExists { path } => Check::FileExists(resolve(&path)),
            Condition::FileContains { path, regex } => {
                Check::FileContains(resolve(&path), bytes_regex(&regex)?)
            }
            Condition::LogMatches {
                source,
                stream,
                regex,
                from_offset,
            } => {
                let regex = bytes_regex(&regex)?;
                let (dir, stream, what) = match &source {
                    LogSource::Job(id) => (self.jobs.log_dir(id)?, stream, format!("job {id}")),
                    LogSource::Session(id) => (
                        self.sessions.log_dir(id)?,
                        Stream::Stdout,
                        format!("session {id}"),
                    ),
                };
                let pos = match from_offset {
                    Some(offset) => offset,
                    None => {
                        read_log(&dir, stream, None, 0)
                            .map_err(|e| err(ErrorKind::Io, format!("reading the log: {e}")))?
                            .total
                    }
                };
                Check::Log(LogCheck {
                    dir,
                    stream,
                    regex,
                    pos,
                    carry: Vec::new(),
                    source,
                    what,
                })
            }
            Condition::ProcessGone { pid, start_time } => {
                if pid == 0 {
                    return Err(invalid("there is no process 0"));
                }
                Check::ProcessGone { pid, start_time }
            }
            Condition::JobFinished { job_id } => {
                self.jobs.info(&job_id)?;
                Check::JobFinished(job_id)
            }
            Condition::SessionExited { session_id } => {
                self.sessions.info(&session_id)?;
                Check::SessionExited(session_id)
            }
        })
    }

    /// One look at a condition that reads files, run off the async
    /// threads.
    fn look_blocking(&self, check: &mut Check) -> Result<Look, Error> {
        Ok(match check {
            Check::FileExists(path) => match std::fs::metadata(&*path) {
                Ok(_) => Look::met(format!("{} exists", path.display())),
                Err(e) => Look::not_yet(format!("{}: {e}", path.display())),
            },
            Check::FileContains(path, regex) => file_tail_matches(path, regex),
            Check::Log(log) => {
                let mut look = log.look()?;
                if !look.met {
                    // A finished job or an ended session writes no more.
                    let over = match &log.source {
                        LogSource::Job(id) => self.jobs.info(id).is_ok_and(|i| i.finished),
                        LogSource::Session(id) => self.sessions.info(id).is_ok_and(|i| i.finished),
                    };
                    if over {
                        // What it wrote last, then nothing more.
                        look = log.look()?;
                        look.settled = !look.met;
                        if look.settled {
                            look.detail = format!("{}; it has ended", look.detail);
                        }
                    }
                }
                look
            }
            Check::ProcessGone { pid, start_time } => {
                let gone = match start_time {
                    Some(start) => !procfs::is_same_process(*pid, *start),
                    None => procfs::start_time(*pid).is_none() || !alive(*pid),
                };
                if gone {
                    Look::met(format!("process {pid} is gone"))
                } else {
                    Look::not_yet(format!("process {pid} runs"))
                }
            }
            Check::JobFinished(id) => {
                let info = self.jobs.info(id)?;
                if info.finished {
                    Look::met(format!("job {id} finished: {:?}", info.state))
                } else {
                    Look::not_yet(format!("job {id} runs ({} processes)", info.processes))
                }
            }
            Check::SessionExited(id) => {
                let info = self.sessions.info(id)?;
                if info.state == JobState::Running {
                    Look::not_yet(format!("session {id} runs"))
                } else {
                    Look::met(format!("session {id} ended: {:?}", info.state))
                }
            }
            Check::Port { .. } | Check::Http { .. } => unreachable!("not a blocking check"),
        })
    }
}

/// Whether a process with this pid runs (and is not a zombie).
fn alive(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next().map(|st| st != "Z"))
            .unwrap_or(false)
    })
}

/// Waits for `spec`'s condition: `(met, elapsed_ms, detail)`.
///
/// # Errors
///
/// `InvalidArgument` for a bad spec, `NotFound` for an unknown job or
/// session; a condition that is only not met yet is never an error.
pub async fn wait(
    jobs: Arc<Jobs>,
    sessions: Arc<Sessions>,
    spec: WaitSpec,
) -> Result<(bool, u64, String), Error> {
    if spec.timeout_ms > MAX_TIMEOUT_MS {
        return Err(invalid(format!("timeout_ms is at most {MAX_TIMEOUT_MS}")));
    }
    let interval = spec.interval_ms.unwrap_or(DEFAULT_INTERVAL_MS);
    if interval < MIN_INTERVAL_MS {
        return Err(invalid(format!(
            "interval_ms is at least {MIN_INTERVAL_MS}"
        )));
    }
    let begun = Instant::now();
    let deadline = begun + Duration::from_millis(spec.timeout_ms);
    let waiter = Arc::new(Waiter { jobs, sessions });
    let w = Arc::clone(&waiter);
    let condition = spec.condition;
    let mut check = tokio::task::spawn_blocking(move || w.check(condition))
        .await
        .map_err(|e| err(ErrorKind::Internal, format!("a task failed: {e}")))??;
    let elapsed = || u64::try_from(begun.elapsed().as_millis()).unwrap_or(u64::MAX);
    loop {
        let budget = deadline
            .saturating_duration_since(Instant::now())
            .clamp(Duration::from_millis(MIN_INTERVAL_MS), TRY_TIMEOUT);
        let look = match &check {
            Check::Port { host, port } => match connect(host, *port, budget).await {
                Ok(_) => Look::met(format!("{host} port {port} accepts connections")),
                Err(e) => Look::not_yet(format!("{host} port {port}: {e}")),
            },
            Check::Http { url, status } => match http_status(url, budget).await {
                Ok(code) => {
                    let wanted = status.map_or((200..400).contains(&code), |s| s == code);
                    let detail = format!("http://{}{} answered {code}", url.authority, url.target);
                    if wanted {
                        Look::met(detail)
                    } else {
                        Look::not_yet(detail)
                    }
                }
                Err(e) => Look::not_yet(format!("http://{}{}: {e}", url.authority, url.target)),
            },
            _ => {
                let w = Arc::clone(&waiter);
                let (back, look) = tokio::task::spawn_blocking(move || {
                    let look = w.look_blocking(&mut check);
                    (check, look)
                })
                .await
                .map_err(|e| err(ErrorKind::Internal, format!("a task failed: {e}")))?;
                check = back;
                look?
            }
        };
        if look.met || look.settled || Instant::now() >= deadline {
            return Ok((look.met, elapsed(), look.detail));
        }
        let pause =
            Duration::from_millis(interval).min(deadline.saturating_duration_since(Instant::now()));
        tokio::time::sleep(pause).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        let u = parse_url("http://127.0.0.1:8080/health?x=1#frag").unwrap();
        assert_eq!(
            u,
            Url {
                host: "127.0.0.1".into(),
                port: 8080,
                authority: "127.0.0.1:8080".into(),
                target: "/health?x=1".into(),
            }
        );
        let u = parse_url("HTTP://[::1]/").unwrap();
        assert_eq!((u.host.as_str(), u.port), ("::1", 80));
        let u = parse_url("http://localhost?q").unwrap();
        assert_eq!(u.target, "/?q");
        for bad in [
            "https://example.com/",
            "ftp://x/",
            "http://",
            "http://u@h/",
            "http://h:0/",
            "http://h:99999/",
            "http://h/a b",
            "http://h/\r\nX: y",
            "http://[::1/",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
        assert!(
            parse_url("https://x/")
                .unwrap_err()
                .message
                .contains("PortOpen")
        );
    }

    #[test]
    fn status_lines() {
        assert_eq!(status_code(b"HTTP/1.1 200 OK\r\n"), Some(200));
        assert_eq!(status_code(b"HTTP/1.0 503\r\nx"), Some(503));
        assert_eq!(status_code(b"HTTP/2 404 Not Found"), Some(404));
        for garbage in [
            &b""[..],
            b"\xff\xfe",
            b"SSH-2.0-OpenSSH\r\n",
            b"HTTP/1.1 20 OK",
            b"HTTP/1.1 2000 OK",
            b"HTTP/1.1 abc",
            b"HTTP/1.1",
        ] {
            assert_eq!(status_code(garbage), None, "{garbage:?}");
        }
    }
}
