//! Waits: each condition met, and timed out.

#![allow(clippy::too_many_lines)]

mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::time::{Duration, Instant};

use common::{Env, sh, start};
use ghostd_client::{ClientError, Connection};
use ghostd_protocol::v2::{
    Condition, ErrorKind, LogSource, Request, Response, SessionSpec, Stream, WaitSpec,
};

async fn wait(c: &Connection, condition: Condition, timeout_ms: u64) -> (bool, u64, String) {
    match c
        .call(Request::Wait(WaitSpec {
            condition,
            timeout_ms,
            interval_ms: Some(50),
        }))
        .await
        .unwrap()
    {
        Response::Waited {
            met,
            elapsed_ms,
            detail,
        } => (met, elapsed_ms, detail),
        other => panic!("unexpected {other:?}"),
    }
}

async fn refused(c: &Connection, condition: Condition) -> (ErrorKind, String) {
    match c
        .call(Request::Wait(WaitSpec {
            condition,
            timeout_ms: 1000,
            interval_ms: None,
        }))
        .await
    {
        Err(ClientError::Remote(e)) => (e.kind, e.message),
        other => panic!("not refused: {other:?}"),
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

#[tokio::test]
async fn a_port_opens() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let port = free_port();
    let (met, elapsed, detail) = wait(&c, Condition::PortOpen { host: None, port }, 300).await;
    assert!(!met, "{detail}");
    assert!(elapsed >= 300, "{elapsed}");
    let listener = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
        let _ = l.accept();
    });
    let (met, _, detail) = wait(&c, Condition::PortOpen { host: None, port }, 10_000).await;
    assert!(met, "{detail}");
    listener.join().unwrap();
}

/// Answers `first` once, then `then` to every later request.
fn http_server(first: u16, then: u16) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for code in std::iter::once(first).chain(std::iter::repeat(then)) {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut request = Vec::new();
            let mut buf = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&buf[..n]),
                }
            }
            assert!(
                request.starts_with(b"GET /health HTTP/1.1\r\n"),
                "{request:?}"
            );
            let _ = write!(stream, "HTTP/1.1 {code} X\r\nContent-Length: 0\r\n\r\n");
        }
    });
    port
}

#[tokio::test]
async fn a_url_answers() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let port = http_server(200, 503);
    let url = format!("http://127.0.0.1:{port}/health");
    let (met, _, detail) = wait(
        &c,
        Condition::HttpStatus {
            url: url.clone(),
            status: None,
        },
        5000,
    )
    .await;
    assert!(met, "{detail}");
    assert!(detail.contains("200"), "{detail}");
    // Then only 503s: a wait for 200 times out, one for 503 is met.
    let (met, _, detail) = wait(
        &c,
        Condition::HttpStatus {
            url: url.clone(),
            status: Some(503),
        },
        5000,
    )
    .await;
    assert!(met, "{detail}");
    let (met, _, detail) = wait(
        &c,
        Condition::HttpStatus {
            url,
            status: Some(200),
        },
        400,
    )
    .await;
    assert!(!met, "{detail}");
    assert!(detail.contains("503"), "{detail}");
    // Something that is no HTTP server.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let junk = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            let _ = s.write_all(b"SSH-2.0-junk\r\n\xff\xfe");
        }
    });
    let (met, _, detail) = wait(
        &c,
        Condition::HttpStatus {
            url: format!("http://127.0.0.1:{port}/"),
            status: None,
        },
        300,
    )
    .await;
    assert!(!met, "{detail}");
    junk.join().unwrap();
    // TLS is refused, pointing at the alternatives.
    let (kind, message) = refused(
        &c,
        Condition::HttpStatus {
            url: "https://127.0.0.1/".into(),
            status: None,
        },
    )
    .await;
    assert_eq!(kind, ErrorKind::InvalidArgument);
    assert!(message.contains("PortOpen"), "{message}");
}

#[tokio::test]
async fn a_file_appears_and_fills() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let (met, _, _) = wait(
        &c,
        Condition::FileExists {
            path: b"later".to_vec(),
        },
        200,
    )
    .await;
    assert!(!met);
    let home = env.home.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(home.join("later"), "starting\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(home.join("later"))
            .unwrap();
        f.write_all(b"server ready on 8080\n").unwrap();
    });
    let (met, _, detail) = wait(
        &c,
        Condition::FileExists {
            path: b"later".to_vec(),
        },
        10_000,
    )
    .await;
    assert!(met, "{detail}");
    let (met, _, detail) = wait(
        &c,
        Condition::FileContains {
            path: b"later".to_vec(),
            regex: r"ready on \d+".into(),
        },
        10_000,
    )
    .await;
    assert!(met, "{detail}");
    writer.join().unwrap();
    let (met, _, _) = wait(
        &c,
        Condition::FileContains {
            path: b"later".to_vec(),
            regex: "never".into(),
        },
        200,
    )
    .await;
    assert!(!met);
    let (kind, _) = refused(
        &c,
        Condition::FileContains {
            path: b"later".to_vec(),
            regex: "(".into(),
        },
    )
    .await;
    assert_eq!(kind, ErrorKind::InvalidArgument);
}

#[tokio::test]
async fn a_log_matches_and_jobs_and_processes_end() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let job = start(
        &c,
        sh("echo early; sleep 0.5; echo listening on 3000 >&2; sleep 0.5"),
    )
    .await;
    let (met, _, detail) = wait(
        &c,
        Condition::LogMatches {
            source: LogSource::Job(job.clone()),
            stream: Stream::Stderr,
            regex: r"listening on \d+".into(),
            from_offset: None,
        },
        10_000,
    )
    .await;
    assert!(met, "{detail}");
    // Output written before the wait began does not count, unless asked.
    let (met, _, _) = wait(
        &c,
        Condition::LogMatches {
            source: LogSource::Job(job.clone()),
            stream: Stream::Stdout,
            regex: "early".into(),
            from_offset: None,
        },
        100,
    )
    .await;
    assert!(!met);
    let (met, _, _) = wait(
        &c,
        Condition::LogMatches {
            source: LogSource::Job(job.clone()),
            stream: Stream::Stdout,
            regex: "early".into(),
            from_offset: Some(0),
        },
        1000,
    )
    .await;
    assert!(met);
    let (met, _, detail) = wait(
        &c,
        Condition::JobFinished {
            job_id: job.clone(),
        },
        10_000,
    )
    .await;
    assert!(met, "{detail}");
    // A finished job writes no more: a wait on its log ends at once.
    let begun = Instant::now();
    let (met, _, detail) = wait(
        &c,
        Condition::LogMatches {
            source: LogSource::Job(job),
            stream: Stream::Stdout,
            regex: "never".into(),
            from_offset: Some(0),
        },
        10_000,
    )
    .await;
    assert!(!met);
    assert!(detail.contains("ended"), "{detail}");
    assert!(begun.elapsed() < Duration::from_secs(5));
    let (kind, _) = refused(
        &c,
        Condition::JobFinished {
            job_id: "j0000000000000000".into(),
        },
    )
    .await;
    assert_eq!(kind, ErrorKind::NotFound);

    // A process gone, and one that is not.
    let mut short = std::process::Command::new("sleep")
        .arg("0.3")
        .spawn()
        .unwrap();
    let mut long = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let (met, _, detail) = wait(
        &c,
        Condition::ProcessGone {
            pid: short.id(),
            start_time: None,
        },
        10_000,
    )
    .await;
    assert!(met, "{detail}");
    let (met, _, _) = wait(
        &c,
        Condition::ProcessGone {
            pid: long.id(),
            start_time: None,
        },
        200,
    )
    .await;
    assert!(!met);
    // A start time that is not the process's: another process took the pid.
    let (met, _, _) = wait(
        &c,
        Condition::ProcessGone {
            pid: long.id(),
            start_time: Some(1),
        },
        1000,
    )
    .await;
    assert!(met);
    long.kill().unwrap();
    let _ = long.wait();
    let _ = short.wait();

    // A session's program exiting, and its output.
    let Response::SessionStarted { session_id } = c
        .call(Request::SessionStart(SessionSpec {
            argv: Some(vec![
                b"/bin/sh".to_vec(),
                b"-c".to_vec(),
                b"sleep 0.3; echo session says hi; sleep 0.3".to_vec(),
            ]),
            ..SessionSpec::default()
        }))
        .await
        .unwrap()
    else {
        panic!("no session");
    };
    let (met, _, detail) = wait(
        &c,
        Condition::LogMatches {
            source: LogSource::Session(session_id.clone()),
            stream: Stream::Stdout,
            regex: "says hi".into(),
            from_offset: None,
        },
        10_000,
    )
    .await;
    assert!(met, "{detail}");
    let (met, _, detail) = wait(&c, Condition::SessionExited { session_id }, 10_000).await;
    assert!(met, "{detail}");
}

#[tokio::test]
async fn bounds_are_checked() {
    let env = Env::new();
    let c = env.connect_v2().await;
    for spec in [
        WaitSpec {
            condition: Condition::PortOpen {
                host: None,
                port: 1,
            },
            timeout_ms: 300_001,
            interval_ms: None,
        },
        WaitSpec {
            condition: Condition::PortOpen {
                host: None,
                port: 1,
            },
            timeout_ms: 100,
            interval_ms: Some(10),
        },
    ] {
        let e = c.call(Request::Wait(spec)).await.unwrap_err();
        assert!(
            matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::InvalidArgument),
            "{e}"
        );
    }
}
