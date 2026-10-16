//! The hello, the marker, frames and concurrency against a real daemon.

#![allow(clippy::too_many_lines)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Env, Raw, exec, sh};
use ghostd_client::{ClientError, Connection, Options};
use ghostd_protocol::v1::{ClientFrame, Outcome, Request, Response, ServerFrame};
use ghostd_protocol::{MAX_FRAME, decode, encode_frame};

#[tokio::test]
async fn negotiation_against_the_daemon() {
    let env = Env::new();
    let refused = env
        .try_connect(Options {
            min: 2,
            max: 3,
            program_version: "future".into(),
        })
        .await
        .unwrap_err();
    let text = refused.to_string();
    assert!(matches!(refused, ClientError::Refused { .. }), "{text}");
    assert!(text.contains("1..=1") && text.contains("2..=3"), "{text}");
    assert!(text.contains("update ghostd"), "{text}");
    let c = env
        .try_connect(Options {
            min: 1,
            max: 5,
            program_version: "newer".into(),
        })
        .await
        .unwrap();
    assert_eq!(c.version(), 1);
    assert_eq!(c.server_version(), env!("CARGO_PKG_VERSION"));
    assert_eq!(c.call(Request::Ping).await.unwrap(), Response::Pong);
}

#[tokio::test]
async fn a_banner_before_the_marker_is_skipped() {
    let env = Env::new();
    let wrapper = env.tokio_cmd(
        "/bin/sh",
        &[
            "-c",
            "echo 'Welcome to the machine'; printf 'junk\\000\\377\\n'; exec \"$GHOSTD\" stdio",
        ],
    );
    let c = Connection::spawn_command(wrapper, Options::default())
        .await
        .unwrap();
    assert_eq!(c.call(Request::Ping).await.unwrap(), Response::Pong);
}

#[tokio::test]
async fn too_much_junk_fails_showing_it() {
    let env = Env::new();
    let wrapper = env.tokio_cmd(
        "/bin/sh",
        &[
            "-c",
            "head -c 1100000 /dev/zero | tr '\\000' 'x'; exec \"$GHOSTD\" stdio",
        ],
    );
    let e = Connection::spawn_command(wrapper, Options::default())
        .await
        .unwrap_err();
    let text = e.to_string();
    assert!(text.contains("no ghostd hello"), "{text}");
    assert!(text.contains("xxxxxxxxxx"), "{text}");
}

#[tokio::test]
async fn a_missing_binary_shows_the_shell_error() {
    let env = Env::new();
    let wrapper = env.tokio_cmd("/bin/sh", &["-c", "exec /nonexistent/ghostd stdio"]);
    let e = Connection::spawn_command(wrapper, Options::default())
        .await
        .unwrap_err();
    let text = e.to_string();
    assert!(text.contains("no ghostd hello"), "{text}");
    assert!(text.contains("/nonexistent/ghostd"), "{text}");
}

#[test]
fn an_oversized_length_is_refused() {
    let env = Env::new();
    let mut raw = Raw::connect(&env);
    let len = u32::try_from(MAX_FRAME + 1).unwrap();
    raw.send(&len.to_be_bytes());
    let frame = raw.frame().expect("a protocol error");
    let ServerFrame::ProtocolError { message } = decode::<ServerFrame>(&frame).unwrap() else {
        panic!("not a protocol error");
    };
    assert!(message.contains("exceeds"), "{message}");
    assert!(raw.frame().is_none(), "the connection stays open");
}

#[test]
fn garbage_after_the_hello_closes() {
    let env = Env::new();
    let mut raw = Raw::connect(&env);
    // A valid request first, answered.
    raw.send(
        &encode_frame(&ClientFrame::Request {
            id: 1,
            body: Request::Ping,
        })
        .unwrap(),
    );
    let answer: ServerFrame = decode(&raw.frame().unwrap()).unwrap();
    assert_eq!(
        answer,
        ServerFrame::Response {
            id: 1,
            result: Ok(Response::Pong)
        }
    );
    let mut garbage = 5u32.to_be_bytes().to_vec();
    garbage.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff]);
    raw.send(&garbage);
    let frame = raw.frame().expect("a protocol error");
    assert!(matches!(
        decode::<ServerFrame>(&frame).unwrap(),
        ServerFrame::ProtocolError { .. }
    ));
    assert!(raw.frame().is_none());
}

#[tokio::test]
async fn two_relays_start_one_daemon() {
    let env = Env::new();
    let (a, b) = tokio::join!(env.connect(), env.connect());
    assert_eq!(a.call(Request::Ping).await.unwrap(), Response::Pong);
    assert_eq!(b.call(Request::Ping).await.unwrap(), Response::Pong);
    // The losing daemon exits at once.
    env.wait_for("one daemon", || env.processes("daemon").len() == 1);
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(env.processes("daemon").len(), 1);
    assert_eq!(env.processes("worker").len(), 1);
}

#[tokio::test]
async fn fifty_requests_at_once_answered_out_of_order() {
    let env = Env::new();
    let c = Arc::new(env.connect().await);
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));
    let mut tasks = Vec::new();
    for i in 0..50u32 {
        let c = Arc::clone(&c);
        let order = Arc::clone(&order);
        tasks.push(tokio::spawn(async move {
            // The first requests sleep longest.
            let delay = f64::from(50 - i) * 0.02;
            let r = exec(&c, sh(&format!("sleep {delay}; echo {i}"))).await;
            assert_eq!(r.outcome, Outcome::Exited { code: 0 });
            assert_eq!(r.stdout.data, format!("{i}\n").into_bytes());
            order.lock().unwrap().push(i);
        }));
    }
    for t in tasks {
        t.await.unwrap();
    }
    let order = order.lock().unwrap().clone();
    assert_eq!(order.len(), 50);
    assert_ne!(order, (0..50).collect::<Vec<_>>(), "answers came in order");
}

#[test]
fn status_reports_the_daemon() {
    let env = Env::new();
    let out = env.cmd(&["status"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["running"], false);
    let raw = Raw::connect(&env);
    let out = env.cmd(&["status"]).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["running"], true);
    assert_eq!(v["daemon_version"], env!("CARGO_PKG_VERSION"));
    drop(raw);
    let out = env.cmd(&["stop"]).output().unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["stopped"], true);
    assert!(env.processes("daemon").is_empty());
}

#[tokio::test]
async fn a_daemon_whose_socket_is_removed_stops() {
    let env = Env::new();
    let c = env.connect().await;
    assert_eq!(c.call(Request::Ping).await.unwrap(), Response::Pong);
    drop(c);
    let daemon = env.processes("daemon");
    assert_eq!(daemon.len(), 1);
    std::fs::remove_file(env.runtime.join("ghostd.sock")).unwrap();
    let until = std::time::Instant::now() + Duration::from_secs(20);
    while common::alive(daemon[0]) {
        assert!(std::time::Instant::now() < until, "the daemon lingers");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The next relay starts a fresh one.
    let c = env.connect().await;
    assert_eq!(c.call(Request::Ping).await.unwrap(), Response::Pong);
}

#[tokio::test]
async fn a_cancelled_call_leaves_the_connection_usable() {
    let env = Env::new();
    let c = env.connect().await;
    // An 8 MiB write cut off by a timeout while its frame is being sent.
    let big = Request::FileWrite {
        path: b"big".to_vec(),
        data: vec![7; 8 * 1024 * 1024],
        mode: None,
        create_dirs: false,
    };
    let cut = tokio::time::timeout(Duration::from_millis(1), c.call(big)).await;
    assert!(cut.is_err(), "the call finished within 1 ms: {cut:?}");
    let answer = tokio::time::timeout(Duration::from_secs(10), c.call(Request::Ping))
        .await
        .expect("the next call was never answered");
    assert_eq!(answer.unwrap(), Response::Pong);
    assert_eq!(c.call(Request::Ping).await.unwrap(), Response::Pong);
}
