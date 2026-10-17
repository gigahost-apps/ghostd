//! Sessions: persistent PTYs read as screens, typed into, surviving the
//! worker's and the daemon's death, and stopped whole.

#![allow(clippy::too_many_lines)]

mod common;

use std::path::Path;
use std::time::Duration;

use common::Env;
use ghostd_client::{ClientError, Connection};
use ghostd_protocol::v1;
use ghostd_protocol::v2::{
    ErrorKind, Key, NamedKey, Request, Response, Screen, SessionEnd, SessionInfo, SessionSpec,
    Until,
};

/// A spec's `argv`.
#[allow(clippy::unnecessary_wraps)]
fn argv(args: &[&str]) -> Option<Vec<Vec<u8>>> {
    Some(args.iter().map(|a| a.as_bytes().to_vec()).collect())
}

fn shell() -> SessionSpec {
    SessionSpec {
        argv: argv(&["/bin/sh"]),
        env: vec![(b"PS1".to_vec(), b"$ ".to_vec())],
        ..SessionSpec::default()
    }
}

async fn start(c: &Connection, spec: SessionSpec) -> String {
    match c.call(Request::SessionStart(spec)).await.unwrap() {
        Response::SessionStarted { session_id } => session_id,
        other => panic!("unexpected {other:?}"),
    }
}

async fn send(c: &Connection, id: &str, input: Vec<Key>) {
    let answer = c
        .call(Request::SessionSend {
            session_id: id.into(),
            input,
        })
        .await
        .unwrap();
    assert_eq!(answer, Response::DONE);
}

async fn line(c: &Connection, id: &str, text: &str) {
    send(
        c,
        id,
        vec![Key::Text(text.into()), Key::Named(NamedKey::Enter)],
    )
    .await;
}

async fn read(c: &Connection, id: &str, until: Option<Until>, wait_ms: u64) -> Screen {
    match c
        .call(Request::SessionRead {
            session_id: id.into(),
            wait_ms,
            until,
            scrollback_lines: 0,
        })
        .await
        .unwrap()
    {
        Response::Screen(screen) => screen,
        other => panic!("unexpected {other:?}"),
    }
}

/// Reads until `pattern` matches the screen, failing the test after 10 s.
async fn until_matches(c: &Connection, id: &str, pattern: &str) -> Screen {
    let screen = read(c, id, Some(Until::Matches(pattern.into())), 10_000).await;
    assert_eq!(
        screen.until_met,
        Some(true),
        "no {pattern:?} on the screen:\n{}",
        screen.text
    );
    screen
}

async fn info(c: &Connection, id: &str) -> SessionInfo {
    let Response::Sessions(all) = c.call(Request::SessionList).await.unwrap() else {
        panic!("no list");
    };
    all.into_iter()
        .find(|s| s.session_id == id)
        .expect("the session is listed")
}

/// The processes below the session's shim, by name.
fn below_shim(env: &Env, id: &str, name: &str) -> Vec<u32> {
    let dir = env.state.join("sessions").join(id);
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("status.json")).unwrap()).unwrap();
    let shim = u32::try_from(status["shim_pid"].as_u64().unwrap()).unwrap();
    descendants(shim)
        .into_iter()
        .filter(|&pid| {
            std::fs::read_to_string(format!("/proc/{pid}/comm")).is_ok_and(|c| c.trim() == name)
        })
        .collect()
}

fn descendants(root: u32) -> Vec<u32> {
    let mut parents = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        let Some((_, rest)) = stat.rsplit_once(')') else {
            continue;
        };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if fields.first() == Some(&"Z") {
            continue;
        }
        if let Some(ppid) = fields.get(1).and_then(|p| p.parse::<u32>().ok()) {
            parents.push((pid, ppid));
        }
    }
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(parent) = stack.pop() {
        for &(pid, ppid) in &parents {
            if ppid == parent && !out.contains(&pid) {
                out.push(pid);
                stack.push(pid);
            }
        }
    }
    out
}

#[tokio::test]
async fn a_shell_echoes_and_ctrl_c_interrupts() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let id = start(&c, shell()).await;
    assert!(id.starts_with('s') && id.len() == 17, "{id}");
    until_matches(&c, &id, r"\$").await;
    line(&c, &id, "echo hi").await;
    let screen = until_matches(&c, &id, "(?m)^hi$").await;
    assert_eq!((screen.cols, screen.rows), (120, 40));
    assert!(screen.exited.is_none());
    assert!(!screen.alternate_screen);

    line(&c, &id, "sleep 100").await;
    env.wait_for("the sleep", || !below_shim(&env, &id, "sleep").is_empty());
    send(&c, &id, vec![Key::Named(NamedKey::Ctrl('c'))]).await;
    // A sleep not interrupted would take the next line as its input.
    line(&c, &id, "echo done$((1+1))").await;
    until_matches(&c, &id, "(?m)^done2$").await;
    assert!(below_shim(&env, &id, "sleep").is_empty());

    // Changed waits for output after the number it is given.
    let now = read(&c, &id, None, 0).await;
    let quiet = read(
        &c,
        &id,
        Some(Until::Changed {
            since: Some(now.changed_since),
        }),
        300,
    )
    .await;
    assert_eq!(quiet.until_met, Some(false));
    line(&c, &id, "echo more").await;
    let changed = read(
        &c,
        &id,
        Some(Until::Changed {
            since: Some(now.changed_since),
        }),
        10_000,
    )
    .await;
    assert_eq!(changed.until_met, Some(true));
    assert!(changed.changed_since > now.changed_since);

    // The raw output is kept as a log.
    let Response::V1(v1::Response::LogSlice(slice)) = c
        .call(Request::SessionLogRead {
            session_id: id.clone(),
            offset: Some(0),
            max_len: 1 << 20,
        })
        .await
        .unwrap()
    else {
        panic!("no log slice");
    };
    assert!(
        String::from_utf8_lossy(&slice.data).contains("done2"),
        "{slice:?}"
    );
    assert!(!slice.ended);
}

#[tokio::test]
async fn full_screen_programs_and_application_keys() {
    let env = Env::new();
    let c = env.connect_v2().await;
    // A program that switches to the alternate screen.
    let id = start(
        &c,
        SessionSpec {
            argv: argv(&[
                "/bin/sh",
                "-c",
                r"printf '\033[?1049h\033[2J\033[Hfull screen'; sleep 30",
            ]),
            ..SessionSpec::default()
        },
    )
    .await;
    let screen = until_matches(&c, &id, "full screen").await;
    assert!(screen.alternate_screen);
    if Path::new("/usr/bin/less").exists() {
        std::fs::write(env.home.join("text"), "line one\nline two\n").unwrap();
        let less = start(
            &c,
            SessionSpec {
                argv: argv(&["/usr/bin/less", "text"]),
                ..SessionSpec::default()
            },
        )
        .await;
        let screen = until_matches(&c, &less, "line two").await;
        assert!(screen.alternate_screen, "{}", screen.text);
        send(&c, &less, vec![Key::Text("q".into())]).await;
        let end = read(&c, &less, Some(Until::Exited), 10_000).await;
        assert_eq!(end.exited, Some(SessionEnd::Exited { code: 0 }));
    }
    // The arrows in application cursor-key mode are sent as ESC O x.
    let keys = start(
        &c,
        SessionSpec {
            argv: argv(&[
                "/bin/sh",
                "-c",
                r"stty raw -echo; printf '\033[?1hready\r\n'; head -c 6 | od -An -c; sleep 30",
            ]),
            ..SessionSpec::default()
        },
    )
    .await;
    until_matches(&c, &keys, "ready").await;
    send(
        &c,
        &keys,
        vec![Key::Named(NamedKey::Up), Key::Named(NamedKey::Left)],
    )
    .await;
    until_matches(&c, &keys, r"033\s+O\s+A\s+033\s+O\s+D").await;
}

#[tokio::test]
async fn a_resize_reaches_the_program() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let id = start(
        &c,
        SessionSpec {
            cols: Some(80),
            rows: Some(24),
            ..shell()
        },
    )
    .await;
    until_matches(&c, &id, r"\$").await;
    line(&c, &id, "stty size").await;
    until_matches(&c, &id, "(?m)^24 80$").await;
    let answer = c
        .call(Request::SessionResize {
            session_id: id.clone(),
            cols: 100,
            rows: 30,
        })
        .await
        .unwrap();
    assert_eq!(answer, Response::DONE);
    line(&c, &id, "stty size").await;
    let screen = until_matches(&c, &id, "(?m)^30 100$").await;
    assert_eq!((screen.cols, screen.rows), (100, 30));
    assert_eq!(
        (info(&c, &id).await.cols, info(&c, &id).await.rows),
        (100, 30)
    );
    let e = c
        .call(Request::SessionResize {
            session_id: id.clone(),
            cols: 5000,
            rows: 30,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::InvalidArgument),
        "{e}"
    );
}

#[tokio::test]
async fn a_session_survives_the_worker_and_the_daemon() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let id = start(&c, shell()).await;
    line(&c, &id, "echo one").await;
    until_matches(&c, &id, "(?m)^one$").await;
    drop(c);
    // The worker, then the daemon, killed.
    let worker = env.processes("worker")[0];
    common::signal(worker, 9);
    common::wait_gone(worker);
    env.wait_for("a new worker", || {
        env.processes("worker").iter().any(|&w| w != worker)
    });
    let c = env.connect_v2().await;
    until_matches(&c, &id, "(?m)^one$").await;
    drop(c);
    let daemon = env.processes("daemon")[0];
    common::signal(daemon, 9);
    common::wait_gone(daemon);
    env.wait_for("no worker", || env.processes("worker").is_empty());
    let c = env.connect_v2().await;
    let screen = read(&c, &id, None, 0).await;
    assert!(screen.text.contains("one"), "{}", screen.text);
    line(&c, &id, "echo two").await;
    until_matches(&c, &id, "(?m)^two$").await;
    assert_eq!(info(&c, &id).await.state, v1::JobState::Running);
}

#[tokio::test]
async fn close_stops_the_whole_tree_and_keeps_the_final_screen() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let id = start(&c, shell()).await;
    line(&c, &id, "sleep 1000 & sleep 1001 & echo started").await;
    until_matches(&c, &id, "(?m)^started$").await;
    env.wait_for("two sleeps", || below_shim(&env, &id, "sleep").len() == 2);
    let sleeps = below_shim(&env, &id, "sleep");
    let Response::Session(closed) = c
        .call(Request::SessionClose {
            session_id: id.clone(),
            grace_ms: Some(500),
        })
        .await
        .unwrap()
    else {
        panic!("no session info");
    };
    assert!(closed.finished, "{closed:?}");
    for pid in sleeps {
        assert!(!common::alive(pid), "sleep {pid} outlived the close");
    }
    // The final screen stays readable.
    let screen = read(&c, &id, Some(Until::Exited), 1000).await;
    assert!(screen.text.contains("started"), "{}", screen.text);
    assert!(screen.exited.is_some());
    assert_eq!(screen.until_met, Some(true));
    // Input is refused once it has ended.
    let e = c
        .call(Request::SessionSend {
            session_id: id.clone(),
            input: vec![Key::Text("x".into())],
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::Conflict),
        "{e}"
    );
}

#[tokio::test]
async fn a_program_that_exits_ends_its_session() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let id = start(
        &c,
        SessionSpec {
            argv: argv(&["/bin/sh", "-c", "sleep 1000 & echo bye; exit 3"]),
            name: Some("short".into()),
            ..SessionSpec::default()
        },
    )
    .await;
    let screen = read(&c, &id, Some(Until::Exited), 10_000).await;
    assert_eq!(screen.exited, Some(SessionEnd::Exited { code: 3 }));
    assert!(screen.text.contains("bye"), "{}", screen.text);
    // What it left in its session is stopped, as after an Exec.
    env.wait_for("the session to finish", || {
        std::fs::read(env.state.join("sessions").join(&id).join("status.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .is_some_and(|v| v["tree_gone"] == true)
    });
    let session = info(&c, &id).await;
    assert!(session.finished);
    assert_eq!(session.state, v1::JobState::Exited { code: 3 });
    assert_eq!(session.name.as_deref(), Some("short"));
    // From the final screen, once the shim is gone.
    let kept = read(&c, &id, Some(Until::Matches("b.e".into())), 0).await;
    assert_eq!(kept.until_met, Some(true));
    assert!(kept.text.contains("bye"));
    assert!(env.named("sleep").is_empty(), "a leftover sleep runs");
}

#[tokio::test]
async fn a_client_chosen_id_is_retry_safe() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let spec = SessionSpec {
        session_id: Some("s00000000000000aa".into()),
        ..shell()
    };
    let first = start(&c, spec.clone()).await;
    let again = start(&c, spec.clone()).await;
    assert_eq!(first, "s00000000000000aa");
    assert_eq!(again, first);
    assert_eq!(env.processes("shim").len(), 1);
    let other = SessionSpec {
        argv: argv(&["/bin/sh", "-c", "true"]),
        ..spec
    };
    let e = c.call(Request::SessionStart(other)).await.unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::Conflict),
        "{e}"
    );
    let e = c
        .call(Request::SessionStart(SessionSpec {
            session_id: Some("j00000000000000aa".into()),
            ..shell()
        }))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::InvalidArgument),
        "{e}"
    );
    // A program that does not exist.
    let e = c
        .call(Request::SessionStart(SessionSpec {
            argv: argv(&["/nonexistent/program"]),
            ..SessionSpec::default()
        }))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::NotFound
            && r.message.contains("/nonexistent/program")),
        "{e}"
    );
}

#[tokio::test]
async fn at_most_32_sessions_live() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let spec = || SessionSpec {
        argv: argv(&["/bin/sh", "-c", "sleep 60"]),
        ..SessionSpec::default()
    };
    let mut ids = Vec::new();
    for _ in 0..32 {
        ids.push(start(&c, spec()).await);
    }
    let e = c.call(Request::SessionStart(spec())).await.unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::Busy),
        "{e}"
    );
    c.call(Request::SessionClose {
        session_id: ids[0].clone(),
        grace_ms: Some(100),
    })
    .await
    .unwrap();
    start(&c, spec()).await;
    for id in &ids[1..] {
        c.call(Request::SessionClose {
            session_id: id.clone(),
            grace_ms: Some(100),
        })
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(10)).await;
}

#[tokio::test]
async fn a_flood_nobody_reads_never_blocks_and_scrollback_is_kept() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let flood = start(
        &c,
        SessionSpec {
            argv: argv(&[
                "/bin/sh",
                "-c",
                r"head -c 3000000 /dev/zero | tr '\000' x; echo; echo END",
            ]),
            ..SessionSpec::default()
        },
    )
    .await;
    let lines = start(
        &c,
        SessionSpec {
            argv: argv(&["/bin/sh", "-c", "seq 1 100; sleep 30"]),
            ..SessionSpec::default()
        },
    )
    .await;
    // Nobody reads the flood while it runs: it still ends.
    let dir = env.state.join("sessions").join(&flood);
    let until = std::time::Instant::now() + Duration::from_mins(1);
    loop {
        let done = std::fs::read(dir.join("status.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .is_some_and(|v| v["tree_gone"] == true);
        if done {
            break;
        }
        assert!(std::time::Instant::now() < until, "the flood never ended");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let screen = read(&c, &flood, None, 0).await;
    assert!(screen.text.contains("END"), "{}", screen.text);
    // The terminal sends a newline as CR LF.
    assert_eq!(info(&c, &flood).await.output_total, 3_000_000 + 2 + 5);

    let screen = until_matches(&c, &lines, "(?m)^100$").await;
    assert!(screen.text.starts_with("62\n"), "{}", screen.text);
    let Response::Screen(with) = c
        .call(Request::SessionRead {
            session_id: lines.clone(),
            wait_ms: 0,
            until: None,
            scrollback_lines: 50,
        })
        .await
        .unwrap()
    else {
        panic!("no screen");
    };
    let back: Vec<String> = (12..=61).map(|n| n.to_string()).collect();
    assert_eq!(with.scrollback.as_deref(), Some(back.join("\n").as_str()));
    let e = c
        .call(Request::SessionRead {
            session_id: lines,
            wait_ms: 0,
            until: None,
            scrollback_lines: 1001,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::InvalidArgument),
        "{e}"
    );
}
