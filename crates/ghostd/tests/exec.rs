//! Exec: bytes in, bytes out, nothing parsed by a shell.

#![allow(clippy::too_many_lines)]

mod common;

use common::{Env, argv, exec, sh, wait_gone, wait_job};
use ghostd_protocol::v1::{ExecSpec, JobState, Outcome, Program, Request, Response, Stream};

fn hostile() -> Vec<Vec<u8>> {
    vec![
        b"'".to_vec(),
        b"\"".to_vec(),
        b"$HOME".to_vec(),
        b"*".to_vec(),
        b";".to_vec(),
        b"a b".to_vec(),
        b"line\nbreak".to_vec(),
        Vec::new(),
        vec![0xff, 0xfe, b'x'],
        b"`id` $(id) \\".to_vec(),
    ]
}

/// Prints each argument followed by a NUL.
const PRINT_ARGS: &[u8] = b"for a; do printf '%s' \"$a\"; printf '\\000'; done";

fn print_args(args: &[Vec<u8>]) -> ExecSpec {
    let mut v = vec![
        b"/bin/sh".to_vec(),
        b"-c".to_vec(),
        PRINT_ARGS.to_vec(),
        b"sh".to_vec(),
    ];
    v.extend(args.iter().cloned());
    ExecSpec {
        program: Program::Argv(v),
        ..ExecSpec::default()
    }
}

fn nul_joined(args: &[Vec<u8>]) -> Vec<u8> {
    args.iter()
        .flat_map(|a| a.iter().copied().chain(std::iter::once(0)))
        .collect()
}

#[tokio::test]
async fn argv_reaches_the_program_byte_for_byte() {
    let env = Env::new();
    let c = env.connect().await;
    let r = exec(&c, print_args(&hostile())).await;
    assert_eq!(r.outcome, Outcome::Exited { code: 0 });
    assert_eq!(r.stdout.data, nul_joined(&hostile()));
    // Through the login shell too: as positional parameters.
    let mut spec = print_args(&hostile());
    spec.login = true;
    let r = exec(&c, spec).await;
    assert_eq!(r.outcome, Outcome::Exited { code: 0 }, "{r:?}");
    assert_eq!(r.stdout.data, nul_joined(&hostile()));
}

#[tokio::test]
async fn scripts() {
    let env = Env::new();
    let c = env.connect().await;
    let body = b"#!/bin/sh\necho \"it's \\\"quoted\\\"\" \"$1\" \"$#\"\n".to_vec();
    let r = exec(
        &c,
        ExecSpec {
            program: Program::Script {
                body,
                interpreter: None,
                args: vec![b"a b".to_vec()],
            },
            ..ExecSpec::default()
        },
    )
    .await;
    assert_eq!(r.outcome, Outcome::Exited { code: 0 }, "{r:?}");
    assert_eq!(r.stdout.data, b"it's \"quoted\" a b 1\n");
    // No shebang: /bin/sh. An interpreter given: it.
    let r = exec(
        &c,
        ExecSpec {
            program: Program::Script {
                body: b"echo plain \"$1\"".to_vec(),
                interpreter: None,
                args: vec![b"x".to_vec()],
            },
            ..ExecSpec::default()
        },
    )
    .await;
    assert_eq!(r.stdout.data, b"plain x\n");
    let r = exec(
        &c,
        ExecSpec {
            program: Program::Script {
                body: b"line one\nline two\n".to_vec(),
                interpreter: Some(vec![b"/bin/cat".to_vec()]),
                args: Vec::new(),
            },
            ..ExecSpec::default()
        },
    )
    .await;
    assert_eq!(r.stdout.data, b"line one\nline two\n");
}

#[tokio::test]
async fn stdin_env_and_cwd() {
    let env = Env::new();
    std::fs::create_dir(env.home.join("sub dir")).unwrap();
    let c = env.connect().await;
    let r = exec(
        &c,
        ExecSpec {
            program: argv(&[b"cat"]),
            stdin: Some(b"in\0put\xff".to_vec()),
            ..ExecSpec::default()
        },
    )
    .await;
    assert_eq!(r.stdout.data, b"in\0put\xff");
    let mut spec = sh("printf '%s|%s' \"$FOO\" \"${HOME-unset}\"");
    spec.env = vec![(b"FOO".to_vec(), b"b a r".to_vec())];
    spec.env_remove = vec![b"HOME".to_vec()];
    assert_eq!(exec(&c, spec).await.stdout.data, b"b a r|unset");
    let mut spec = ExecSpec {
        program: argv(&[b"/usr/bin/env"]),
        ..ExecSpec::default()
    };
    spec.env_clear = true;
    spec.env = vec![(b"ONLY".to_vec(), b"1".to_vec())];
    assert_eq!(exec(&c, spec).await.stdout.data, b"ONLY=1\n");
    let mut spec = argv_spec(&[b"pwd"]);
    spec.cwd = Some(b"sub dir".to_vec());
    let expected = format!("{}\n", env.home.join("sub dir").display());
    assert_eq!(exec(&c, spec).await.stdout.data, expected.as_bytes());
    let spec = argv_spec(&[b"pwd"]);
    let expected = format!("{}\n", env.home.display());
    assert_eq!(exec(&c, spec).await.stdout.data, expected.as_bytes());
}

fn argv_spec(args: &[&[u8]]) -> ExecSpec {
    ExecSpec {
        program: argv(args),
        ..ExecSpec::default()
    }
}

#[tokio::test]
async fn exit_codes_signals_and_failures() {
    let env = Env::new();
    let c = env.connect().await;
    let r = exec(&c, sh("echo out; echo err >&2; exit 7")).await;
    assert_eq!(r.outcome, Outcome::Exited { code: 7 });
    assert_eq!(r.stdout.data, b"out\n");
    assert_eq!(r.stderr.data, b"err\n");
    assert_eq!(
        exec(&c, sh("kill -9 $$")).await.outcome,
        Outcome::Signaled { signal: 9 }
    );
    let r = exec(&c, argv_spec(&[b"/nonexistent/program"])).await;
    let Outcome::FailedToStart { message } = r.outcome else {
        panic!("{r:?}")
    };
    assert!(message.contains("/nonexistent/program"), "{message}");
    // An empty argv is refused.
    let e = c
        .call(Request::Exec(ExecSpec {
            program: Program::Argv(Vec::new()),
            ..ExecSpec::default()
        }))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("argv"), "{e}");
}

#[tokio::test]
async fn a_timeout_kills_the_tree() {
    let env = Env::new();
    let c = env.connect().await;
    let mut spec = sh("sleep 101 & echo $!; sleep 100");
    spec.timeout_ms = Some(300);
    let r = exec(&c, spec).await;
    assert_eq!(r.outcome, Outcome::TimedOut { killed: true }, "{r:?}");
    let pid: u32 = String::from_utf8(r.stdout.data)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    wait_gone(pid);
}

#[tokio::test]
async fn keep_on_timeout_leaves_a_job() {
    let env = Env::new();
    let c = env.connect().await;
    let mut spec = sh("echo begun; sleep 1; echo done");
    spec.timeout_ms = Some(200);
    spec.keep_on_timeout = true;
    let r = exec(&c, spec).await;
    assert_eq!(r.outcome, Outcome::TimedOut { killed: false });
    assert_eq!(r.stdout.data, b"begun\n");
    let info = wait_job(&c, &r.job_id).await;
    assert_eq!(info.state, JobState::Exited { code: 0 });
    let Response::LogSlice(slice) = c
        .call(Request::JobLogRead {
            job_id: r.job_id.clone(),
            stream: Stream::Stdout,
            offset: Some(0),
            max_len: 1000,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(slice.data, b"begun\ndone\n");
    assert!(slice.ended);
}

#[tokio::test]
async fn output_over_the_cap() {
    let env = Env::new();
    let c = env.connect().await;
    let expected: Vec<u8> = (1..=100_000)
        .flat_map(|i| format!("{i}\n").into_bytes())
        .collect();
    let mut spec = sh("seq 1 100000");
    spec.output_cap = Some(1000);
    let r = exec(&c, spec).await;
    assert_eq!(r.stdout.total, expected.len() as u64);
    assert_eq!(r.stdout.data, expected[expected.len() - 1000..]);
    assert_eq!(r.stdout.offset, expected.len() as u64 - 1000);
    let Response::LogSlice(slice) = c
        .call(Request::JobLogRead {
            job_id: r.job_id.clone(),
            stream: Stream::Stdout,
            offset: Some(0),
            max_len: 8 * 1024 * 1024,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(slice.data, expected);
    assert_eq!(slice.offset, 0);
}

#[tokio::test]
async fn an_exec_job_is_listed() {
    let env = Env::new();
    let c = env.connect().await;
    let mut spec = sh("true");
    spec.name = Some("named".into());
    let r = exec(&c, spec).await;
    let Response::Jobs(jobs) = c
        .call(Request::JobList {
            include_finished: true,
            limit: 0,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(
        jobs.iter()
            .any(|j| j.job_id == r.job_id && j.name.as_deref() == Some("named"))
    );
}
