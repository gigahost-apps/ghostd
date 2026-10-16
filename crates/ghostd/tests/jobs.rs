//! Jobs: their lifecycle, logs, stops, and survival of the daemon's death.

#![allow(clippy::too_many_lines)]

mod common;

use std::fs;
use std::time::{Duration, Instant, SystemTime};

use common::{Env, alive, exec, sh, signal, start, status, wait_gone, wait_job};
use ghostd_client::Connection;
use ghostd_protocol::v1::{ErrorKind, JobInfo, JobState, LogSlice, Request, Response, Stream};

async fn log(
    c: &Connection,
    job: &str,
    stream: Stream,
    offset: Option<u64>,
    max_len: u32,
) -> LogSlice {
    match c
        .call(Request::JobLogRead {
            job_id: job.into(),
            stream,
            offset,
            max_len,
        })
        .await
        .unwrap()
    {
        Response::LogSlice(s) => s,
        other => panic!("{other:?}"),
    }
}

async fn wait_output(c: &Connection, job: &str, needle: &str) -> String {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let s = log(c, job, Stream::Stdout, Some(0), 65536).await;
        let text = String::from_utf8_lossy(&s.data).into_owned();
        if text.contains(needle) {
            return text;
        }
        assert!(Instant::now() < until, "no {needle:?} in {text:?}");
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn remote_kind(e: &ghostd_client::ClientError) -> ErrorKind {
    match e {
        ghostd_client::ClientError::Remote(e) => e.kind,
        other => panic!("{other}"),
    }
}

#[tokio::test]
async fn lifecycle() {
    let env = Env::new();
    let c = env.connect().await;
    let mut spec = sh("echo started; sleep 30");
    spec.name = Some("sleeper".into());
    let job = start(&c, spec).await;
    wait_output(&c, &job, "started").await;
    let info = status(&c, &job).await;
    assert_eq!(info.state, JobState::Running);
    assert_eq!(info.name.as_deref(), Some("sleeper"));
    assert!(
        info.argv_summary.starts_with("/bin/sh -c echo started"),
        "{}",
        info.argv_summary
    );
    let Response::Jobs(running) = c
        .call(Request::JobList {
            include_finished: false,
            limit: 10,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(running.len(), 1);
    // A wait that times out answers Running.
    let begun = Instant::now();
    let Response::Job(waited) = c
        .call(Request::JobWait {
            job_id: job.clone(),
            timeout_ms: 200,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(waited.state, JobState::Running);
    assert!(begun.elapsed() >= Duration::from_millis(200));
    let e = c
        .call(Request::JobRemove {
            job_id: job.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::Busy);
    c.call(Request::JobSignal {
        job_id: job.clone(),
        signal: 15,
    })
    .await
    .unwrap();
    let info = wait_job(&c, &job).await;
    assert_eq!(info.state, JobState::Signaled { signal: 15 });
    assert!(info.ended_at_ms.is_some());
    let e = c
        .call(Request::JobSignal {
            job_id: job.clone(),
            signal: 15,
        })
        .await
        .unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::Conflict);
    // Its shim may still be finishing; removal succeeds once it is gone.
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        match c
            .call(Request::JobRemove {
                job_id: job.clone(),
            })
            .await
        {
            Ok(_) => break,
            Err(_) if Instant::now() < until => tokio::time::sleep(Duration::from_millis(25)).await,
            Err(e) => panic!("{e}"),
        }
    }
    let e = c
        .call(Request::JobStatus { job_id: job })
        .await
        .unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::NotFound);
    let e = c
        .call(Request::JobStatus {
            job_id: "j../../../etc".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::NotFound);
}

#[tokio::test]
async fn log_slices_across_rotation() {
    let env = Env::with_config("stop_grace_ms = 300\nlog_max_bytes = 1024\n");
    let c = env.connect().await;
    let expected: Vec<u8> = (1..=2000)
        .flat_map(|i| format!("{i}\n").into_bytes())
        .collect();
    let job = start(&c, sh("seq 1 2000")).await;
    assert_eq!(wait_job(&c, &job).await.state, JobState::Exited { code: 0 });
    let tail = log(&c, &job, Stream::Stdout, None, 100).await;
    assert_eq!(tail.total, expected.len() as u64);
    assert_eq!(tail.data, expected[expected.len() - 100..]);
    assert_eq!(tail.offset, expected.len() as u64 - 100);
    let head = log(&c, &job, Stream::Stdout, Some(0), 1_000_000).await;
    assert!(head.first_available > 0, "nothing was rotated away");
    assert_eq!(head.offset, head.first_available);
    let kept = usize::try_from(head.first_available).unwrap();
    assert_eq!(head.data, expected[kept..]);
    assert!(head.data.len() > 1024, "the rotated file is read too");
    // A slice in the middle.
    let mid = log(
        &c,
        &job,
        Stream::Stdout,
        Some(head.first_available + 10),
        50,
    )
    .await;
    assert_eq!(mid.data, expected[kept + 10..kept + 60]);
    assert!(mid.ended);
    let empty = log(&c, &job, Stream::Stderr, None, 100).await;
    assert_eq!(empty.total, 0);
}

#[tokio::test]
async fn stop_kills_the_whole_tree() {
    let env = Env::new();
    let c = env.connect().await;
    let script = "setsid sleep 300 & echo $!; (sleep 301 & echo $!); trap '' TERM; echo ready; while :; do sleep 1; done";
    let job = start(&c, sh(script)).await;
    let out = wait_output(&c, &job, "ready").await;
    let pids: Vec<u32> = out.lines().filter_map(|l| l.trim().parse().ok()).collect();
    assert_eq!(pids.len(), 2, "{out}");
    let info = status(&c, &job).await;
    let program = info.pid.unwrap();
    for &pid in &pids {
        assert!(alive(pid));
    }
    let shim = env.processes("shim");
    assert_eq!(shim.len(), 1);
    let Response::Job(stopped) = c
        .call(Request::JobStop {
            job_id: job.clone(),
            grace_ms: Some(300),
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(
        stopped.state,
        JobState::Signaled { signal: 9 },
        "it ignored SIGTERM"
    );
    for pid in pids.iter().copied().chain([program]) {
        assert!(!alive(pid), "{pid} survived the stop");
    }
    assert!(!alive(shim[0]));
}

#[tokio::test]
async fn jobs_survive_the_worker_and_the_daemon() {
    let env = Env::new();
    let c = env.connect().await;
    let job = start(&c, sh("sleep 60")).await;
    let workers = env.processes("worker");
    assert_eq!(workers.len(), 1);
    signal(workers[0], 9);
    env.wait_for("a new worker", || {
        let now = env.processes("worker");
        now.len() == 1 && now[0] != workers[0]
    });
    drop(c);
    let until = Instant::now() + Duration::from_secs(10);
    let c = loop {
        if let Ok(c) = env.try_connect(ghostd_client::Options::default()).await {
            break c;
        }
        assert!(Instant::now() < until);
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert_eq!(status(&c, &job).await.state, JobState::Running);
    drop(c);
    // Now the whole daemon.
    for pid in env.processes("daemon") {
        signal(pid, 9);
    }
    for pid in env.processes("worker") {
        signal(pid, 9);
    }
    env.wait_for("no daemon", || {
        env.processes("daemon").is_empty() && env.processes("worker").is_empty()
    });
    let c = env.connect().await;
    assert_eq!(env.processes("daemon").len(), 1);
    assert_eq!(status(&c, &job).await.state, JobState::Running);
    let Response::Job(stopped) = c
        .call(Request::JobStop {
            job_id: job,
            grace_ms: None,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(stopped.state, JobState::Signaled { signal: 15 });
}

#[tokio::test]
async fn a_killed_shim_is_lost_and_nothing_is_killed_for_it() {
    let env = Env::new();
    let c = env.connect().await;
    let job = start(&c, sh("sleep 60")).await;
    let info = status(&c, &job).await;
    let program = info.pid.unwrap();
    let shim = env.processes("shim");
    assert_eq!(shim.len(), 1);
    signal(shim[0], 9);
    wait_gone(shim[0]);
    assert_eq!(status(&c, &job).await.state, JobState::Lost);
    // A stop of a lost job kills nothing by pid.
    let Response::Job(after) = c
        .call(Request::JobStop {
            job_id: job.clone(),
            grace_ms: Some(10),
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(after.state, JobState::Lost);
    assert!(alive(program), "a lost job's program was killed");
    signal(program, 9);
    c.call(Request::JobRemove { job_id: job }).await.unwrap();
}

#[tokio::test]
async fn gc_keeps_running_jobs() {
    let env =
        Env::with_config("stop_grace_ms = 300\nmax_jobs_kept = 1\nexec_retention_hours = 0\n");
    let c = env.connect().await;
    let running = start(&c, sh("sleep 60")).await;
    for _ in 0..2 {
        let done = start(&c, sh("true")).await;
        wait_job(&c, &done).await;
    }
    exec(&c, sh("true")).await;
    drop(c);
    env.stop();
    // The next worker collects at its start.
    let c = env.connect().await;
    let until = Instant::now() + Duration::from_secs(10);
    loop {
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
        if jobs.len() == 1 {
            assert_eq!(jobs[0].job_id, running);
            assert_eq!(jobs[0].state, JobState::Running);
            break;
        }
        assert!(Instant::now() < until, "{jobs:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn max_running_jobs_refuses_more() {
    let env = Env::with_config("stop_grace_ms = 300\nmax_running_jobs = 1\n");
    let c = env.connect().await;
    let _job = start(&c, sh("sleep 60")).await;
    let e = c.call(Request::JobStart(sh("true"))).await.unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::Busy);
    let e = c.call(Request::Exec(sh("true"))).await.unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::Busy);
}

#[tokio::test]
async fn a_job_timeout_stops_it() {
    let env = Env::new();
    let c = env.connect().await;
    let mut spec = sh("sleep 60");
    spec.timeout_ms = Some(200);
    let job = start(&c, spec).await;
    assert_eq!(
        wait_job(&c, &job).await.state,
        JobState::Signaled { signal: 15 }
    );
}

/// Sets a directory's mtime two hours back.
fn age(dir: &std::path::Path) {
    fs::File::open(dir)
        .unwrap()
        .set_modified(SystemTime::now() - Duration::from_hours(2))
        .unwrap();
}

#[tokio::test]
async fn job_files_of_another_build_are_read_and_never_collected_blindly() {
    let env = Env::new();
    let c = env.connect().await;
    let job = start(&c, sh("sleep 60")).await;
    drop(c);
    env.stop();
    // A newer build wrote fields this one does not know (or an older one
    // lacks some): the job is still read, running, and stoppable.
    let dir = env.job_dir(&job);
    for name in ["spec.json", "status.json"] {
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join(name)).unwrap()).unwrap();
        value["added_by_a_newer_build"] = serde_json::json!({"x": 1});
        fs::write(dir.join(name), serde_json::to_vec(&value).unwrap()).unwrap();
    }
    // One whose spec this build cannot read at all, and one the worker
    // died creating (neither spec nor status), both two hours old.
    let foreign = env.state.join("jobs/j00000000000000aa");
    fs::create_dir(&foreign).unwrap();
    fs::write(foreign.join("spec.json"), b"{\"format\": 7}").unwrap();
    let abandoned = env.state.join("jobs/j00000000000000bb");
    fs::create_dir(&abandoned).unwrap();
    for d in [&dir, &foreign, &abandoned] {
        age(d);
    }
    // The next worker collects at its start.
    let c = env.connect().await;
    env.wait_for("the abandoned directory to go", || !abandoned.exists());
    assert!(dir.exists(), "a running job was collected");
    assert!(foreign.exists(), "a job of another format was collected");
    assert_eq!(status(&c, &job).await.state, JobState::Running);
    let e = c
        .call(Request::JobStatus {
            job_id: "j00000000000000aa".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::Unsupported);
    let Response::Job(stopped) = c
        .call(Request::JobStop {
            job_id: job,
            grace_ms: None,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(stopped.state, JobState::Signaled { signal: 15 });
}

#[tokio::test]
async fn a_client_chosen_id_makes_a_repeat_safe() {
    let env = Env::new();
    let c = env.connect().await;
    // JobStart twice with the same ID: one job, one run.
    let mut spec = sh("echo run >> runs; sleep 30");
    spec.job_id = Some("j0123456789abcdef".into());
    let first = start(&c, spec.clone()).await;
    assert_eq!(first, "j0123456789abcdef");
    assert_eq!(start(&c, spec.clone()).await, first);
    // Another request under a kept job's ID is refused.
    let mut other = sh("true");
    other.job_id = spec.job_id.clone();
    let e = c.call(Request::JobStart(other)).await.unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::Conflict);
    let e = c.call(Request::Exec(spec.clone())).await.unwrap_err();
    assert_eq!(
        remote_kind(&e),
        ErrorKind::Conflict,
        "an Exec of a JobStart's ID"
    );
    let mut bad = sh("true");
    bad.job_id = Some("../../etc".into());
    let e = c.call(Request::JobStart(bad)).await.unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::InvalidArgument);
    // An Exec whose answer is lost with its connection: the job is found by
    // its ID on another one, and the same request answers that run.
    let mut run = sh("echo x >> execs; sleep 1; echo done");
    run.job_id = Some("jfedcba9876543210".into());
    let lost = {
        let c2 = env.connect().await;
        let run = run.clone();
        tokio::spawn(async move { c2.call(Request::Exec(run)).await })
    };
    let until = Instant::now() + Duration::from_secs(10);
    while c
        .call(Request::JobStatus {
            job_id: "jfedcba9876543210".into(),
        })
        .await
        .is_err()
    {
        assert!(Instant::now() < until, "the exec never started");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    lost.abort();
    let _ = lost.await;
    let r = exec(&c, run).await;
    assert_eq!(r.job_id, "jfedcba9876543210");
    assert_eq!(
        r.outcome,
        ghostd_protocol::v1::Outcome::Exited { code: 0 },
        "{r:?}"
    );
    assert_eq!(r.stdout.data, b"done\n");
    assert_eq!(fs::read(env.home.join("execs")).unwrap(), b"x\n");
    assert_eq!(fs::read(env.home.join("runs")).unwrap(), b"run\n");
}

#[tokio::test]
async fn a_job_whose_shim_runs_is_never_collected_even_without_a_status() {
    let env = Env::with_config("stop_grace_ms = 300\njob_retention_hours = 0\n");
    let c = env.connect().await;
    let job = start(&c, sh("sleep 60")).await;
    drop(c);
    env.stop();
    // A shim that could not write its status (a full disk), for a job
    // started long ago.
    let dir = env.job_dir(&job);
    fs::remove_file(dir.join("status.json")).unwrap();
    let mut spec: serde_json::Value =
        serde_json::from_slice(&fs::read(dir.join("spec.json")).unwrap()).unwrap();
    spec["created_at_ms"] = serde_json::json!(1_000);
    fs::write(dir.join("spec.json"), serde_json::to_vec(&spec).unwrap()).unwrap();
    // A finished job beside it is collected, so the collection did run.
    let c = env.connect().await;
    let done = start(&c, sh("true")).await;
    wait_job(&c, &done).await;
    drop(c);
    env.stop();
    let c = env.connect().await;
    env.wait_for("the finished job to be collected", || {
        !env.job_dir(&done).exists()
    });
    assert!(dir.exists(), "a job whose shim runs was collected");
    assert_eq!(status(&c, &job).await.state, JobState::Running);
}

async fn wait_for_ms(c: &Connection, job: &str, timeout_ms: u64) -> JobInfo {
    match c
        .call(Request::JobWait {
            job_id: job.into(),
            timeout_ms,
        })
        .await
        .unwrap()
    {
        Response::Job(info) => info,
        other => panic!("unexpected {other:?}"),
    }
}

/// Waits until the job's program has ended (the job may live on).
async fn program_ended(c: &Connection, job: &str) -> JobInfo {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let info = status(c, job).await;
        if info.state != JobState::Running {
            return info;
        }
        assert!(Instant::now() < until, "{info:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_background_process_belongs_to_the_job_until_it_is_stopped() {
    let env = Env::new();
    let c = env.connect().await;
    let job = start(&c, sh("nohup sleep 301 >/dev/null 2>&1 & echo started")).await;
    let info = program_ended(&c, &job).await;
    assert_eq!(info.state, JobState::Exited { code: 0 });
    // Well past any settle, the server is still the job's.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let info = status(&c, &job).await;
    assert_eq!(info.state, JobState::Exited { code: 0 });
    assert_eq!(info.processes, 1, "{info:?}");
    assert!(!info.finished);
    assert_eq!(env.processes("301").len(), 1);
    // Listed as unfinished, not removable.
    let Response::Jobs(jobs) = c
        .call(Request::JobList {
            include_finished: false,
            limit: 0,
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(jobs.iter().any(|j| j.job_id == job));
    let e = c
        .call(Request::JobRemove {
            job_id: job.clone(),
        })
        .await
        .unwrap_err();
    assert_eq!(remote_kind(&e), ErrorKind::Busy);
    // A log read does not call it ended.
    let slice = log(&c, &job, Stream::Stdout, Some(0), 100).await;
    assert!(!slice.ended);
    // A short wait returns unfinished.
    let begun = Instant::now();
    let info = wait_for_ms(&c, &job, 300).await;
    assert!(!info.finished);
    assert!(begun.elapsed() >= Duration::from_millis(250));
    let Response::Job(stopped) = c
        .call(Request::JobStop {
            job_id: job.clone(),
            grace_ms: Some(300),
        })
        .await
        .unwrap()
    else {
        panic!()
    };
    assert!(stopped.finished, "{stopped:?}");
    assert_eq!(stopped.processes, 0);
    assert_eq!(stopped.state, JobState::Exited { code: 0 });
    assert!(
        env.processes("301").is_empty(),
        "the server outlived the stop"
    );
    let begun = Instant::now();
    assert!(wait_for_ms(&c, &job, 10_000).await.finished);
    assert!(begun.elapsed() < Duration::from_secs(1));
    let slice = log(&c, &job, Stream::Stdout, Some(0), 100).await;
    assert!(slice.ended);
    assert_eq!(slice.data, b"started\n");
}

#[tokio::test]
async fn a_job_finishes_when_its_leftovers_end() {
    let env = Env::new();
    let c = env.connect().await;
    let begun = Instant::now();
    let job = start(&c, sh("sleep 1 &")).await;
    let info = program_ended(&c, &job).await;
    assert_eq!(info.state, JobState::Exited { code: 0 });
    let info = wait_job(&c, &job).await;
    assert!(info.finished);
    let took = begun.elapsed();
    assert!(took >= Duration::from_millis(950), "{took:?}");
    assert!(took < Duration::from_secs(4), "{took:?}");
    assert_eq!(info.processes, 0);
}

#[tokio::test]
async fn a_detached_process_is_not_waited_for() {
    let env = Env::new();
    let c = env.connect().await;
    let job = start(
        &c,
        sh("setsid sleep 302 >/dev/null 2>&1 </dev/null & echo $!"),
    )
    .await;
    let begun = Instant::now();
    let info = wait_job(&c, &job).await;
    assert!(info.finished);
    assert_eq!(info.state, JobState::Exited { code: 0 });
    assert!(
        begun.elapsed() < Duration::from_secs(3),
        "{:?}",
        begun.elapsed()
    );
    let out = log(&c, &job, Stream::Stdout, Some(0), 100).await;
    let pid: u32 = String::from_utf8(out.data).unwrap().trim().parse().unwrap();
    assert!(alive(pid), "the detached process was killed");
    signal(pid, 9);
    wait_gone(pid);
}

#[tokio::test]
async fn a_job_timeout_takes_what_the_program_left() {
    let env = Env::new();
    let c = env.connect().await;
    let mut spec = sh("sleep 303 >/dev/null 2>&1 &");
    spec.timeout_ms = Some(700);
    let job = start(&c, spec).await;
    let info = wait_job(&c, &job).await;
    assert!(info.finished);
    assert_eq!(info.state, JobState::Exited { code: 0 });
    assert!(env.processes("303").is_empty());
}
