//! `ghostd daemon` (the supervisor that keeps a worker running), `ghostd
//! stop` and `ghostd status`.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::process::{ExitCode, Stdio};
use std::time::{Duration, Instant};

use ghostd_protocol::{
    FrameDecoder, MAX_HELLO_FRAME, MarkerScan, MarkerScanner, RelayInfo, ServerHello, decode,
    encode_frame,
};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use serde_json::json;

use crate::config::Config;
use crate::jobs::Jobs;
use crate::logfile::{self, log};
use crate::paths::Paths;
use crate::util::atomic_write;

const BACKOFF_START: Duration = Duration::from_millis(500);
const BACKOFF_MAX: Duration = Duration::from_secs(30);
/// A worker up this long resets the back-off.
const HEALTHY: Duration = Duration::from_mins(1);
const STOP_WAIT: Duration = Duration::from_secs(10);

fn open_lock(paths: &Paths) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(paths.daemon_lock())
}

/// Whether a daemon holds the lock (probing it without keeping it).
fn daemon_runs(paths: &Paths) -> bool {
    let Ok(file) = OpenOptions::new().write(true).open(paths.daemon_lock()) else {
        return false;
    };
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => {
            drop(lock);
            false
        }
        Err(_) => true,
    }
}

fn read_pid(paths: &Paths) -> Option<i32> {
    fs::read_to_string(paths.pid_file())
        .ok()?
        .trim()
        .parse()
        .ok()
}

pub fn daemon(paths: &Paths) -> ExitCode {
    if let Err(e) = paths.ensure() {
        eprintln!("ghostd daemon: {e}");
        return ExitCode::from(1);
    }
    let file = match open_lock(paths) {
        Ok(file) => file,
        Err(e) => {
            eprintln!("ghostd daemon: {}: {e}", paths.daemon_lock().display());
            return ExitCode::from(1);
        }
    };
    let Ok(_lock) = Flock::lock(file, FlockArg::LockExclusiveNonblock) else {
        println!("a ghostd daemon already runs");
        return ExitCode::SUCCESS;
    };
    // Already a session leader when started from an interactive shell's
    // job; the relay's child is not.
    let _ = nix::unistd::setsid();
    if let Err(e) = Config::load(&paths.config) {
        log(paths, &format!("daemon: configuration: {e}"));
        eprintln!("ghostd daemon: {e}");
        return ExitCode::from(1);
    }
    let pid = std::process::id().to_string();
    if let Err(e) = atomic_write(&paths.pid_file(), pid.as_bytes(), 0o600, false) {
        log(paths, &format!("daemon: pid file: {e}"));
    }
    log(
        paths,
        &format!("daemon: started ({})", env!("CARGO_PKG_VERSION")),
    );
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            log(paths, &format!("daemon: runtime: {e}"));
            return ExitCode::from(1);
        }
    };
    // The workers are spawned from this (the main) thread: their parent
    // death signal is tied to it.
    let code = runtime.block_on(supervise(paths));
    let _ = fs::remove_file(paths.pid_file());
    log(paths, "daemon: stopped");
    code
}

fn spawn_worker(paths: &Paths) -> std::io::Result<tokio::process::Child> {
    let mut command = tokio::process::Command::new("/proc/self/exe");
    command.arg0("ghostd").arg("worker").stdin(Stdio::null());
    match (logfile::open(paths), logfile::open(paths)) {
        (Ok(out), Ok(err)) => {
            command.stdout(out).stderr(err);
        }
        _ => {
            command.stdout(Stdio::null()).stderr(Stdio::null());
        }
    }
    command.spawn()
}

async fn supervise(paths: &Paths) -> ExitCode {
    use tokio::signal::unix::{SignalKind, signal};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        return ExitCode::from(1);
    };
    let mut backoff = BACKOFF_START;
    loop {
        let mut worker = match spawn_worker(paths) {
            Ok(child) => child,
            Err(e) => {
                log(paths, &format!("daemon: cannot start the worker: {e}"));
                return ExitCode::from(1);
            }
        };
        let started = Instant::now();
        let status = tokio::select! {
            status = worker.wait() => status,
            _ = term.recv() => return stop_worker(paths, worker).await,
            _ = int.recv() => return stop_worker(paths, worker).await,
        };
        match status {
            Ok(s) if s.success() => {
                log(paths, "daemon: the worker exited normally");
                return ExitCode::SUCCESS;
            }
            Ok(s) => log(
                paths,
                &format!("daemon: the worker exited ({s}); restarting"),
            ),
            Err(e) => log(paths, &format!("daemon: waiting for the worker: {e}")),
        }
        if started.elapsed() >= HEALTHY {
            backoff = BACKOFF_START;
        }
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            _ = term.recv() => return ExitCode::SUCCESS,
            _ = int.recv() => return ExitCode::SUCCESS,
        }
        backoff = (backoff * 2).min(BACKOFF_MAX);
    }
}

async fn stop_worker(paths: &Paths, mut worker: tokio::process::Child) -> ExitCode {
    if let Some(id) = worker.id()
        && let Ok(pid) = i32::try_from(id)
    {
        let _ = kill(Pid::from_raw(pid), Signal::SIGTERM);
    }
    if tokio::time::timeout(STOP_WAIT, worker.wait())
        .await
        .is_err()
    {
        log(paths, "daemon: the worker ignored SIGTERM; killing it");
        let _ = worker.kill().await;
    }
    ExitCode::SUCCESS
}

pub fn stop(paths: &Paths) -> ExitCode {
    if !daemon_runs(paths) {
        println!("{}", json!({ "running": false, "stopped": false }));
        return ExitCode::SUCCESS;
    }
    let Some(pid) = read_pid(paths) else {
        eprintln!(
            "ghostd stop: a daemon runs but {} is unreadable",
            paths.pid_file().display()
        );
        return ExitCode::from(1);
    };
    if let Err(e) = kill(Pid::from_raw(pid), Signal::SIGTERM) {
        eprintln!("ghostd stop: signalling {pid}: {e}");
        return ExitCode::from(1);
    }
    let begun = Instant::now();
    while begun.elapsed() < STOP_WAIT {
        if !daemon_runs(paths) {
            println!(
                "{}",
                json!({ "running": false, "stopped": true, "pid": pid })
            );
            return ExitCode::SUCCESS;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    eprintln!(
        "ghostd stop: the daemon ({pid}) did not stop within {} s",
        STOP_WAIT.as_secs()
    );
    ExitCode::from(1)
}

/// The running daemon's version, from the hello on its socket.
fn daemon_version(paths: &Paths) -> Option<String> {
    let mut stream = UnixStream::connect(paths.socket()).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let preamble = encode_frame(&RelayInfo {
        client_label: Some("status".into()),
        ssh_connection: None,
    })
    .ok()?;
    stream.write_all(&preamble).ok()?;
    let mut scanner = MarkerScanner::new();
    let mut decoder = FrameDecoder::with_max(MAX_HELLO_FRAME);
    let mut buf = [0u8; 4096];
    let mut found = false;
    loop {
        let n = stream.read(&mut buf).ok()?;
        if n == 0 {
            return None;
        }
        if found {
            decoder.feed(&buf[..n]);
        } else {
            match scanner.feed(&buf[..n]) {
                MarkerScan::Found { rest } => {
                    decoder.feed(&rest);
                    found = true;
                }
                MarkerScan::NeedMore => continue,
                MarkerScan::TooMuch => return None,
            }
        }
        if let Some(body) = decoder.next_frame().ok()? {
            let hello: ServerHello = decode(&body).ok()?;
            return Some(hello.program_version);
        }
    }
}

pub fn status(paths: &Paths) -> ExitCode {
    let running = daemon_runs(paths);
    let pid = if running { read_pid(paths) } else { None };
    let config = Config::load(&paths.config).unwrap_or_default();
    let (jobs_running, jobs_finished) = Jobs::new(paths.jobs(), config).counts();
    let report = json!({
        "running": running,
        "pid": pid,
        "version": env!("CARGO_PKG_VERSION"),
        "daemon_version": if running { daemon_version(paths) } else { None },
        "socket": paths.socket(),
        "state_dir": paths.state,
        "jobs": { "running": jobs_running, "finished": jobs_finished },
    });
    println!("{report}");
    ExitCode::SUCCESS
}
