//! A private ghostd for each test: temp state, runtime, config and home.

#![allow(dead_code)]

use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use ghostd_client::{Connection, Options};
use ghostd_protocol::v1::{ExecResult, ExecSpec, JobInfo, JobState, Program, Request, Response};
use ghostd_protocol::{
    ClientHello, FrameDecoder, HelloAnswer, MarkerScan, MarkerScanner, ServerHello, decode,
    encode_frame,
};

pub const EXE: &str = env!("CARGO_BIN_EXE_ghostd");

/// The configuration every test starts from: short stop grace.
pub const TEST_CONFIG: &str = "stop_grace_ms = 300\n";

pub struct Env {
    pub dir: tempfile::TempDir,
    pub home: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
    pub config: PathBuf,
}

impl Env {
    pub fn new() -> Self {
        Self::with_config(TEST_CONFIG)
    }

    pub fn with_config(config: &str) -> Self {
        let dir = tempfile::Builder::new()
            .prefix("ghostd-t")
            .tempdir()
            .unwrap();
        let home = dir.path().join("home");
        fs::create_dir(&home).unwrap();
        let config_path = dir.path().join("config.toml");
        fs::write(&config_path, config).unwrap();
        Self {
            home,
            state: dir.path().join("state"),
            runtime: dir.path().join("run"),
            config: config_path,
            dir,
        }
    }

    fn vars(&self) -> Vec<(&'static str, PathBuf)> {
        vec![
            ("GHOSTD_STATE_DIR", self.state.clone()),
            ("GHOSTD_RUNTIME_DIR", self.runtime.clone()),
            ("GHOSTD_CONFIG", self.config.clone()),
            ("HOME", self.home.clone()),
            ("SHELL", PathBuf::from("/bin/sh")),
        ]
    }

    /// `ghostd <args>` in this environment.
    pub fn cmd<S: AsRef<OsStr>>(&self, args: &[S]) -> std::process::Command {
        let mut c = std::process::Command::new(EXE);
        c.args(args);
        for (k, v) in self.vars() {
            c.env(k, v);
        }
        c.env_remove("XDG_RUNTIME_DIR")
            .env_remove("XDG_STATE_HOME")
            .env_remove("XDG_CONFIG_HOME");
        c
    }

    /// A command (any program) in this environment, for wrappers.
    pub fn tokio_cmd<S: AsRef<OsStr>>(&self, program: &str, args: &[S]) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(program);
        c.args(args);
        for (k, v) in self.vars() {
            c.env(k, v);
        }
        c.env("GHOSTD", EXE);
        c.env_remove("XDG_RUNTIME_DIR");
        c
    }

    pub async fn connect(&self) -> Connection {
        self.try_connect(Options::default()).await.unwrap()
    }

    pub async fn try_connect(
        &self,
        options: Options,
    ) -> Result<Connection, ghostd_client::ClientError> {
        Connection::spawn_command(self.tokio_cmd(EXE, &["stdio"]), options).await
    }

    /// Our processes (found by their environment) whose first argument is
    /// `role` (`daemon`, `worker`, `shim`).
    pub fn processes(&self, role: &str) -> Vec<u32> {
        ours(&self.state)
            .into_iter()
            .filter(|&pid| {
                fs::read(format!("/proc/{pid}/cmdline"))
                    .ok()
                    .and_then(|c| c.split(|&b| b == 0).nth(1).map(<[u8]>::to_vec))
                    .is_some_and(|arg| arg == role.as_bytes())
            })
            .collect()
    }

    #[allow(clippy::unused_self)]
    pub fn wait_for(&self, what: &str, mut f: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(10);
        while !f() {
            assert!(Instant::now() < until, "timed out waiting for {what}");
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    pub fn job_dir(&self, id: &str) -> PathBuf {
        self.state.join("jobs").join(id)
    }

    pub fn stop(&self) {
        let _ = self.cmd(&["stop"]).stdout(Stdio::null()).status();
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        for pid in self.processes("shim") {
            signal(pid, 15);
        }
        self.stop();
        let until = Instant::now() + Duration::from_secs(3);
        while !self.processes("shim").is_empty() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(25));
        }
        for pid in ours(&self.state) {
            signal(pid, 9);
        }
    }
}

/// Processes whose environment names this state directory.
fn ours(state: &Path) -> Vec<u32> {
    let mut needle = b"GHOSTD_STATE_DIR=".to_vec();
    needle.extend_from_slice(state.as_os_str().as_bytes());
    let me = std::process::id();
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<u32>().ok())
        .filter(|&pid| pid != me)
        .filter(|pid| {
            fs::read(format!("/proc/{pid}/environ"))
                .is_ok_and(|env| env.split(|&b| b == 0).any(|v| v == needle.as_slice()))
        })
        .collect()
}

pub fn signal(pid: u32, sig: i32) {
    let _ = std::process::Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .stderr(Stdio::null())
        .status();
}

/// Whether a live (non-zombie) process has this pid.
pub fn alive(pid: u32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
        s.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next().map(|st| st != "Z"))
            .unwrap_or(false)
    })
}

pub fn wait_gone(pid: u32) {
    let until = Instant::now() + Duration::from_secs(10);
    while alive(pid) {
        assert!(Instant::now() < until, "process {pid} still runs");
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub fn argv(args: &[&[u8]]) -> Program {
    Program::Argv(args.iter().map(|a| a.to_vec()).collect())
}

pub fn sh(script: &str) -> ExecSpec {
    ExecSpec {
        program: argv(&[b"/bin/sh", b"-c", script.as_bytes()]),
        ..ExecSpec::default()
    }
}

pub async fn exec(c: &Connection, spec: ExecSpec) -> ExecResult {
    match c.call(Request::Exec(spec)).await.unwrap() {
        Response::Exec(r) => r,
        other => panic!("unexpected {other:?}"),
    }
}

pub async fn start(c: &Connection, spec: ExecSpec) -> String {
    match c.call(Request::JobStart(spec)).await.unwrap() {
        Response::JobStarted { job_id } => job_id,
        other => panic!("unexpected {other:?}"),
    }
}

pub async fn status(c: &Connection, job_id: &str) -> JobInfo {
    match c
        .call(Request::JobStatus {
            job_id: job_id.into(),
        })
        .await
        .unwrap()
    {
        Response::Job(info) => info,
        other => panic!("unexpected {other:?}"),
    }
}

pub async fn wait_job(c: &Connection, job_id: &str) -> JobInfo {
    loop {
        let info = match c
            .call(Request::JobWait {
                job_id: job_id.into(),
                timeout_ms: 10_000,
            })
            .await
            .unwrap()
        {
            Response::Job(info) => info,
            other => panic!("unexpected {other:?}"),
        };
        if info.state != JobState::Running {
            return info;
        }
    }
}

/// A connection spoken by hand, for frame-level tests.
pub struct Raw {
    pub child: std::process::Child,
    pub stdin: std::process::ChildStdin,
    pub stdout: std::process::ChildStdout,
    pub decoder: FrameDecoder,
}

impl Raw {
    /// Connects through `ghostd stdio` and says hello with version 1.
    pub fn connect(env: &Env) -> Self {
        let mut child = env
            .cmd(&["stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut scanner = MarkerScanner::new();
        let mut buf = [0u8; 4096];
        let mut decoder = FrameDecoder::new();
        loop {
            let n = stdout.read(&mut buf).unwrap();
            assert!(n > 0, "no hello");
            if let MarkerScan::Found { rest } = scanner.feed(&buf[..n]) {
                decoder.feed(&rest);
                break;
            }
        }
        let mut raw = Self {
            child,
            stdin,
            stdout,
            decoder,
        };
        let hello: ServerHello = decode(&raw.frame().unwrap()).unwrap();
        assert_eq!(hello.min, 1);
        raw.send(
            &encode_frame(&ClientHello {
                program_version: "raw".into(),
                min: 1,
                max: 1,
            })
            .unwrap(),
        );
        let answer: HelloAnswer = decode(&raw.frame().unwrap()).unwrap();
        assert_eq!(answer, HelloAnswer::Welcome { version: 1 });
        raw
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.stdin.write_all(bytes).unwrap();
        self.stdin.flush().unwrap();
    }

    /// The next frame, `None` at EOF.
    pub fn frame(&mut self) -> Option<Vec<u8>> {
        let mut buf = vec![0u8; 65536];
        loop {
            if let Some(f) = self.decoder.next_frame().unwrap() {
                return Some(f);
            }
            let n = self.stdout.read(&mut buf).unwrap();
            if n == 0 {
                return None;
            }
            self.decoder.feed(&buf[..n]);
        }
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
