//! End to end over a real sshd: a private `sshd` on 127.0.0.1 with temp
//! keys, its own temp `AuthorizedKeysFile` written by the test (the test's
//! sshd configuration; ghostd never touches one), and `ssh` as the
//! transport running `<binary> stdio` as the remote command. Ignored by
//! default (it needs `/usr/sbin/sshd`); the checks run it with `--ignored`.

#![allow(clippy::too_many_lines)]

mod common;

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::{EXE, Env, exec};
use ghostd_client::Connection;
use ghostd_protocol::v1::{ExecSpec, Outcome, Program, Request, Response};

const SSHD: &str = "/usr/sbin/sshd";

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn keygen(path: &Path) {
    let status = Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", "ghostd-test", "-f"])
        .arg(path)
        .status()
        .expect("ssh-keygen");
    assert!(status.success());
}

#[tokio::test]
#[ignore = "starts a private sshd; run with --ignored"]
async fn over_ssh_with_the_users_access() {
    if !Path::new(SSHD).exists() {
        eprintln!("skipping: no {SSHD}");
        return;
    }
    let env = Env::new();
    let tmp = env.dir.path().to_path_buf();
    keygen(&tmp.join("host_key"));
    keygen(&tmp.join("client_key"));
    let public = fs::read_to_string(tmp.join("client_key.pub")).unwrap();
    let authorized = tmp.join("authorized_keys");
    fs::write(&authorized, format!("{}\n", public.trim())).unwrap();

    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let config = format!(
        "Port {port}
ListenAddress 127.0.0.1
HostKey {tmp}/host_key
PidFile {tmp}/sshd.pid
UsePAM no
StrictModes no
AuthorizedKeysFile {authorized}
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
LogLevel ERROR
SetEnv GHOSTD_STATE_DIR={state} GHOSTD_RUNTIME_DIR={runtime} GHOSTD_CONFIG={config} HOME={home}
",
        tmp = tmp.display(),
        home = env.home.display(),
        authorized = authorized.display(),
        state = env.state.display(),
        runtime = env.runtime.display(),
        config = env.config.display(),
    );
    fs::write(tmp.join("sshd_config"), config).unwrap();
    let log = fs::File::create(tmp.join("sshd.log")).unwrap();
    let _sshd = Daemon(
        Command::new(SSHD)
            .args(["-D", "-e", "-f"])
            .arg(tmp.join("sshd_config"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let until = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            Instant::now() < until,
            "sshd did not start: {}",
            fs::read_to_string(tmp.join("sshd.log")).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let argv: Vec<String> = vec![
        "ssh".into(),
        "-T".into(),
        "-F".into(),
        "/dev/null".into(),
        "-i".into(),
        tmp.join("client_key").display().to_string(),
        "-p".into(),
        port.to_string(),
        "-o".into(),
        format!("UserKnownHostsFile={}", tmp.join("known_hosts").display()),
        "-o".into(),
        "GlobalKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        "IdentitiesOnly=yes".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "127.0.0.1".into(),
        // The full path: a non-login `ssh host cmd` may not have the
        // install directory on PATH.
        format!("{EXE} stdio --client ssh-test"),
    ];
    let c = match Connection::spawn(&argv).await {
        Ok(c) => c,
        Err(e) => panic!(
            "{e}\nsshd log: {}",
            fs::read_to_string(tmp.join("sshd.log")).unwrap_or_default()
        ),
    };
    assert_eq!(c.call(Request::Ping).await.unwrap(), Response::Pong);
    let hostile: Vec<Vec<u8>> = vec![
        b"'".to_vec(),
        b"\"".to_vec(),
        b"$HOME".to_vec(),
        b"*".to_vec(),
        b";".to_vec(),
        b"a b".to_vec(),
        b"new\nline".to_vec(),
        Vec::new(),
        vec![0xff, 0x01, 0xfe],
    ];
    let mut program = vec![
        b"/bin/sh".to_vec(),
        b"-c".to_vec(),
        b"for a; do printf '%s' \"$a\"; printf '\\000'; done".to_vec(),
        b"sh".to_vec(),
    ];
    program.extend(hostile.iter().cloned());
    let r = exec(
        &c,
        ExecSpec {
            program: Program::Argv(program),
            ..ExecSpec::default()
        },
    )
    .await;
    assert_eq!(r.outcome, Outcome::Exited { code: 0 });
    let expected: Vec<u8> = hostile
        .iter()
        .flat_map(|a| a.iter().copied().chain(std::iter::once(0)))
        .collect();
    assert_eq!(r.stdout.data, expected);
}
