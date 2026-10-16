//! `ghostd stdio`: what sshd runs. It connects to the daemon's socket
//! (starting the daemon when none runs), sends the relay preamble, then
//! copies stdin to the socket and the socket to stdout, byte for byte. It
//! writes nothing of its own to stdout.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

use ghostd_protocol::{RelayInfo, encode_frame};

use crate::paths::Paths;
use crate::util::valid_label;

/// How long a relay waits for a daemon it started.
const START_WAIT: Duration = Duration::from_secs(5);

pub fn run(paths: &Paths, label: Option<String>) -> ExitCode {
    if let Some(label) = &label
        && !valid_label(label)
    {
        eprintln!("ghostd stdio: the client label must match [A-Za-z0-9._-]{{1,64}}");
        return ExitCode::from(2);
    }
    let stream = match connect_or_start(paths) {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("ghostd stdio: {e}");
            return ExitCode::from(1);
        }
    };
    let preamble = RelayInfo {
        client_label: label,
        ssh_connection: std::env::var("SSH_CONNECTION").ok(),
    };
    let frame = match encode_frame(&preamble) {
        Ok(frame) => frame,
        Err(e) => {
            eprintln!("ghostd stdio: {e}");
            return ExitCode::from(1);
        }
    };
    let mut to_daemon = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ghostd stdio: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = to_daemon.write_all(&frame) {
        eprintln!("ghostd stdio: {e}");
        return ExitCode::from(1);
    }
    std::thread::spawn(move || {
        let mut stdin = io::stdin().lock();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_daemon.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = to_daemon.shutdown(std::net::Shutdown::Write);
    });
    let mut from_daemon = stream;
    let mut stdout = io::stdout().lock();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        match from_daemon.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if stdout
                    .write_all(&buf[..n])
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    return ExitCode::from(1);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                eprintln!("ghostd stdio: {e}");
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

fn startable(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
    )
}

fn spawn_daemon() -> io::Result<Child> {
    // The daemon detaches itself (setsid) at once; stdio goes nowhere so
    // that sshd's channel closes when the relay ends.
    Command::new("/proc/self/exe")
        .arg0("ghostd")
        .arg("daemon")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

fn connect_or_start(paths: &Paths) -> Result<UnixStream, String> {
    let socket = paths.socket();
    let first = match UnixStream::connect(&socket) {
        Ok(stream) => return Ok(stream),
        Err(e) if startable(&e) => e,
        Err(e) => return Err(format!("{}: {e}", socket.display())),
    };
    let mut daemon = spawn_daemon().map_err(|e| format!("cannot start the daemon: {e}"))?;
    let begun = Instant::now();
    let mut last = first;
    while begun.elapsed() < START_WAIT {
        std::thread::sleep(Duration::from_millis(25));
        match UnixStream::connect(&socket) {
            Ok(stream) => return Ok(stream),
            Err(e) if startable(&e) => last = e,
            Err(e) => return Err(format!("{}: {e}", socket.display())),
        }
        // A daemon that failed (not one that found another running).
        if let Ok(Some(status)) = daemon.try_wait()
            && !status.success()
        {
            return Err(format!(
                "the daemon failed to start ({status}); see {}",
                paths.log_file().display()
            ));
        }
    }
    Err(format!(
        "no daemon answered on {} within {} s ({last}); see {}",
        socket.display(),
        START_WAIT.as_secs(),
        paths.log_file().display()
    ))
}
