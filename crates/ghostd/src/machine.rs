//! `MachineState` and `Identify`: what the machine is and how it is doing,
//! read from `/proc`, `/sys`, `/etc` and a few commands. Each part is read
//! on its own: one that cannot be read leaves its field empty and says why
//! in `notes`, so the answer never fails as a whole. Commands run by
//! their argv (never a shell) with `LC_ALL=C`, a 5 s timeout and their
//! output capped.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use ghostd_protocol::v2::{Disk, HostId, Identity, Listening, Machine, Memory, Proto};

/// How long a command may run.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
/// How much of a command's output is kept.
const OUTPUT_CAP: usize = 256 * 1024;
/// How many of the latest error lines are answered.
const ERRORS_KEPT: usize = 20;
/// How long a filesystem's statvfs may take (a hung network mount).
const STATVFS_TIMEOUT: Duration = Duration::from_secs(2);
/// How many kernel messages `/dev/kmsg` is read for.
const KMSG_RECORDS: usize = 20_000;

fn first_line(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let line = text.lines().next()?.trim().to_string();
    (!line.is_empty()).then_some(line)
}

/// Who this daemon is.
#[must_use]
pub fn identity(host_id: HostId) -> Identity {
    Identity {
        host_id,
        hostname: rustix::system::uname()
            .nodename()
            .to_string_lossy()
            .into_owned(),
        machine_id: first_line("/etc/machine-id"),
        boot_id: first_line("/proc/sys/kernel/random/boot_id"),
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        uid: rustix::process::getuid().as_raw(),
    }
}

/// `program` found on `path` (a `PATH` value), as `which` finds it.
fn find_program(program: &str, path: Option<&OsStr>) -> Option<PathBuf> {
    let path = path?;
    std::env::split_paths(path)
        .map(|dir| dir.join(program))
        .find(|candidate| {
            fs::metadata(candidate).is_ok_and(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.is_file() && m.permissions().mode() & 0o111 != 0
            })
        })
}

/// Runs `argv` with `LC_ALL=C`, stdin from `/dev/null`, stderr kept
/// apart, for at most [`COMMAND_TIMEOUT`]; answers its stdout (capped) or
/// why it failed.
fn run(program: &Path, args: &[&str]) -> Result<String, String> {
    let name = program
        .file_name()
        .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .env_remove("LANG")
        .env("SYSTEMD_PAGER", "")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| format!("{name}: {e}"))?;
    let capped = |mut pipe: Box<dyn Read + Send>| {
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut kept = Vec::new();
            let mut buf = [0u8; 16 * 1024];
            loop {
                match pipe.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let room = OUTPUT_CAP.saturating_sub(kept.len());
                        kept.extend_from_slice(&buf[..n.min(room)]);
                    }
                }
            }
            let _ = tx.send(kept);
        });
        rx
    };
    let stdout = child.stdout.take().map(|p| capped(Box::new(p)));
    let stderr = child.stderr.take().map(|p| capped(Box::new(p)));
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(None) | Err(_) => {
                // The whole group: a command's own children too.
                let _ = nix::sys::signal::killpg(
                    nix::unistd::Pid::from_raw(i32::try_from(child.id()).unwrap_or(i32::MAX)),
                    nix::sys::signal::Signal::SIGKILL,
                );
                let _ = child.wait();
                return Err(format!(
                    "{name} did not finish within {} s",
                    COMMAND_TIMEOUT.as_secs()
                ));
            }
        }
    };
    let take = |rx: Option<mpsc::Receiver<Vec<u8>>>| {
        rx.and_then(|rx| rx.recv_timeout(Duration::from_secs(1)).ok())
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    let out = take(stdout);
    let err = take(stderr);
    if status.success() {
        Ok(out)
    } else {
        let said = err.lines().next().unwrap_or("").trim().to_string();
        Err(format!(
            "{name} failed ({status}){}",
            if said.is_empty() {
                String::new()
            } else {
                format!(": {said}")
            }
        ))
    }
}

/// The last `n` non-empty lines.
fn last_lines(text: &str, n: usize) -> Vec<String> {
    let lines: Vec<String> = text
        .lines()
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with("-- No entries --"))
        .map(|l| l.chars().take(1000).collect())
        .collect();
    let from = lines.len().saturating_sub(n);
    lines[from..].to_vec()
}

fn os_name(notes: &mut Vec<String>) -> String {
    for path in ["/etc/os-release", "/usr/lib/os-release"] {
        if let Ok(text) = fs::read_to_string(path)
            && let Some(name) = text.lines().find_map(|l| l.strip_prefix("PRETTY_NAME="))
        {
            return name.trim().trim_matches('"').to_string();
        }
    }
    notes.push("no PRETTY_NAME in /etc/os-release".into());
    String::new()
}

fn meminfo(notes: &mut Vec<String>) -> Memory {
    let Ok(text) = fs::read_to_string("/proc/meminfo") else {
        notes.push("cannot read /proc/meminfo".into());
        return Memory::default();
    };
    let field = |name: &str| -> u64 {
        text.lines()
            .find_map(|l| l.strip_prefix(name)?.strip_prefix(':'))
            .and_then(|v| v.split_whitespace().next()?.parse::<u64>().ok())
            .map_or(0, |kib| kib * 1024)
    };
    Memory {
        total: field("MemTotal"),
        available: field("MemAvailable"),
        swap_total: field("SwapTotal"),
        swap_free: field("SwapFree"),
    }
}

/// The online CPUs (`/sys/devices/system/cpu/online`, ranges like
/// `0-3,8-11`), else the ones this process may use.
fn cpus() -> u32 {
    let parsed = first_line("/sys/devices/system/cpu/online").and_then(|list| {
        let mut n = 0u32;
        for part in list.split(',') {
            if let Some((a, b)) = part.split_once('-') {
                let (a, b) = (a.parse::<u32>().ok()?, b.parse::<u32>().ok()?);
                n += b.checked_sub(a)? + 1;
            } else {
                part.parse::<u32>().ok()?;
                n += 1;
            }
        }
        Some(n)
    });
    parsed.filter(|&n| n > 0).unwrap_or_else(|| {
        std::thread::available_parallelism().map_or(1, |n| u32::try_from(n.get()).unwrap_or(1))
    })
}

/// A mount point as `/proc/self/mountinfo` escapes it (`\040` for a
/// space).
fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\'
            && i + 3 < bytes.len()
            && bytes[i + 1..i + 4]
                .iter()
                .all(|b| (b'0'..=b'7').contains(b))
        {
            let value =
                (bytes[i + 1] - b'0') * 64 + (bytes[i + 2] - b'0') * 8 + (bytes[i + 3] - b'0');
            out.push(value);
            i += 4;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Filesystem types that hold no data of their own.
const VIRTUAL: &[&str] = &[
    "proc",
    "sysfs",
    "cgroup",
    "cgroup2",
    "devpts",
    "devtmpfs",
    "mqueue",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "configfs",
    "fusectl",
    "hugetlbfs",
    "autofs",
    "binfmt_misc",
    "rpc_pipefs",
    "nsfs",
    "efivarfs",
    "selinuxfs",
    "ramfs",
    "squashfs",
    "fuse.snapfuse",
    "fuse.lxcfs",
    "fuse.gvfsd-fuse",
    "fuse.portal",
    "nfsd",
];

/// Whether a mount is a real filesystem to report.
fn reported(fs_type: &str, mount: &str) -> bool {
    if VIRTUAL.contains(&fs_type) || mount.starts_with("/snap/") {
        return false;
    }
    match fs_type {
        "tmpfs" => mount == "/tmp" || mount == "/dev/shm",
        // A container's root is an overlay; the overlays of other
        // containers on the machine are their lower directories.
        "overlay" => mount == "/",
        _ => true,
    }
}

/// One mount from a line of `/proc/self/mountinfo`: (device numbers,
/// mount point, type, source).
fn mount_line(line: &str) -> Option<(String, String, String, String)> {
    let (before, after) = line.split_once(" - ")?;
    let fields: Vec<&str> = before.split(' ').collect();
    let device = (*fields.get(2)?).to_string();
    let mount = unescape(fields.get(4)?);
    let mut after = after.split(' ');
    let fs_type = after.next()?.to_string();
    let source = unescape(after.next().unwrap_or(""));
    Some((device, mount, fs_type, source))
}

fn statvfs_bounded(mount: &str) -> Result<rustix::fs::StatVfs, String> {
    let (tx, rx) = mpsc::channel();
    let path = mount.to_string();
    std::thread::spawn(move || {
        let _ = tx.send(rustix::fs::statvfs(path.as_str()).map_err(|e| e.to_string()));
    });
    rx.recv_timeout(STATVFS_TIMEOUT)
        .map_err(|_| format!("no answer within {} s", STATVFS_TIMEOUT.as_secs()))?
}

fn disks(notes: &mut Vec<String>) -> Vec<Disk> {
    let Ok(text) = fs::read_to_string("/proc/self/mountinfo") else {
        notes.push("cannot read /proc/self/mountinfo".into());
        return Vec::new();
    };
    let mut seen = HashSet::new();
    let mut mounts: Vec<(String, String, String, String)> = text
        .lines()
        .filter_map(mount_line)
        .filter(|(_, mount, fs_type, _)| reported(fs_type, mount))
        .collect();
    // A bind mount shows a filesystem again: keep its shortest path.
    mounts.sort_by_key(|(_, mount, _, _)| (mount.len(), mount.clone()));
    let mut out = Vec::new();
    for (device, mount, fs_type, source) in mounts {
        if !seen.insert(device) {
            continue;
        }
        match statvfs_bounded(&mount) {
            Ok(st) => {
                let block = st.f_frsize.max(1);
                let total = st.f_blocks.saturating_mul(block);
                let free = st.f_bavail.saturating_mul(block);
                let used = st.f_blocks.saturating_sub(st.f_bfree);
                let usable = used + st.f_bavail;
                let used_pct = if usable == 0 {
                    0
                } else {
                    u8::try_from((used * 100).div_ceil(usable).min(100)).unwrap_or(100)
                };
                if total == 0 {
                    continue;
                }
                out.push(Disk {
                    mount,
                    fs: fs_type,
                    device: source,
                    total,
                    free,
                    used_pct,
                });
            }
            Err(e) => notes.push(format!("{mount}: {e}")),
        }
    }
    out.sort_by(|a, b| a.mount.cmp(&b.mount));
    out
}

/// An address of `/proc/net/{tcp,udp}[6]`: hex, each 32-bit word in the
/// machine's byte order.
fn address(hex: &str) -> Option<String> {
    let words: Vec<u32> = (0..hex.len() / 8)
        .map(|i| u32::from_str_radix(hex.get(i * 8..i * 8 + 8)?, 16).ok())
        .collect::<Option<_>>()?;
    match words.as_slice() {
        [w] => Some(std::net::Ipv4Addr::from(w.to_ne_bytes()).to_string()),
        [a, b, c, d] => {
            let mut bytes = [0u8; 16];
            for (i, w) in [a, b, c, d].iter().enumerate() {
                bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_ne_bytes());
            }
            Some(std::net::Ipv6Addr::from(bytes).to_string())
        }
        _ => None,
    }
}

/// The listening sockets of one `/proc/net` table: (address, port, inode).
fn sockets(text: &str, tcp: bool) -> Vec<(String, u16, u64)> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(local), Some(remote), Some(state), Some(inode)) =
            (fields.get(1), fields.get(2), fields.get(3), fields.get(9))
        else {
            continue;
        };
        // TCP: LISTEN. UDP: bound and not connected to a peer.
        let listening = if tcp {
            *state == "0A"
        } else {
            *state == "07" && remote.split(':').nth(1) == Some("0000")
        };
        if !listening {
            continue;
        }
        let Some((addr, port)) = local.split_once(':') else {
            continue;
        };
        let (Some(addr), Ok(port), Ok(inode)) = (
            address(addr),
            u16::from_str_radix(port, 16),
            inode.parse::<u64>(),
        ) else {
            continue;
        };
        out.push((addr, port, inode));
    }
    out
}

/// The processes holding each socket inode, as far as `/proc/<pid>/fd`
/// can be read (the daemon's own user's processes, all as root).
fn socket_owners(wanted: &HashSet<u64>) -> HashMap<u64, (u32, String)> {
    let mut owners = HashMap::new();
    if wanted.is_empty() {
        return owners;
    }
    let Ok(procs) = fs::read_dir("/proc") else {
        return owners;
    };
    for entry in procs.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|t| t.strip_suffix(']'))
                .and_then(|t| t.parse::<u64>().ok())
            else {
                continue;
            };
            if wanted.contains(&inode) && !owners.contains_key(&inode) {
                let name = first_line(&format!("/proc/{pid}/comm")).unwrap_or_default();
                owners.insert(inode, (pid, name));
            }
        }
        if owners.len() == wanted.len() {
            break;
        }
    }
    owners
}

fn listening(notes: &mut Vec<String>) -> Vec<Listening> {
    let mut found = Vec::new();
    for (file, proto) in [
        ("tcp", Proto::Tcp),
        ("tcp6", Proto::Tcp),
        ("udp", Proto::Udp),
        ("udp6", Proto::Udp),
    ] {
        match fs::read_to_string(format!("/proc/net/{file}")) {
            Ok(text) => found.extend(
                sockets(&text, proto == Proto::Tcp)
                    .into_iter()
                    .map(|s| (proto, s)),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => notes.push(format!("/proc/net/{file}: {e}")),
        }
    }
    let wanted: HashSet<u64> = found.iter().map(|(_, (_, _, inode))| *inode).collect();
    let owners = socket_owners(&wanted);
    let mut out: Vec<Listening> = found
        .into_iter()
        .map(|(proto, (address, port, inode))| {
            let owner = owners.get(&inode);
            Listening {
                proto,
                address,
                port,
                pid: owner.map(|(pid, _)| *pid),
                process: owner.map(|(_, name)| name.clone()),
            }
        })
        .collect();
    out.sort_by(|a, b| {
        (a.proto == Proto::Udp, a.port, &a.address).cmp(&(
            b.proto == Proto::Udp,
            b.port,
            &b.address,
        ))
    });
    out.dedup();
    out
}

fn failing_units(path: Option<&OsStr>, notes: &mut Vec<String>) -> Option<Vec<String>> {
    let systemctl = find_program("systemctl", path)?;
    if !Path::new("/run/systemd/system").is_dir() {
        notes.push("systemctl is installed but systemd does not run".into());
        return None;
    }
    match run(
        &systemctl,
        &["--failed", "--plain", "--no-legend", "--no-pager"],
    ) {
        Ok(out) => Some(
            out.lines()
                .filter_map(|l| l.split_whitespace().next().map(str::to_string))
                .collect(),
        ),
        Err(e) => {
            notes.push(e);
            None
        }
    }
}

/// Up to [`KMSG_RECORDS`] records of `/dev/kmsg` at `err` or worse, without
/// blocking.
fn kmsg_errors() -> Result<Vec<String>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::fcntl::OFlag::O_NONBLOCK.bits())
        .open("/dev/kmsg")
        .map_err(|e| format!("/dev/kmsg: {e}"))?;
    let mut lines = Vec::new();
    let mut buf = vec![0u8; 8192];
    for _ in 0..KMSG_RECORDS {
        // One record per read; EAGAIN at the end.
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.raw_os_error() == Some(nix::libc::EPIPE) => continue,
            Err(_) => break,
        };
        let record = String::from_utf8_lossy(&buf[..n]);
        let Some((head, message)) = record.split_once(';') else {
            continue;
        };
        let level = head
            .split(',')
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .map_or(7, |p| p & 7);
        if level <= 3 {
            lines.push(message.lines().next().unwrap_or("").to_string());
        }
    }
    let from = lines.len().saturating_sub(ERRORS_KEPT);
    Ok(lines[from..].to_vec())
}

fn kernel_errors(path: Option<&OsStr>, notes: &mut Vec<String>) -> Vec<String> {
    let dmesg = find_program("dmesg", path).map(|dmesg| {
        run(&dmesg, &["--level=emerg,alert,crit,err", "--nopager"])
            .map(|out| last_lines(&out, ERRORS_KEPT))
    });
    match dmesg {
        Some(Ok(lines)) => lines,
        other => match kmsg_errors() {
            Ok(lines) => lines,
            Err(kmsg) => {
                let why = match other {
                    Some(Err(e)) => format!("{e}; {kmsg}"),
                    _ => format!("no dmesg; {kmsg}"),
                };
                notes.push(format!(
                    "the kernel's messages are not readable here ({why})"
                ));
                Vec::new()
            }
        },
    }
}

fn journal_errors(path: Option<&OsStr>, notes: &mut Vec<String>) -> Vec<String> {
    let Some(journalctl) = find_program("journalctl", path) else {
        notes.push("no journalctl: no journal errors".into());
        return Vec::new();
    };
    match run(
        &journalctl,
        &[
            "-p",
            "err",
            "-n",
            "20",
            "--no-pager",
            "-o",
            "short-iso",
            "-q",
        ],
    ) {
        Ok(out) => last_lines(&out, ERRORS_KEPT),
        Err(e) => {
            notes.push(e);
            Vec::new()
        }
    }
}

/// The machine's state. `path`: where commands are looked up (the
/// daemon's `PATH`).
#[must_use]
pub fn state(path: Option<&OsStr>) -> Machine {
    let mut notes = Vec::new();
    let uname = rustix::system::uname();
    let uptime_s = first_line("/proc/uptime")
        .and_then(|l| {
            l.split_whitespace()
                .next()?
                .split('.')
                .next()?
                .parse::<u64>()
                .ok()
        })
        .unwrap_or_else(|| {
            notes.push("cannot read /proc/uptime".into());
            0
        });
    let load = first_line("/proc/loadavg")
        .and_then(|l| {
            let mut it = l.split_whitespace().map(|v| v.parse::<f32>().ok());
            Some((it.next()??, it.next()??, it.next()??))
        })
        .unwrap_or_else(|| {
            notes.push("cannot read /proc/loadavg".into());
            (0.0, 0.0, 0.0)
        });
    let os = os_name(&mut notes);
    let memory = meminfo(&mut notes);
    let disks = disks(&mut notes);
    let listening = listening(&mut notes);
    let failing_units = failing_units(path, &mut notes);
    let kernel_errors = kernel_errors(path, &mut notes);
    let journal_errors = journal_errors(path, &mut notes);
    Machine {
        hostname: uname.nodename().to_string_lossy().into_owned(),
        os,
        kernel: uname.release().to_string_lossy().into_owned(),
        arch: uname.machine().to_string_lossy().into_owned(),
        uptime_s,
        load,
        cpus: cpus(),
        memory,
        disks,
        listening,
        failing_units,
        kernel_errors,
        journal_errors,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses() {
        assert_eq!(address("0100007F").as_deref(), Some("127.0.0.1"));
        assert_eq!(address("00000000").as_deref(), Some("0.0.0.0"));
        assert_eq!(
            address("00000000000000000000000001000000").as_deref(),
            Some("::1")
        );
        assert_eq!(address("zz"), None);
        assert_eq!(address(""), None);
    }

    #[test]
    fn socket_tables() {
        let tcp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F91 0100007F:9C40 01 00000000:00000000 00:00000000 00000000  1000        0 12346 1 0000000000000000 100 0 0 10 0
garbage";
        assert_eq!(
            sockets(tcp, true),
            vec![("127.0.0.1".to_string(), 8080, 12345)]
        );
        let udp = "header
   0: 00000000:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 999 2 0000000000000000 0";
        assert_eq!(sockets(udp, false), vec![("0.0.0.0".to_string(), 68, 999)]);
    }

    #[test]
    fn mounts() {
        let line = "36 35 98:0 /mnt1 /mnt/with\\040space rw,noatime master:1 - ext4 /dev/sda1 rw,errors=continue";
        assert_eq!(
            mount_line(line),
            Some((
                "98:0".into(),
                "/mnt/with space".into(),
                "ext4".into(),
                "/dev/sda1".into()
            ))
        );
        assert!(reported("ext4", "/"));
        assert!(reported("tmpfs", "/tmp"));
        assert!(!reported("tmpfs", "/run"));
        assert!(!reported("proc", "/proc"));
        assert!(reported("overlay", "/"));
        assert!(!reported("overlay", "/var/lib/docker/overlay2/x/merged"));
        assert!(!reported("squashfs", "/snap/core/1"));
        assert_eq!(mount_line("junk"), None);
    }

    #[test]
    fn a_missing_program_is_none() {
        let empty = tempfile::tempdir().unwrap();
        let path = empty.path().as_os_str();
        let mut notes = Vec::new();
        assert_eq!(failing_units(Some(path), &mut notes), None);
        assert!(journal_errors(Some(path), &mut notes).is_empty());
        assert!(notes.iter().any(|n| n.contains("journalctl")), "{notes:?}");
    }

    #[test]
    fn a_command_is_bounded() {
        let out = run(Path::new("/bin/sh"), &["-c", "echo $LC_ALL"]).unwrap();
        assert_eq!(out.trim(), "C");
        let e = run(Path::new("/bin/sh"), &["-c", "echo oops >&2; exit 3"]).unwrap_err();
        assert!(e.contains("oops"), "{e}");
        let big = run(Path::new("/bin/sh"), &["-c", "head -c 1000000 /dev/zero"]).unwrap();
        assert_eq!(big.len(), OUTPUT_CAP);
    }
}
