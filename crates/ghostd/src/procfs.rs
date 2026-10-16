//! Process facts from `/proc`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The fields of `/proc/<pid>/stat` after the command name.
fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let text = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = &text[text.rfind(')')? + 1..];
    Some(after.split_whitespace().map(str::to_string).collect())
}

/// A process's start time (clock ticks since boot), to tell it from a
/// later process that reuses its pid.
#[must_use]
pub fn start_time(pid: u32) -> Option<u64> {
    // Field 22 overall; the list starts at field 3.
    stat_fields(pid)?.get(19)?.parse().ok()
}

/// Whether `pid` is the process that started at `start` (and not a zombie).
#[must_use]
pub fn is_same_process(pid: u32, start: u64) -> bool {
    match stat_fields(pid) {
        Some(fields) => {
            fields.first().is_some_and(|s| s != "Z")
                && fields.get(19).and_then(|s| s.parse::<u64>().ok()) == Some(start)
        }
        None => false,
    }
}

/// Whether a `ghostd shim <dir>` process runs for this job directory (its
/// command line names it).
#[must_use]
pub fn shim_runs_for(dir: &Path) -> bool {
    let Ok(entries) = fs::read_dir("/proc") else {
        return false;
    };
    let dir = dir.as_os_str().as_bytes();
    entries.flatten().any(|entry| {
        let is_pid = entry
            .file_name()
            .to_str()
            .is_some_and(|n| n.bytes().all(|b| b.is_ascii_digit()));
        is_pid
            && fs::read(entry.path().join("cmdline")).is_ok_and(|cmdline| {
                let mut args = cmdline.split(|&b| b == 0).skip(1);
                args.next() == Some(b"shim".as_slice()) && args.next() == Some(dir)
            })
    })
}

struct Entry {
    ppid: u32,
    pgid: u32,
    sid: u32,
    zombie: bool,
}

/// A process's parent, group, session and whether it is a zombie.
fn entry(pid: u32) -> Option<Entry> {
    let fields = stat_fields(pid)?;
    Some(Entry {
        ppid: fields.get(1)?.parse().ok()?,
        pgid: fields.get(2)?.parse().ok()?,
        sid: fields.get(3)?.parse().ok()?,
        zombie: fields.first().is_some_and(|s| s == "Z"),
    })
}

#[cfg(test)]
thread_local! {
    /// How often this thread read every process's entry.
    pub static FULL_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Every process's parent, group, session and whether it is a zombie.
fn table() -> HashMap<u32, Entry> {
    #[cfg(test)]
    FULL_READS.with(|n| n.set(n.get() + 1));
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for dirent in entries.flatten() {
        let Some(pid) = dirent
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(entry) = entry(pid) {
            map.insert(pid, entry);
        }
    }
    map
}

/// A process below another one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Descendant {
    pub pid: u32,
    pub pgid: u32,
    /// Its session: a process that called `setsid` (a daemon) has its own.
    pub sid: u32,
}

/// The processes below `root` (children, their children…), zombies left
/// out, found by walking parent links.
#[must_use]
pub fn descendants(root: u32) -> Vec<Descendant> {
    let table = table();
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    for (&pid, entry) in &table {
        children.entry(entry.ppid).or_default().push(pid);
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    while let Some(pid) = stack.pop() {
        if let Some(kids) = children.get(&pid) {
            for &kid in kids {
                if kid != root && seen.insert(kid) {
                    if let Some(entry) = table.get(&kid)
                        && !entry.zombie
                    {
                        out.push(Descendant {
                            pid: kid,
                            pgid: entry.pgid,
                            sid: entry.sid,
                        });
                    }
                    stack.push(kid);
                }
            }
        }
    }
    out
}

/// Whether the kernel lists each thread's children in
/// `/proc/<pid>/task/<tid>/children` (`CONFIG_PROC_CHILDREN`, which the
/// common distributions' kernels have).
#[must_use]
pub fn has_children_lists() -> bool {
    let me = std::process::id();
    Path::new(&format!("/proc/{me}/task/{me}/children")).exists()
}

/// Adds the children of every thread of `pid` to `out`.
fn children(pid: u32, out: &mut Vec<u32>) {
    let Ok(tasks) = fs::read_dir(format!("/proc/{pid}/task")) else {
        return;
    };
    for task in tasks.flatten() {
        if let Ok(list) = fs::read_to_string(task.path().join("children")) {
            out.extend(
                list.split_ascii_whitespace()
                    .filter_map(|p| p.parse::<u32>().ok()),
            );
        }
    }
}

/// The processes below `root`, zombies left out, found by reading the
/// children lists down from `root`: it reads the subtree only, where
/// [`descendants`] reads every process on the machine. The kernel does
/// not promise a list is complete while processes come and go, so this is
/// for counting: never conclude from it that nothing is left. Empty
/// without [`has_children_lists`].
#[must_use]
pub fn subtree(root: u32) -> Vec<Descendant> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut stack = vec![root];
    let mut kids = Vec::new();
    while let Some(parent) = stack.pop() {
        kids.clear();
        children(parent, &mut kids);
        for &kid in &kids {
            if kid == root || !seen.insert(kid) {
                continue;
            }
            // Its parent now: a process that ended meanwhile may have
            // left its pid to an unrelated one.
            let Some(entry) = entry(kid).filter(|e| e.ppid == parent) else {
                continue;
            };
            if !entry.zombie {
                out.push(Descendant {
                    pid: kid,
                    pgid: entry.pgid,
                    sid: entry.sid,
                });
            }
            stack.push(kid);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_start_time_is_stable() {
        let me = std::process::id();
        let t = start_time(me).unwrap();
        assert!(is_same_process(me, t));
        assert!(!is_same_process(me, t + 1));
    }

    #[test]
    fn finds_a_child() {
        let mut child = std::process::Command::new("sleep")
            .arg("5")
            .spawn()
            .unwrap();
        assert!(
            descendants(std::process::id())
                .iter()
                .any(|d| d.pid == child.id())
        );
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn the_subtree_has_what_the_full_scan_finds() {
        if !has_children_lists() {
            eprintln!("skipped: this kernel has no /proc/<pid>/task/<tid>/children");
            return;
        }
        let mut shell = std::process::Command::new("sh")
            .args(["-c", "sleep 7 & sleep 7 & wait"])
            .spawn()
            .unwrap();
        let pid = shell.id();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while descendants(pid).len() < 2 {
            assert!(
                std::time::Instant::now() < until,
                "the shell started no two"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let mut by_table = descendants(pid);
        let mut by_children = subtree(pid);
        by_table.sort_by_key(|d| d.pid);
        by_children.sort_by_key(|d| d.pid);
        assert_eq!(by_children, by_table);
        assert_eq!(by_table.len(), 2);
        // From further up too: the shell and both of its children.
        let ours = subtree(std::process::id());
        assert!(ours.iter().any(|d| d.pid == pid));
        assert!(by_table.iter().all(|d| ours.contains(d)));
        for d in &by_table {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(i32::try_from(d.pid).unwrap()),
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        shell.wait().unwrap();
    }
}
