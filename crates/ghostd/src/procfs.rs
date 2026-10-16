//! Process facts from `/proc`.

use std::collections::HashMap;
use std::fs;

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

struct Entry {
    ppid: u32,
    pgid: u32,
    sid: u32,
    zombie: bool,
}

/// Every process's parent, group, session and whether it is a zombie.
fn table() -> HashMap<u32, Entry> {
    let mut map = HashMap::new();
    let Ok(entries) = fs::read_dir("/proc") else {
        return map;
    };
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if let Some(fields) = stat_fields(pid)
            && let Some(ppid) = fields.get(1).and_then(|p| p.parse::<u32>().ok())
            && let Some(pgid) = fields.get(2).and_then(|p| p.parse::<u32>().ok())
            && let Some(sid) = fields.get(3).and_then(|p| p.parse::<u32>().ok())
        {
            let zombie = fields.first().is_some_and(|s| s == "Z");
            map.insert(
                pid,
                Entry {
                    ppid,
                    pgid,
                    sid,
                    zombie,
                },
            );
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
    let mut seen = std::collections::HashSet::new();
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
}
