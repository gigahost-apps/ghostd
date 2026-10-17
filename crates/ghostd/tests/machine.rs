//! `MachineState`: the machine in one answer, never failing as a whole.

mod common;

use std::net::TcpListener;

use common::Env;
use ghostd_client::Connection;
use ghostd_protocol::v2::{Machine, Proto, Request, Response};

async fn state(c: &Connection) -> Machine {
    match c.call(Request::MachineState).await.unwrap() {
        Response::Machine(machine) => *machine,
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn the_machine_in_one_answer() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let m = state(&c).await;
    assert!(!m.hostname.is_empty());
    assert!(!m.kernel.is_empty());
    assert_eq!(m.arch, std::env::consts::ARCH);
    assert!(m.cpus >= 1);
    assert!(m.uptime_s > 0);
    assert!(m.memory.total > 0 && m.memory.available <= m.memory.total);
    assert!(
        m.disks.iter().any(|d| d.total > 0 && d.used_pct <= 100),
        "{:?}",
        m.disks
    );
    assert!(m.disks.iter().all(|d| d.fs != "proc" && d.fs != "sysfs"));
    let ours = m
        .listening
        .iter()
        .find(|l| l.port == port && l.proto == Proto::Tcp)
        .unwrap_or_else(|| panic!("port {port} not listed: {:?}", m.listening));
    assert_eq!(ours.address, "127.0.0.1");
    assert_eq!(ours.pid, Some(std::process::id()));
    assert!(ours.process.is_some());
    assert!(m.kernel_errors.len() <= 20 && m.journal_errors.len() <= 20);
    drop(listener);
}

#[tokio::test]
async fn missing_commands_are_notes_not_errors() {
    let mut env = Env::new();
    let empty = env.dir.path().join("empty-bin");
    std::fs::create_dir(&empty).unwrap();
    env.path = Some(empty);
    let c = env.connect_v2().await;
    let m = state(&c).await;
    assert_eq!(m.failing_units, None);
    assert!(m.journal_errors.is_empty());
    assert!(
        m.notes.iter().any(|n| n.contains("journalctl")),
        "{:?}",
        m.notes
    );
    assert!(m.memory.total > 0);
}
