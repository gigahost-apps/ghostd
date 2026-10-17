//! The host ID: made once, kept across restarts, checked before anything
//! runs.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Env, sh};
use ghostd_client::{ClientError, Connection, Options};
use ghostd_protocol::v1::{self, Outcome};
use ghostd_protocol::v2::{ErrorKind, HostId, Identity, Request, Response};

async fn identify(c: &Connection) -> Identity {
    match c.call(Request::Identify).await.unwrap() {
        Response::Identity(identity) => identity,
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test]
async fn made_once_and_kept_across_restarts() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let first = identify(&c).await;
    assert_eq!(first.program_version, env!("CARGO_PKG_VERSION"));
    assert_eq!(first.uid, nix::unistd::getuid().as_raw());
    assert!(!first.hostname.is_empty());
    let file = env.state.join("host-id");
    assert_eq!(
        std::fs::read_to_string(&file).unwrap(),
        format!("{}\n", first.host_id)
    );
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(c);

    // A worker killed and restarted by the daemon.
    let workers = env.processes("worker");
    assert_eq!(workers.len(), 1);
    common::signal(workers[0], 9);
    common::wait_gone(workers[0]);
    env.wait_for("a new worker", || {
        env.processes("worker").iter().any(|&w| w != workers[0])
    });
    let c = env.connect_v2().await;
    assert_eq!(identify(&c).await.host_id, first.host_id);
    drop(c);

    // The daemon stopped and started again.
    env.stop();
    let c = env.connect_v2().await;
    assert_eq!(identify(&c).await.host_id, first.host_id);
    drop(c);

    // A new ghostd state: a new machine as far as clients can tell.
    env.stop();
    std::fs::remove_dir_all(&env.state).unwrap();
    let c = env.connect_v2().await;
    assert_ne!(identify(&c).await.host_id, first.host_id);
}

#[tokio::test]
async fn a_request_for_another_host_runs_nothing() {
    let env = Env::new();
    let c = env.connect_v2().await;
    let ours = identify(&c).await.host_id;
    let marker = env.home.join("ran");
    let touch = || v1::Request::Exec(sh("touch ran"));

    c.set_expected_host(Some(HostId([0; 16])));
    let e = c.call(touch()).await.unwrap_err();
    let ClientError::Remote(remote) = &e else {
        panic!("not a remote error: {e}");
    };
    assert_eq!(remote.kind, ErrorKind::HostMismatch);
    assert!(remote.message.contains(&ours.to_string()), "{remote}");
    assert!(remote.message.contains(&"0".repeat(32)), "{remote}");
    // Also a version 2 request, and one per call.
    let e = c.call(Request::MachineState).await.unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::HostMismatch),
        "{e}"
    );
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!marker.exists(), "the exec ran on the wrong host");
    assert!(
        std::fs::read_dir(env.state.join("jobs"))
            .unwrap()
            .next()
            .is_none(),
        "a job was created"
    );

    // The right ID runs it, and so does none.
    c.set_expected_host(Some(ours));
    let v1::Response::Exec(r) = c.call(touch()).await.unwrap() else {
        panic!("no exec result");
    };
    assert_eq!(r.outcome, Outcome::Exited { code: 0 });
    assert!(marker.exists());
    std::fs::remove_file(&marker).unwrap();
    c.set_expected_host(None);
    c.call(touch()).await.unwrap();
    assert!(marker.exists());
    let e = c
        .call_expecting(touch(), Some(HostId([1; 16])))
        .await
        .unwrap_err();
    assert!(
        matches!(&e, ClientError::Remote(r) if r.kind == ErrorKind::HostMismatch),
        "{e}"
    );
}

#[tokio::test]
async fn an_unreadable_host_id_refuses_only_what_expects_one() {
    let env = Env::new();
    std::fs::create_dir_all(&env.state).unwrap();
    let file = env.state.join("host-id");
    std::fs::write(&file, "junk\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let marker = env.home.join("ran");
    let touch = || v1::Request::Exec(sh("touch ran"));

    // The daemon serves: Identify says what is wrong.
    let c = env.connect_v2().await;
    let e = c.call(Request::Identify).await.unwrap_err();
    let ClientError::Remote(remote) = &e else {
        panic!("not a remote error: {e}");
    };
    assert_eq!(remote.kind, ErrorKind::Io, "{remote}");
    assert!(remote.message.contains("host-id"), "{remote}");
    assert!(remote.message.contains("remove it"), "{remote}");

    // A request that expects a host is refused and runs nothing.
    c.set_expected_host(Some(HostId([7; 16])));
    let e = c.call(touch()).await.unwrap_err();
    let ClientError::Remote(remote) = &e else {
        panic!("not a remote error: {e}");
    };
    assert_eq!(remote.kind, ErrorKind::HostMismatch, "{remote}");
    assert!(remote.message.contains("cannot read"), "{remote}");
    assert!(remote.message.contains(&"07".repeat(16)), "{remote}");
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(!marker.exists(), "an unchecked request ran");

    // One that expects none runs, and so does a version 1 client's.
    c.set_expected_host(None);
    c.call(touch()).await.unwrap();
    assert!(marker.exists());
    let old = env
        .try_connect(Options {
            max: 1,
            ..Options::default()
        })
        .await
        .unwrap();
    assert_eq!(old.version(), 1);
    assert_eq!(
        old.call(v1::Request::Ping).await.unwrap(),
        v1::Response::Pong
    );
    // The file is never replaced.
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "junk\n");

    // Removed (through the daemon itself), the next request that needs an
    // ID makes one, without a restart.
    let rm = sh(&format!("rm '{}'", file.display()));
    let v1::Response::Exec(r) = c.call(v1::Request::Exec(rm)).await.unwrap() else {
        panic!("no exec result");
    };
    assert_eq!(r.outcome, Outcome::Exited { code: 0 });
    assert!(!file.exists());
    let id = identify(&c).await.host_id;
    assert_eq!(std::fs::read_to_string(&file).unwrap(), format!("{id}\n"));
    c.set_expected_host(Some(id));
    c.call(v1::Request::Ping).await.unwrap();
}
