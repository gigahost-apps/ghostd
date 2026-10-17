# ghostd

A daemon on a Linux machine for AI agents to work on it: commands as
argument arrays with structured results, jobs that outlive the connection,
file reads, writes and edits, terminal sessions read as screens, waits done
on the machine and its state in one call, reached over the machine's own
SSH with no quoting and one kept connection.

It is one binary that needs no service manager:
`ghostd stdio`, the command a client runs over the user's own SSH access,
starts the daemon when none runs. ghostd never reads or changes anything
under `~/.ssh`. Jobs run under their own supervisor process, so they survive the
connection, the daemon's restarts and its crashes, and stopping one kills
everything it started. No process is leaked: what a command leaves behind
in the background is stopped when it ends, so a server is started as a job
(see [Background processes](#background-processes)). See [the protocol](docs/protocol.md).

## Install from source

On the machine (Linux, x86_64 or aarch64), from a checkout:

```sh
git clone https://github.com/gigahost-apps/ghostd
sh ghostd/install.sh
```

or piped from a tag (it builds the latest tag unless `--ref` names one;
when GitHub's API cannot be asked for the tags, it stops and asks for
`--ref`):

```sh
curl -fsSL https://raw.githubusercontent.com/gigahost-apps/ghostd/<tag>/install.sh | sh -s --
```

`install.sh` needs a C compiler, and curl (or wget) and tar when it
downloads. It never runs a package manager: when something is missing it
says what to install. When cargo is missing it installs
[rustup](https://rustup.rs) for the user, after saying so (`--no-rustup`
stops instead). It builds a static binary for musl
(`<arch>-unknown-linux-musl`, the target added through rustup), as CI does,
with `cargo build --release --locked` on the toolchain pinned in
`rust-toolchain.toml` (a Rust without rustup and without that target
builds for the host's C library, and says so), installs
`~/.local/bin/ghostd` (`/usr/local/bin/ghostd` as root, or `--prefix`),
then runs `ghostd setup`, which creates the directories and a commented
configuration file and records where the binary came from.

## Connect

A client connects with the SSH access the user already has, running the
fixed command

```sh
ssh -T host /home/you/.local/bin/ghostd stdio [--client <label>]
```

by its full path, because a non-login `ssh host cmd` does not read
`~/.profile` and may not have `~/.local/bin` on `PATH`. `--client` names
the client in the daemon's log. Output a login shell prints first is
skipped: `ghostd` opens with a fixed marker and the client discards what
comes before it.

From Rust, `ghostd-client`:

```rust
let c = ghostd_client::Connection::spawn(&["ssh", "-T", "host", "/home/you/.local/bin/ghostd", "stdio"]).await?;
let answer = c.call(Request::Exec(ExecSpec {
    program: Program::Argv(vec![b"ls".to_vec(), b"-la".to_vec()]),
    ..ExecSpec::default()
})).await?;
```

## Background processes

No process is leaked. A plain background process (`cmd &`, `nohup cmd &`)
does not outlive an `Exec`: what the program leaves in its session is
stopped when it ends, and the result says how many were (`stopped`). To
keep a server running, start it with `JobStart`: then what the program
leaves in the background belongs to the job, which lives until none of it
is left, and `JobStop` (or the job's timeout) stops it all. A process that
detaches into a session of its own (`setsid`, a daemon's own forking, as
`pg_ctl start` or `nginx` do) is left running when the program ends and is not
waited for (a stop or timeout before the job finishes takes the whole tree,
detached processes included), and a service started with `systemctl start` is systemd's, not the
job's.

## Sessions

A session is a program on a terminal (PTY) of its own: a shell, a REPL,
`top`, an installer that asks questions. It is read as a screen in text
(with the cursor, the title, whether a full-screen program switched to the
alternate screen, and up to 1000 lines of scrollback) and typed into as
text, bytes or named keys (`Enter`, `Ctrl('c')`, the arrows, `F1`–`F12`).
A read can wait until the screen changes, a regex matches it or the
program exits. Like a job, a session runs under its own supervisor
process: it survives the connection and the daemon's crashes and is found
again by its ID; closing it stops everything it started, and when its
program exits what it left in the background is stopped. Its final screen
and its raw output are kept until it is collected. At most 32 run at once
(`max_sessions`).

## Waits and the machine's state

`Wait` waits on the machine, so one request replaces a polling loop: until
a port accepts connections, an `http://` URL answers a status, a file
appears or holds a regex, a job's or a session's output matches, a
process, a job or a session ends, up to a timeout (at most 5 minutes).
`MachineState` answers the system, uptime, load, memory, disks, listening
ports with their processes, failing systemd units and the kernel's and
the journal's recent errors in one call; a part that cannot be read is a
note, never a failure.

## The host ID

The daemon makes a random host ID the first time it starts and keeps it in
`<state>/host-id`. It stays across restarts, updates and reboots, and
changes only with the machine or its ghostd state (a reinstall, a swapped
disk, another machine behind the same name or address, another user's
daemon). A client that kept it sends it with its requests: a daemon with
another ID answers `HostMismatch` and runs nothing, so a request never
lands on the wrong machine. Remove the file only to make the machine a new
one: every client that knew the old ID refuses it until it forgets it.

## Commands

| Command | |
|---|---|
| `ghostd stdio [--client <label>]` | Relay stdin and stdout to the daemon, starting it when none runs. |
| `ghostd setup` | Create the directories and a commented configuration file. |
| `ghostd status` | JSON: whether the daemon runs, its pid and version, the socket, job counts. |
| `ghostd stop` | Stop the daemon; jobs keep running. The next `ghostd stdio` starts it again. |
| `ghostd daemon` | Run the supervisor in the foreground of a new session (what `ghostd stdio` starts). |
| `ghostd --version` | |

## Where things live

| | As a user | As root |
|---|---|---|
| State: jobs, sessions, logs, `ghostd.log`, `install.json`, `host-id` | `$XDG_STATE_HOME/ghostd` (`~/.local/state/ghostd`) | `/var/lib/ghostd` |
| Socket, lock and pid file | `$XDG_RUNTIME_DIR/ghostd`, else `<state>/run` | `/run/ghostd` |
| Configuration | `$XDG_CONFIG_HOME/ghostd/config.toml` (`~/.config/ghostd/config.toml`) | `/etc/ghostd/config.toml` |

`GHOSTD_STATE_DIR`, `GHOSTD_RUNTIME_DIR` and `GHOSTD_CONFIG` override them.
The directories are 0700 and the socket 0600, and the daemon accepts only
connections from its own user. One daemon runs per user, as that user; jobs
run as that user. `ghostd setup` writes the configuration file with every
key and its default, commented out.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
