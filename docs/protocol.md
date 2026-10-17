# The ghostd protocol

A client talks to `ghostd` over one byte stream: the stdin and stdout of
`ghostd stdio`, usually the channel of an SSH connection with the user's
own access that runs it by its full path
(`ssh -T host /home/you/.local/bin/ghostd stdio`). Nothing in the stream is ever parsed by a shell:
arguments, paths and data travel inside length-prefixed binary frames as
bytes.

The Rust types are the reference: `crates/ghostd-protocol`. The client
crate `crates/ghostd-client` implements everything on this page.

## Frames

A frame is a big-endian `u32` length followed by that many bytes of
[postcard](https://docs.rs/postcard). The largest frame is 16 MiB
(`MAX_FRAME`); a receiver checks the length against the cap before it
allocates anything, and a longer length is a protocol error. Hellos and the
relay preamble are capped at 64 KiB.

A frame holds exactly one message: bytes left over after it are an error.

## Opening

1. The server writes the 16-byte **marker**
   `00 ff 67 68 6f 73 74 64 2d 68 65 6c 6c 6f 00 01` (`\0\xffghostd-hello\0\x01`),
   then a `ServerHello` frame. It does so first on every connection.
2. The client discards everything before the marker: a login shell's
   banner, a message of the day, `command not found`. It gives up after
   1 MiB without a marker, or at the end of the stream, and reports the
   first 200 discarded bytes (and, for a spawned command, its stderr).
3. The client sends a `ClientHello` frame.
4. The server answers with a `HelloAnswer` frame: `Welcome { version }`,
   the highest version both ranges hold, or `Refused { server_min,
   server_max, message }`, after which it closes the connection. The
   client also checks that the welcomed version is in its own range.

When the ranges do not overlap, the side whose maximum is lower is the
one to update; both sides say so.

### The frozen messages

These never change, in any version, so that any client and any server can
always tell each other what they speak:

| Message | Fields |
|---|---|
| `ServerHello` | `program_version: String, min: u32, max: u32` |
| `ClientHello` | `program_version: String, min: u32, max: u32` |
| `HelloAnswer` | `Welcome { version: u32 }` or `Refused { server_min: u32, server_max: u32, message: String }` |
| `RelayInfo` | `client_label: Option<String>, ssh_connection: Option<String>` |

`RelayInfo` is the relay preamble: the first frame `ghostd stdio` writes to
the daemon's Unix socket, before any of the client's bytes. It carries the
relay's `--client <label>` and `$SSH_CONNECTION`. A client never
sees or sends it.

## Versioning

- Any change to any message after the hellos, however small, is a new
  protocol version: a new module (`v2`) that reuses the unchanged types of
  the older one, with `PROTOCOL_MAX` raised.
- A server keeps speaking older versions for a support window, then raises
  `PROTOCOL_MIN`.
- There is no schema exchange and there are no unknown fields: postcard
  carries neither field names nor tags beyond enum variant indexes, so a
  message is only ever decoded by the version that defined it.
- Each request knows the lowest version that has it
  (`Request::min_version`); a client refuses to send a request newer than
  the agreed version instead of letting the server misread it.

This build speaks versions 1 and 2 (`PROTOCOL_MIN = 1`, `PROTOCOL_MAX =
2`). A connection agreed at version 1 behaves exactly as ghostd 0.1 did.

## Version 1

The client sends `ClientFrame::Request { id: u64, body: Request }`; the
server answers `ServerFrame::Response { id, result: Result<Response,
Error> }`. Requests run concurrently and answers may come in any order: the
`id` pairs them. The one exception is uploads: `UploadChunk`, `UploadEnd`
and `UploadAbort` run one at a time in the order they arrive on the
connection, so a client may send an upload's chunks without waiting for
each answer. At most 64 requests are in flight per connection; more
are answered `Busy`. A frame the server cannot decode is answered
`ServerFrame::ProtocolError { message }` and the connection is closed.

`Error { kind, message, os_code }`, `kind` one of `NotFound`,
`PermissionDenied`, `AlreadyExists`, `InvalidArgument`, `TooLarge`,
`Conflict`, `Busy`, `Io`, `Unsupported`, `Internal`; `os_code` is the
`errno` when a system call failed.

Everything a Unix system may hold as non-UTF-8 bytes (arguments,
environment names and values, paths, file contents, output) is bytes.
A relative path is relative to `$HOME`. There is no sandbox: the daemon
acts as its user. A single data field (a read, a write, an upload chunk, a
log slice) is at most 8 MiB.

### Programs

`ExecSpec { program, stdin, env, env_remove, env_clear, cwd, login,
timeout_ms, output_cap, keep_on_timeout, name, job_id }`:

- `program`: `Argv([argv0, args…])` (non-empty; `argv0` without a slash is
  looked up in `$PATH`), or `Script { body, interpreter, args }`: the body
  is written to a file and run with `interpreter` (default: its `#!` line
  when it has one, else `/bin/sh`) followed by `args`.
- The environment is the daemon's, then `env_clear`, `env_remove`, `env`.
- `cwd` defaults to `$HOME`.
- `login: true` runs it through the user's login shell without parsing:
  `[$SHELL, "-lc", "exec \"$0\" \"$@\"", argv…]`, the arguments as
  positional parameters.
- `stdin`: bytes for the program's stdin, else `/dev/null`.
- `job_id`: the job's ID chosen by the client, `j` and 16 random lowercase
  hex digits (else the server chooses one); see [Retries](#retries).

Every program runs as a job under its own shim, in its own process group.
Stopping one (a stop, a timeout) sends SIGTERM to its group and to every
process below the shim, waits the grace, then SIGKILLs what remains until
nothing below the shim is left, including processes that left the group or
started their own session.

No process is leaked. When the program ends by itself, what it left in
the job's session (background processes, `cmd &`, `nohup cmd &`, double
forks) depends on how it was started:

- `Exec`: they are stopped the same way half a second later, before the
  answer, and `ExecResult.stopped` counts them (0 normally). A plain
  background process does not outlive an `Exec`.
- `JobStart`: they belong to the job. The job lives as long as anything is
  left in its session; it finishes when none is left, or by `JobStop` or
  its timeout, which take the whole tree. So `JobStart(["sh", "-c",
  "nohup srv >log 2>&1 &"])` keeps `srv` as part of the job and `JobStop`
  stops it. `JobInfo.state` is the program's (`Exited` once it ended),
  `processes` counts what is left in the session and `finished` says the
  job is over. An `Exec` with `keep_on_timeout` answered at its timeout
  follows this rule from then on.

Either way a process that started a session of its own is left running
and is not waited for: daemons detach that way (`setsid`,
`start-stop-daemon --background`, `pg_ctl start`, a forking `nginx`,
`redis-server --daemonize yes`, `tmux new -d`, `screen -dm`), so that
`rc-service nginx start` or `pg_ctl start` works as an `Exec`. A detached
process is then init's, not the job's; it should not keep the job's stdout
or stderr open (daemons redirect them), since nothing reads them once the
shim is gone. A service started with `systemctl start` is systemd's child,
not the job's, so it runs on when the job ends. A stop or timeout before the job finishes takes the whole tree, detached processes included.

| Request | Answer | Notes |
|---|---|---|
| `Ping` | `Pong` | |
| `Exec(ExecSpec)` | `Exec(ExecResult)` | Runs to the end or `timeout_ms` (default 120 s, at most a day). `ExecResult { job_id, outcome, stdout, stderr, duration_ms, stopped }`; `outcome` `Exited { code }`, `Signaled { signal }`, `TimedOut { killed }` or `FailedToStart { message }`. Each `Output { data, offset, total }` holds the last `output_cap` bytes (default 256 KiB, at most 8 MiB); `offset > 0` means the earlier bytes are in the job's log. `keep_on_timeout` leaves the program running as job `job_id` (`killed: false`). After `FailedToStart` no job is kept and `job_id` is empty. `stopped`: how many processes the program left in its session were stopped after it ended (see above). |
| `JobStart(ExecSpec)` | `JobStarted { job_id }` | `timeout_ms` (default none) stops the job; `output_cap` and `keep_on_timeout` do not apply. |
| `JobList { include_finished, limit }` | `Jobs([JobInfo])` | Newest first; `limit` 0 means 100. Without `include_finished`, the jobs not `finished`. |
| `JobStatus { job_id }` | `Job(JobInfo)` | `JobInfo { job_id, name, argv_summary, state, started_at_ms, ended_at_ms, stdout_total, stderr_total, pid, processes, finished }`, `state` the program's: `Running`, `Exited { code }`, `Signaled { signal }` or `Lost` (its shim vanished before the job finished, also after the program ended: what is left of the job may still run, and nothing watches, stops or kills it any more). `processes`: the processes still in the job's session, the program included (0 once finished). `finished`: none is left and the final state is written, or the job is `Lost`. |
| `JobWait { job_id, timeout_ms }` | `Job(JobInfo)` | When it is `finished`, or at the timeout (at most 60 s) with `finished: false`. |
| `JobLogRead { job_id, stream, offset, max_len }` | `LogSlice { data, offset, total, first_available, ended }` | `offset` `None` reads the last `max_len` bytes. Logs rotate per stream at `log_max_bytes`, one rotated file kept; `first_available` is the lowest offset still kept. `ended`: the job is `finished` and `total` is final. |
| `JobSignal { job_id, signal }` | `Done` | To the program's process group; `Conflict` once the program has ended (also while its leftovers keep the job unfinished: use `JobStop`). |
| `JobStop { job_id, grace_ms }` | `Job(JobInfo)` | Answers once everything the job started is gone. |
| `JobRemove { job_id }` | `Done` | `Busy` until it is `finished`. |

### Retries

An answer can be lost: the SSH connection drops, the laptop sleeps. A
client that wants to take a job up again, or to retry safely, chooses the
job's ID itself (`job_id`), so it knows the ID before any answer comes.
Then, on any connection:

- `JobStatus`, `JobWait`, `JobLogRead` or `JobStop` with that ID reach the
  job; `NotFound` means the request never arrived (or its program failed
  to start), so it can be sent again.
- Sending the same request again never runs the program twice: while the
  job is kept, a `JobStart` answers `JobStarted` with the job, and an
  `Exec` waits for the job the first one started and answers its result.
  A different request (or the other kind) under a kept job's ID is
  refused with `Conflict`. Two requests with one ID never both start: the
  job's directory is created once.

Once the job is removed (`JobRemove`, or collected after its retention)
its ID is free again.

### Files

| Request | Answer | Notes |
|---|---|---|
| `FileStat { path, follow }` | `Stat(Stat)` | `Stat { kind, size, mode, mtime_ms, uid, gid, link_target }`, `kind` `File`, `Dir`, `Symlink` or `Other`, `mode` the permission bits. |
| `FileRead { path, offset, len }` | `FileData { data, size, eof }` | `len` at most 8 MiB. |
| `FileWrite { path, data, mode, create_dirs }` | `Written { size, sha256 }` | Atomic: a temp file beside it, fsync, rename. Keeps an existing file's mode unless `mode` (new files 0644) and, as far as the daemon's user may, its owner, group, SELinux label, ACL and `user.*` attributes; a hard link to the old file keeps the old content. Writes through a symlink to its target. |
| `UploadBegin { path, mode, create_dirs }` | `Upload { handle }` | At most 16 open per connection. |
| `UploadChunk { handle, offset, data }` | `Done` | Offsets contiguous, else `InvalidArgument`; carried out in the order they arrive. |
| `UploadEnd { handle, sha256 }` | `Written { size, sha256 }` | Checks the hash when given (`Conflict` and discarded on a mismatch), then renames into place atomically, keeping what `FileWrite` keeps. |
| `UploadAbort { handle }` | `Done` | An unfinished upload's temp file is also removed when the connection ends. |
| `FileEdit { path, old, new, replace_all }` | `Edited { replacements, sha256 }` | `NotFound` when `old` is absent, `Conflict` when it occurs more than once without `replace_all`. Atomic, keeping what `FileWrite` keeps. |
| `FileList { path, depth, max_entries }` | `Listing { entries, truncated }` | `entries` `(relative path, Stat)`, depth first, each directory sorted by name, hidden files included, symlinks not followed. `depth` 1..=16 (0 means 1), `max_entries` default 1000, at most 100 000. `truncated` also when an entry cannot be read (in a directory readable but not searchable). |
| `FileSearch { pattern, path, globs, case_insensitive, hidden, max_matches }` | `Matches { matches, truncated }` | A regex with ripgrep's defaults: `.gitignore` (in a git repository) and `.ignore` respected, binary files skipped, hidden files only with `hidden`. `globs` as ripgrep's `-g`. Each match `{ path (relative to the searched path), line_number, line (at most 4 KiB) }`; `max_matches` default 200, at most 10 000. |
| `FileHash { path }` | `Hash { size, sha256 }` | |
| `FileRemove { path, recursive }` | `Done` | A recursive removal of `/` or `$HOME` is refused. |
| `FileRename { from, to, overwrite }` | `Done` | Without `overwrite`, an existing `to` is refused atomically (`AlreadyExists`). |
| `FileMkdir { path, parents, mode }` | `Done` | Default mode 0755. |

An answer that would not fit a frame (a huge listing) is replaced by a
`TooLarge` error; listings and searches stop at about 12 MiB and say
`truncated`.

## Version 2

Version 2 is version 1 plus the host ID check, sessions (persistent
PTYs), waits and the machine's state. Version 1's requests travel wrapped
and keep their types and their meaning; their bytes are version 1's,
after one variant index.

- The client sends `ClientFrame::Request { id: u64, expected_host:
  Option<HostId>, body: Request }`; the server answers `ServerFrame` as in
  version 1, with version 2's `Response` and `Error`.
- `Request` is `V1(v1::Request)` (answered `Response::V1(v1::Response)`)
  or one of the requests below.
- `Error { kind, message, os_code }`, `kind` version 1's kinds, in the same
  order, then `HostMismatch`.
- A client on a version 1 connection sends a `V1` request as a version 1
  frame and refuses every other request before sending anything.

### The host ID

A `HostId` is 16 random bytes (shown as 32 hex digits) that the worker
makes the first time it starts with none and keeps in `<state>/host-id`
(0600, written atomically). It is never made again while the file exists,
so it stays across daemon restarts, updates and reboots, and it changes
when the machine or its ghostd state is new: a reinstall, a swapped disk,
another machine behind the same name or address, another user's daemon. A
file that holds no host ID stops the worker (it says so in `ghostd.log`)
instead of being replaced.

Every request may carry the `expected_host` a client learned before. When
it is `Some` and not this daemon's ID, the request is answered
`HostMismatch` (naming both IDs) before anything else is done: nothing
runs, nothing is created, also for a version 1 request in a `V1`. `None`
skips the check.

| Request | Answer | Notes |
|---|---|---|
| `Identify` | `Identity { host_id, hostname, machine_id, boot_id, program_version, uid }` | `machine_id` from `/etc/machine-id`, `boot_id` from `/proc/sys/kernel/random/boot_id` (new on every boot), when readable. |

### Sessions

A session is a program on a PTY of its own, held by a shim like a job's
(`ghostd shim <dir> --session`, in `<state>/sessions/<id>/`), so it
survives the connection, the worker's and the daemon's crashes, and is
reached again by its ID on any connection. The shim reads the PTY all the
time, so a program that floods output while nobody looks never blocks:
the output goes to a terminal emulator (the screen and 1000 lines of
scrollback) and to a rotated log (`log_max_bytes`). It makes the PTY the
program's controlling terminal in a session of its own (`TERM` is
`xterm-256color` unless the spec sets it).

`SessionSpec { argv, env, env_remove, cwd, cols, rows, session_id, name }`:
`argv` `None` runs the user's login shell (`$SHELL -l`, else `/bin/sh -l`);
the environment is the daemon's, then `env_remove`, then `env`; `cwd`
defaults to `$HOME`; `cols` 20..=500 (default 120), `rows` 5..=200
(default 40); `session_id` is chosen by the client as `job_id` is (`s` and
16 random lowercase hex digits): the same request again answers the
session it started, another request under its ID is refused with
`Conflict`.

No process is leaked, as for jobs: when the program ends by itself, what it
left in its session is stopped half a second later (as after an `Exec`),
and a close stops the whole tree. An ended session keeps its final screen
(`screen.json`) and its log until it is collected, as a finished exec is
(`exec_retention_hours`, `max_jobs_kept`). At most `max_sessions` (32)
run at once.

| Request | Answer | Notes |
|---|---|---|
| `SessionStart(SessionSpec)` | `SessionStarted { session_id }` | Once the program runs; a program that cannot start is `NotFound` with why. `Busy` at `max_sessions`. |
| `SessionSend { session_id, input: [Key] }` | `V1(Done)` | `Key` is `Text(String)`, `Bytes(bytes)` or `Named(NamedKey)`: `Enter`, `Tab`, `Escape`, `Backspace`, `Delete`, `Up`, `Down`, `Left`, `Right`, `Home`, `End`, `PageUp`, `PageDown`, `Insert`, `F1`–`F12`, `Ctrl(char)` (a letter, `[`, `\`, `]`, `^`, `_`), `Alt(char)`, sent as an xterm sends them (the arrows, Home and End as `ESC O x` in the application cursor-key mode the program set). At most 64 KiB per send; `Busy` while the program has not read what was sent before; `Conflict` once it has exited. |
| `SessionRead { session_id, wait_ms, until, scrollback_lines }` | `Screen` | Without `until`, at once; with it, when it holds or at `wait_ms` (at most 60 s). `Until` is `Changed { since }` (output after the sequence number `since`, `None`: after the request came), `Matches(regex)` (over the screen's text, Rust `regex` syntax) or `Exited`. `scrollback_lines` at most 1000. |
| `SessionResize { session_id, cols, rows }` | `V1(Done)` | The program gets `SIGWINCH`. |
| `SessionSignal { session_id, signal }` | `V1(Done)` | To the PTY's foreground process group (the job a shell runs), else the program's. `Conflict` once it has exited. |
| `SessionList` | `Sessions([SessionInfo])` | Live and ended, newest first. `SessionInfo { session_id, name, argv_summary, state, started_at_ms, ended_at_ms, pid, cols, rows, output_total, finished }`, `state` as a job's. |
| `SessionClose { session_id, grace_ms }` | `Session(SessionInfo)` | `SIGHUP` to the program's group, then the whole tree stopped as `JobStop` does; answers once all is gone. The final screen stays readable. |
| `SessionLogRead { session_id, offset, max_len }` | `V1(LogSlice)` | The raw output, as `JobLogRead`. |

`Screen { text, cursor, cols, rows, title, alternate_screen, scrollback,
exited, changed_since, until_met }`: `text` is the rows joined with `\n`,
each without its trailing spaces; `cursor` (row, column) from 0; `title`
what the program set; `alternate_screen` true while a full-screen program
(`vi`, `less`, `top`) runs; `scrollback` the lines above the screen, oldest
first, when asked for; `exited` `Exited { code }` or `Signaled { signal }`
once the program has ended; `changed_since` a sequence number bumped on
every output and resize; `until_met` whether `until` held (`None` without
one).

### Waits

`Wait(WaitSpec { condition, timeout_ms, interval_ms })` waits on the
machine and answers `Waited { met, elapsed_ms, detail }` when the condition
holds or at `timeout_ms` (at most 300 000), looking every `interval_ms`
(default 250, at least 50). `detail` says what it saw last. A condition
that does not hold yet is never an error; a bad argument, an unknown job or
session is.

| `Condition` | Holds when |
|---|---|
| `PortOpen { host, port }` | A TCP connection to `host` (default `127.0.0.1`) succeeds, each try within 5 s. |
| `HttpStatus { url, status }` | A `GET` of a plain `http://` URL (`Connection: close`, 5 s per try) answers `status`, default any 2xx or 3xx. `https://` is refused with `InvalidArgument`: wait with `PortOpen`, or exec `curl`. |
| `FileExists { path }` | The path exists. |
| `FileContains { path, regex }` | The regex matches the file's last 1 MiB. |
| `LogMatches { source, stream, regex, from_offset }` | The regex matches output of `Job(id)` (`stream`) or `Session(id)` written after `from_offset` (default: the stream's total when the wait began), within 64 KiB. Once the job or session has ended with no match, it answers at once. |
| `ProcessGone { pid, start_time }` | No process `pid` runs; with `start_time` (clock ticks since boot, field 22 of `/proc/<pid>/stat`) one that reused the pid does not count. |
| `JobFinished { job_id }` | The job is `finished`. |
| `SessionExited { session_id }` | The session's program has ended. |

### The machine's state

`MachineState` answers `Machine { hostname, os, kernel, arch, uptime_s,
load, cpus, memory, disks, listening, failing_units, kernel_errors,
journal_errors, notes }`:

- `os` is `PRETTY_NAME` of `/etc/os-release`, `kernel` `uname -r`, `load`
  the 1, 5 and 15 minute averages, `cpus` the online CPUs;
- `memory { total, available, swap_total, swap_free }` in bytes, from
  `/proc/meminfo`;
- `disks [{ mount, fs, device, total, free, used_pct }]`: the real
  filesystems of `/proc/self/mountinfo` (no `proc`, `sysfs`, `cgroup`,
  squashfs snaps, other containers' overlays, nor `tmpfs` but `/tmp` and
  `/dev/shm`), a bind mount once, `used_pct` as `df` counts it;
- `listening [{ proto, address, port, pid, process }]`: TCP sockets in
  `LISTEN` and unconnected UDP ones, from `/proc/net`, with the process
  where `/proc/<pid>/fd` is readable (the daemon's user's own, all as
  root);
- `failing_units`: `systemctl --failed`, `None` without systemd;
- `kernel_errors`: the last 20 of `dmesg --level=emerg,alert,crit,err`, else
  of `/dev/kmsg`; `journal_errors`: the last 20 of `journalctl -p err`;
- `notes`: what could not be read and why.

A part that cannot be read never fails the answer: it is left empty and
`notes` says why. Commands run by their argv with `LC_ALL=C`, a 5 s
timeout and their output capped.

