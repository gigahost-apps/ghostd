//! `ghostd`: a daemon on a Linux machine for AI agents to work on it.

mod config;
mod files;
mod hostid;
mod jobfiles;
mod jobs;
mod keys;
mod logfile;
mod machine;
mod paths;
mod procfs;
mod relay;
mod sessions;
mod sessproto;
mod setup;
mod shim;
mod supervisor;
mod util;
mod waits;
mod worker;

use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use crate::paths::Paths;

#[derive(Parser)]
#[command(
    name = "ghostd",
    version,
    about = "A daemon for AI agents to work on this machine, reached over SSH"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Relay stdin and stdout to the daemon, starting it when none runs.
    /// A client runs it over SSH by its full path
    /// (`ssh -T host /home/you/.local/bin/ghostd stdio`), since a
    /// non-login `ssh host cmd` may not have `~/.local/bin` on PATH.
    Stdio {
        /// A label for the client ([A-Za-z0-9._-]{1,64}), for the logs.
        #[arg(long = "client")]
        client: Option<String>,
    },
    /// Run the supervisor, which keeps a worker serving the socket.
    Daemon,
    /// Serve the socket (started by the daemon).
    #[command(hide = true)]
    Worker,
    /// Run one job's program, or hold one session's terminal (started by
    /// the worker).
    #[command(hide = true)]
    Shim {
        job_dir: PathBuf,
        #[arg(long)]
        session: bool,
    },
    /// Start a session's program on its terminal (started by its shim).
    #[command(hide = true)]
    PtyExec {
        tty: PathBuf,
        #[arg(last = true, required = true)]
        argv: Vec<OsString>,
    },
    /// Create the directories and the configuration file; record the
    /// install origin. Nothing under `~/.ssh` is ever touched.
    Setup {
        /// Where this installation came from (written by install.sh).
        #[arg(long, value_parser = ["source", "channel", "client"])]
        origin: Option<String>,
        /// The tag, branch or commit installed.
        #[arg(long = "ref", requires = "origin")]
        git_ref: Option<String>,
        /// The commit installed.
        #[arg(long, requires = "origin")]
        commit: Option<String>,
    },
    /// Stop the daemon (jobs keep running).
    Stop,
    /// Print the daemon's state as JSON.
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let paths = Paths::resolve();
    match cli.command {
        Command::Stdio { client } => relay::run(&paths, client),
        Command::Daemon => supervisor::daemon(&paths),
        Command::Worker => worker::run(&paths),
        Command::Shim {
            job_dir,
            session: false,
        } => shim::run(&job_dir),
        Command::Shim {
            job_dir,
            session: true,
        } => shim::run_session(&job_dir),
        Command::PtyExec { tty, argv } => shim::pty_exec(&tty, &argv),
        Command::Setup {
            origin,
            git_ref,
            commit,
        } => setup::setup(
            &paths,
            &setup::Setup {
                origin,
                git_ref,
                commit,
            },
        ),
        Command::Stop => supervisor::stop(&paths),
        Command::Status => supervisor::status(&paths),
    }
}
