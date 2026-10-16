//! `ghostd`: a daemon on a Linux machine for AI agents to work on it.

mod config;
mod files;
mod jobfiles;
mod jobs;
mod keys;
mod logfile;
mod paths;
mod procfs;
mod relay;
mod shim;
mod supervisor;
mod util;
mod worker;

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
    /// Relay stdin and stdout to the daemon, starting it when none runs
    /// (what sshd runs).
    Stdio {
        /// The client's label, as the forced command names it.
        #[arg(long = "client")]
        client: Option<String>,
    },
    /// Run the supervisor, which keeps a worker serving the socket.
    Daemon,
    /// Serve the socket (started by the daemon).
    #[command(hide = true)]
    Worker,
    /// Run one job's program (started by the worker).
    #[command(hide = true)]
    Shim { job_dir: PathBuf },
    /// Create the directories and configuration; authorize a key.
    Setup {
        /// An OpenSSH public key line to authorize with a forced command.
        #[arg(long, requires = "label")]
        authorize_key: Option<String>,
        /// The key's label ([A-Za-z0-9._-]{1,64}).
        #[arg(long, requires = "authorize_key")]
        label: Option<String>,
        /// Turn a key already authorized for plain logins into a
        /// ghostd-only key (it loses shell access).
        #[arg(long, requires = "authorize_key")]
        replace: bool,
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
    /// List or remove the ghostd keys in `~/.ssh/authorized_keys`.
    Keys {
        #[command(subcommand)]
        command: KeysCommand,
    },
    /// Stop the daemon (jobs keep running).
    Stop,
    /// Print the daemon's state as JSON.
    Status,
}

#[derive(Subcommand)]
enum KeysCommand {
    /// The ghostd keys as JSON.
    List,
    /// Remove the ghostd keys with this label.
    Remove { label: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let paths = Paths::resolve();
    match cli.command {
        Command::Stdio { client } => relay::run(&paths, client),
        Command::Daemon => supervisor::daemon(&paths),
        Command::Worker => worker::run(&paths),
        Command::Shim { job_dir } => shim::run(&job_dir),
        Command::Setup {
            authorize_key,
            label,
            replace,
            origin,
            git_ref,
            commit,
        } => keys::setup(
            &paths,
            &keys::Setup {
                authorize_key,
                label,
                replace,
                origin,
                git_ref,
                commit,
            },
        ),
        Command::Keys { command } => match command {
            KeysCommand::List => keys::list(),
            KeysCommand::Remove { label } => keys::remove(&label),
        },
        Command::Stop => supervisor::stop(&paths),
        Command::Status => supervisor::status(&paths),
    }
}
