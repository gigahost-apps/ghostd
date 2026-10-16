//! `ghostd setup`: the directories, a commented configuration file and the
//! install record.
//!
//! ghostd never reads or writes anything under `~/.ssh`: a client reaches
//! it with the user's own SSH access by running `<path>/ghostd stdio`.

use std::fs;
use std::process::ExitCode;

use serde_json::{Value, json};

use crate::config::TEMPLATE;
use crate::paths::Paths;
use crate::util::{atomic_write, now_ms};

/// The options of `ghostd setup`.
pub struct Setup {
    pub origin: Option<String>,
    pub git_ref: Option<String>,
    pub commit: Option<String>,
}

pub fn setup(paths: &Paths, options: &Setup) -> ExitCode {
    match run_setup(paths, options) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("ghostd setup: {e}");
            ExitCode::from(1)
        }
    }
}

fn run_setup(paths: &Paths, options: &Setup) -> Result<Value, String> {
    paths
        .ensure()
        .map_err(|e| format!("creating the directories: {e}"))?;
    let mut config_created = false;
    if !paths.config.exists() {
        if let Some(dir) = paths.config.parent() {
            fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        atomic_write(&paths.config, TEMPLATE.as_bytes(), 0o644, true)
            .map_err(|e| format!("{}: {e}", paths.config.display()))?;
        config_created = true;
    }
    let binary = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|e| format!("cannot find this binary's path: {e}"))?;
    let mut install = Value::Null;
    if let Some(origin) = &options.origin {
        if !matches!(origin.as_str(), "source" | "channel" | "client") {
            return Err("--origin is source, channel or client".into());
        }
        install = json!({
            "origin": origin,
            "ref": options.git_ref,
            "commit": options.commit,
            "version": env!("CARGO_PKG_VERSION"),
            "binary": binary,
            "installed_at_ms": now_ms(),
        });
        let bytes = serde_json::to_vec_pretty(&install).map_err(|e| e.to_string())?;
        atomic_write(&paths.install_record(), &bytes, 0o600, true)
            .map_err(|e| format!("{}: {e}", paths.install_record().display()))?;
    }
    Ok(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "binary": binary,
        "state_dir": paths.state,
        "runtime_dir": paths.runtime,
        "config": paths.config,
        "config_created": config_created,
        "install": install,
    }))
}
