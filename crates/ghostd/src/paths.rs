//! Where the daemon keeps its state, its socket and its configuration.

use std::fs::{self, DirBuilder};
use std::io;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::util::home;

#[derive(Debug, Clone)]
pub struct Paths {
    pub state: PathBuf,
    pub runtime: PathBuf,
    pub config: PathBuf,
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn writable(dir: &Path) -> bool {
    dir.is_dir() && nix::unistd::access(dir, nix::unistd::AccessFlags::W_OK).is_ok()
}

impl Paths {
    /// The paths for this user: system ones as root, XDG ones otherwise,
    /// each overridable by `GHOSTD_STATE_DIR`, `GHOSTD_RUNTIME_DIR` and
    /// `GHOSTD_CONFIG`.
    #[must_use]
    pub fn resolve() -> Self {
        let root = nix::unistd::geteuid().is_root();
        let state = env_path("GHOSTD_STATE_DIR").unwrap_or_else(|| {
            if root {
                PathBuf::from("/var/lib/ghostd")
            } else {
                env_path("XDG_STATE_HOME")
                    .unwrap_or_else(|| home().join(".local/state"))
                    .join("ghostd")
            }
        });
        let runtime = env_path("GHOSTD_RUNTIME_DIR").unwrap_or_else(|| {
            if root {
                PathBuf::from("/run/ghostd")
            } else {
                match env_path("XDG_RUNTIME_DIR") {
                    Some(dir) if writable(&dir) => dir.join("ghostd"),
                    _ => state.join("run"),
                }
            }
        });
        let config = env_path("GHOSTD_CONFIG").unwrap_or_else(|| {
            if root {
                PathBuf::from("/etc/ghostd/config.toml")
            } else {
                env_path("XDG_CONFIG_HOME")
                    .unwrap_or_else(|| home().join(".config"))
                    .join("ghostd/config.toml")
            }
        });
        Self {
            state,
            runtime,
            config,
        }
    }

    #[must_use]
    pub fn socket(&self) -> PathBuf {
        self.runtime.join("ghostd.sock")
    }

    #[must_use]
    pub fn daemon_lock(&self) -> PathBuf {
        self.runtime.join("daemon.lock")
    }

    #[must_use]
    pub fn worker_lock(&self) -> PathBuf {
        self.runtime.join("worker.lock")
    }

    #[must_use]
    pub fn pid_file(&self) -> PathBuf {
        self.runtime.join("daemon.pid")
    }

    #[must_use]
    pub fn log_file(&self) -> PathBuf {
        self.state.join("ghostd.log")
    }

    #[must_use]
    pub fn jobs(&self) -> PathBuf {
        self.state.join("jobs")
    }

    #[must_use]
    pub fn install_record(&self) -> PathBuf {
        self.state.join("install.json")
    }

    /// Creates the state, jobs and runtime directories, 0700.
    ///
    /// # Errors
    ///
    /// When a directory cannot be created or restricted.
    pub fn ensure(&self) -> io::Result<()> {
        for dir in [&self.state, &self.jobs(), &self.runtime] {
            private_dir(dir)?;
        }
        Ok(())
    }
}

/// Creates `dir` (and its parents) and makes it 0700.
///
/// # Errors
///
/// When it cannot be created or its mode set.
pub fn private_dir(dir: &Path) -> io::Result<()> {
    DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    let mode = fs::metadata(dir)?.permissions().mode() & 0o7777;
    if mode != 0o700 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}
