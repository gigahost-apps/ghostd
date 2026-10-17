//! The daemon's configuration file.

use std::path::Path;

use serde::Deserialize;

const KIB: u64 = 1024;
const MIB: u64 = 1024 * KIB;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// The last bytes of each stream an exec answers by default.
    pub exec_output_cap: u64,
    /// A job's log per stream rotates at this size; one rotated file kept.
    pub log_max_bytes: u64,
    /// How long a stop waits after SIGTERM before SIGKILL.
    pub stop_grace_ms: u64,
    /// An exec's timeout when it names none.
    pub exec_timeout_ms: u64,
    pub job_retention_hours: u64,
    pub exec_retention_hours: u64,
    pub max_jobs_kept: u64,
    pub max_running_jobs: u64,
    /// Sessions (PTYs) live at once.
    pub max_sessions: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            exec_output_cap: 256 * KIB,
            log_max_bytes: 64 * MIB,
            stop_grace_ms: 5000,
            exec_timeout_ms: 120_000,
            job_retention_hours: 168,
            exec_retention_hours: 24,
            max_jobs_kept: 1000,
            max_running_jobs: 256,
            max_sessions: 32,
        }
    }
}

/// The longest exec timeout: a day.
pub const MAX_EXEC_TIMEOUT_MS: u64 = 86_400_000;
/// The largest output an exec answers per stream.
pub const MAX_OUTPUT_CAP: u64 = 8 * MIB;

impl Config {
    /// Reads the file, or the defaults when it does not exist.
    ///
    /// # Errors
    ///
    /// A message naming the file and the problem (an unknown key is named).
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        let config: Self = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        config
            .validate()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), String> {
        if self.exec_output_cap > MAX_OUTPUT_CAP {
            return Err(format!("exec_output_cap is at most {MAX_OUTPUT_CAP}"));
        }
        if self.log_max_bytes < KIB {
            return Err("log_max_bytes is at least 1024".into());
        }
        if self.exec_timeout_ms == 0 || self.exec_timeout_ms > MAX_EXEC_TIMEOUT_MS {
            return Err(format!("exec_timeout_ms is 1..={MAX_EXEC_TIMEOUT_MS}"));
        }
        if self.max_jobs_kept == 0 || self.max_running_jobs == 0 || self.max_sessions == 0 {
            return Err("max_jobs_kept, max_running_jobs and max_sessions are at least 1".into());
        }
        Ok(())
    }
}

/// The commented file `ghostd setup` writes when there is none.
pub const TEMPLATE: &str = "\
# ghostd's configuration. Every key is optional; the values shown are the
# defaults. An unknown key stops the daemon from starting, naming the key.
# Changes take effect when the daemon restarts (`ghostd stop`; the next
# `ghostd stdio` starts it again).

# The last bytes of stdout and of stderr an exec answers (at most 8 MiB).
# exec_output_cap = 262144

# A job's log, per stream, rotates at this size; one rotated file is kept.
# log_max_bytes = 67108864

# How long a stop waits after SIGTERM before it sends SIGKILL.
# stop_grace_ms = 5000

# An exec's timeout when it names none (at most 86400000, a day).
# exec_timeout_ms = 120000

# How long finished jobs and finished execs are kept.
# job_retention_hours = 168
# exec_retention_hours = 24

# At most this many jobs are kept; the oldest finished go first.
# max_jobs_kept = 1000

# Starting more jobs than this at once is refused.
# max_running_jobs = 256

# Starting more sessions (terminals) than this at once is refused. Ended
# sessions are kept as long as finished execs.
# max_sessions = 32
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_key_named() {
        let e = toml::from_str::<Config>("stop_grace = 1").unwrap_err();
        assert!(e.to_string().contains("stop_grace"), "{e}");
    }

    #[test]
    fn template_is_the_defaults() {
        let uncommented: String = TEMPLATE
            .lines()
            .filter_map(|l| l.strip_prefix("# "))
            .filter(|l| l.contains(" = "))
            .fold(String::new(), |mut s, l| {
                s.push_str(l);
                s.push('\n');
                s
            });
        let parsed: Config = toml::from_str(&uncommented).unwrap();
        let defaults = Config::default();
        assert_eq!(format!("{parsed:?}"), format!("{defaults:?}"));
    }
}
