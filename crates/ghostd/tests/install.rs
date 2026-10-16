//! `install.sh` run as it is when piped, against fake `curl`, `cargo` and
//! `cc`: no network, nothing built. It checks how the script chooses what
//! to build.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

const SCRIPT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../install.sh");

/// Serves `FAKE_TAGS` for the tags API (fails when unset), fails every
/// other download, and logs each URL to `FAKE_LOG`.
const FAKE_CURL: &str = r#"#!/bin/sh
out=""
prev=""
for a in "$@"; do
    if [ "$prev" = "-o" ]; then out="$a"; fi
    prev="$a"
done
printf '%s\n' "$prev" >>"$FAKE_LOG"
case "$prev" in
    */tags)
        [ -n "${FAKE_TAGS+set}" ] || exit 22
        printf '%s' "$FAKE_TAGS" >"$out"
        ;;
    *) exit 22 ;;
esac
"#;

fn tool(dir: &Path, name: &str, body: &str) {
    let path = dir.join(name);
    fs::write(&path, body).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// Runs the script piped (`sh -s --`) with `tags` as the tags API's
/// answer (`None`: the call fails). Answers its stderr and the URLs it
/// fetched.
fn piped(tags: Option<&str>) -> (bool, String, String) {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("bin");
    fs::create_dir(&bin).unwrap();
    tool(&bin, "curl", FAKE_CURL);
    tool(&bin, "cargo", "#!/bin/sh\nexit 0\n");
    tool(&bin, "cc", "#!/bin/sh\nexit 0\n");
    let home = dir.path().join("home");
    fs::create_dir(&home).unwrap();
    let log = dir.path().join("urls");
    let mut command = Command::new("sh");
    command
        .args(["-s", "--"])
        .stdin(fs::File::open(SCRIPT).unwrap())
        .stdout(Stdio::null())
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("HOME", &home)
        .env("FAKE_LOG", &log);
    if let Some(tags) = tags {
        command.env("FAKE_TAGS", tags);
    }
    let out = command.output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
        fs::read_to_string(&log).unwrap_or_default(),
    )
}

#[test]
fn a_failed_tags_call_stops_instead_of_building_main() {
    let (ok, stderr, urls) = piped(None);
    assert!(!ok);
    assert!(stderr.contains("--ref"), "{stderr}");
    assert!(!stderr.contains("building main"), "{stderr}");
    assert_eq!(
        urls.lines().count(),
        1,
        "it went on after the failure: {urls}"
    );
}

#[test]
fn no_tag_at_all_builds_main_and_says_so() {
    let (ok, stderr, urls) = piped(Some("[ ]\n"));
    assert!(!ok, "the fake download fails");
    assert!(
        stderr.contains("no release tag yet: building main"),
        "{stderr}"
    );
    assert!(urls.contains("/commits/main"), "{urls}");
}

#[test]
fn the_latest_tag_is_built() {
    let compact = r#"[{"name": "v0.2.0", "commit": {"sha": "x"}}, {"name": "v0.1.0"}]"#;
    let pretty = "[\n  {\n    \"name\": \"v0.2.0\",\n    \"commit\": {\n      \"sha\": \"x\"\n    }\n  },\n  {\n    \"name\": \"v0.1.0\"\n  }\n]\n";
    for tags in [compact, pretty] {
        let (ok, stderr, urls) = piped(Some(tags));
        assert!(!ok, "the fake download fails");
        assert!(urls.contains("/commits/v0.2.0"), "{urls}");
        assert!(urls.contains("/tar.gz/v0.2.0"), "{urls}\n{stderr}");
    }
}

#[test]
fn an_unreadable_tags_answer_stops() {
    let (ok, stderr, urls) = piped(Some("<html>rate limited</html>"));
    assert!(!ok);
    assert!(stderr.contains("--ref"), "{stderr}");
    assert_eq!(urls.lines().count(), 1, "{urls}");
}
