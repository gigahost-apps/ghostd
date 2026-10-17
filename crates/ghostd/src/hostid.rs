//! The daemon's host ID: 16 random bytes made by the first worker that
//! starts with none and kept in `<state>/host-id` (32 hex digits, 0600).
//! It is never made again while the file exists, so it stays across
//! restarts, updates and reboots and changes only with the machine or its
//! ghostd state (a reinstall, a swapped disk, another user's daemon). A
//! client that kept it sends it with its requests and learns when a name
//! or an address now reaches another machine.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use ghostd_protocol::v2::HostId;

use crate::util::{sync_dir, temp_beside};

/// Reads the host ID, making it first when there is none.
///
/// # Errors
///
/// When the file cannot be read or written, or holds no host ID (it is
/// then left alone: a new ID would make every client that knows this
/// machine refuse it).
pub fn load_or_create(path: &Path) -> io::Result<HostId> {
    match read(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        other => return other,
    }
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let id = HostId(bytes);
    let tmp = temp_beside(path)?;
    let written = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(format!("{id}\n").as_bytes())?;
        file.sync_all()?;
        drop(file);
        // A hard link never replaces a file: when another process made the
        // ID meanwhile, its ID stays and is the one read below.
        match fs::hard_link(&tmp, path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e),
        }
    })();
    let _ = fs::remove_file(&tmp);
    written?;
    if let Some(dir) = path.parent() {
        sync_dir(dir);
    }
    read(path)
}

fn read(path: &Path) -> io::Result<HostId> {
    let text = fs::read_to_string(path)?;
    let mode = fs::metadata(path)?.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    text.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "{} holds no host ID (32 hex digits); remove it to make a new one, which clients \
                 that know this machine will refuse until they forget it",
                path.display()
            ),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn made_once_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-id");
        let id = load_or_create(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), format!("{id}\n"));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(load_or_create(&path).unwrap(), id);
        // Nothing but the file is left.
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        fs::remove_file(&path).unwrap();
        assert_ne!(load_or_create(&path).unwrap(), id);
    }

    #[test]
    fn a_broken_file_is_never_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-id");
        fs::write(&path, "nope").unwrap();
        let e = load_or_create(&path).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert_eq!(fs::read_to_string(&path).unwrap(), "nope");
    }
}
