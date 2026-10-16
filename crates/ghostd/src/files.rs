//! File requests. Paths are bytes, relative ones relative to `$HOME`.
//! There is no sandbox: the daemon acts as its user, like their shell.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use ghostd_protocol::v1::{Error, ErrorKind, FileKind, MAX_DATA, Response, SearchMatch, Stat};
use sha2::{Digest, Sha256};

use crate::util::{err, home, io_error, resolve, sync_dir, temp_beside};

/// The largest file an edit loads.
const MAX_EDIT: u64 = 64 * 1024 * 1024;
/// What a listing or a search may put in one answer.
const ANSWER_BUDGET: usize = 12 * 1024 * 1024;
/// The longest line a search answers.
const MAX_LINE: usize = 4096;
/// Uploads open at once on one connection.
const MAX_UPLOADS: usize = 16;
/// The mode of a file created without one.
const DEFAULT_MODE: u32 = 0o644;

fn display(path: &Path) -> String {
    path.display().to_string()
}

fn too_large(what: &str, max: usize) -> Error {
    err(
        ErrorKind::TooLarge,
        format!("{what} is at most {max} bytes"),
    )
}

/// The stat of a path we already have metadata for.
fn stat_of(path: &Path, meta: &Metadata) -> Stat {
    let ft = meta.file_type();
    let kind = if ft.is_symlink() {
        FileKind::Symlink
    } else if ft.is_dir() {
        FileKind::Dir
    } else if ft.is_file() {
        FileKind::File
    } else {
        FileKind::Other
    };
    let link_target = if ft.is_symlink() {
        fs::read_link(path)
            .ok()
            .map(|t| t.into_os_string().into_encoded_bytes())
    } else {
        None
    };
    Stat {
        kind,
        size: meta.size(),
        mode: meta.mode() & 0o7777,
        mtime_ms: meta.mtime() * 1000 + meta.mtime_nsec() / 1_000_000,
        uid: meta.uid(),
        gid: meta.gid(),
        link_target,
    }
}

/// `FileStat`.
///
/// # Errors
///
/// When the path cannot be stat'ed.
pub fn stat(path: &[u8], follow: bool) -> Result<Response, Error> {
    let path = resolve(path);
    let meta = if follow {
        fs::metadata(&path)
    } else {
        fs::symlink_metadata(&path)
    }
    .map_err(|e| io_error(&e, &display(&path)))?;
    Ok(Response::Stat(stat_of(&path, &meta)))
}

/// `FileRead`.
///
/// # Errors
///
/// `TooLarge` past 8 MiB, or the file's error.
pub fn read(path: &[u8], offset: u64, len: u32) -> Result<Response, Error> {
    if len as usize > MAX_DATA {
        return Err(too_large("len", MAX_DATA));
    }
    let path = resolve(path);
    let ctx = || display(&path);
    let mut file = File::open(&path).map_err(|e| io_error(&e, &ctx()))?;
    let size = file.metadata().map_err(|e| io_error(&e, &ctx()))?.len();
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| io_error(&e, &ctx()))?;
    let mut data = Vec::new();
    file.take(u64::from(len))
        .read_to_end(&mut data)
        .map_err(|e| io_error(&e, &ctx()))?;
    let eof = offset + data.len() as u64 >= size;
    Ok(Response::FileData { data, size, eof })
}

/// Where a write to `path` lands: the final target of a symlink, so that
/// replacing the file never replaces the link.
fn write_target(path: &[u8], create_dirs: bool) -> Result<PathBuf, Error> {
    let path = resolve(path);
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(err(
            ErrorKind::InvalidArgument,
            format!("{} is not a file path", display(&path)),
        ));
    }
    if create_dirs && let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| io_error(&e, &display(parent)))?;
    }
    match fs::symlink_metadata(&path) {
        Ok(meta) if meta.file_type().is_symlink() => fs::canonicalize(&path)
            .map_err(|e| io_error(&e, &format!("{} (a symlink)", display(&path)))),
        Ok(meta) if meta.is_dir() => Err(err(
            ErrorKind::InvalidArgument,
            format!("{} is a directory", display(&path)),
        )),
        _ => Ok(path),
    }
}

/// The mode a replaced file gets: the asked one, else the existing file's,
/// else 0644.
fn final_mode(target: &Path, mode: Option<u32>) -> u32 {
    mode.map_or_else(
        || fs::metadata(target).map_or(DEFAULT_MODE, |m| m.permissions().mode() & 0o7777),
        |m| m & 0o7777,
    )
}

fn create_temp(target: &Path) -> Result<(PathBuf, File), Error> {
    let tmp = temp_beside(target).map_err(|e| io_error(&e, "random bytes"))?;
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| io_error(&e, &display(&tmp)))?;
    Ok((tmp, file))
}

/// The extended attributes a replaced file passes on: its `SELinux` label,
/// its ACL and the user's own. Not file capabilities or integrity
/// signatures, which belonged to the old content.
fn kept_xattr(name: &[u8]) -> bool {
    name == b"security.selinux" || name == b"system.posix_acl_access" || name.starts_with(b"user.")
}

/// Gives the temp file the identity of the file it replaces, as far as this
/// user may: its owner and group (a root daemon editing `pg_hba.conf` must
/// leave it `postgres:postgres`; a user keeps at least a group they are in)
/// and the extended attributes [`kept_xattr`] names. Hard links to the old
/// file keep the old content: a replacement is a new file.
fn keep_identity(file: &File, target: &Path) {
    let Ok(meta) = fs::metadata(target) else {
        return;
    };
    if std::os::unix::fs::fchown(file, Some(meta.uid()), Some(meta.gid())).is_err() {
        let _ = std::os::unix::fs::fchown(file, None, Some(meta.gid()));
    }
    let mut names = vec![0u8; 64 * 1024];
    let Ok(len) = rustix::fs::listxattr(target, &mut names[..]) else {
        return;
    };
    let mut value = vec![0u8; 64 * 1024];
    for name in names[..len].split(|&b| b == 0) {
        if !kept_xattr(name) {
            continue;
        }
        if let Ok(n) = rustix::fs::getxattr(target, name, &mut value[..]) {
            let _ = rustix::fs::fsetxattr(file, name, &value[..n], rustix::fs::XattrFlags::empty());
        }
    }
}

/// Gives the temp file the replaced file's owner, group and attributes,
/// then its mode (after the owner: a chown may clear set-id bits), syncs it
/// and renames it over `target`.
fn commit(tmp: &Path, file: &File, target: &Path, mode: u32) -> io::Result<()> {
    keep_identity(file, target);
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    fs::rename(tmp, target)?;
    if let Some(parent) = target.parent() {
        sync_dir(parent);
    }
    Ok(())
}

fn replace_file(target: &Path, data: &[u8], mode: u32) -> Result<(), Error> {
    let (tmp, mut file) = create_temp(target)?;
    let result = file
        .write_all(data)
        .and_then(|()| commit(&tmp, &file, target, mode));
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(io_error(&e, &display(target)));
    }
    Ok(())
}

/// `FileWrite`: atomic, keeping an existing file's mode unless `mode`.
///
/// # Errors
///
/// `TooLarge` past 8 MiB, or the file's error.
pub fn write(
    path: &[u8],
    data: &[u8],
    mode: Option<u32>,
    create_dirs: bool,
) -> Result<Response, Error> {
    if data.len() > MAX_DATA {
        return Err(too_large("data", MAX_DATA));
    }
    let target = write_target(path, create_dirs)?;
    replace_file(&target, data, final_mode(&target, mode))?;
    Ok(Response::Written {
        size: data.len() as u64,
        sha256: Sha256::digest(data).into(),
    })
}

fn find_all(hay: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + needle.len() <= hay.len() {
        match hay[at..].windows(needle.len()).position(|w| w == needle) {
            Some(pos) => {
                found.push(at + pos);
                at += pos + needle.len();
            }
            None => break,
        }
    }
    found
}

/// `FileEdit`.
///
/// # Errors
///
/// `NotFound` when `old` is absent, `Conflict` when it occurs more than
/// once without `replace_all`, or the file's error.
pub fn edit(path: &[u8], old: &[u8], new: &[u8], replace_all: bool) -> Result<Response, Error> {
    if old.is_empty() {
        return Err(err(ErrorKind::InvalidArgument, "old is empty"));
    }
    let target = write_target(path, false)?;
    let meta = fs::metadata(&target).map_err(|e| io_error(&e, &display(&target)))?;
    if meta.len() > MAX_EDIT {
        return Err(err(
            ErrorKind::TooLarge,
            format!("an edited file is at most {MAX_EDIT} bytes"),
        ));
    }
    let content = fs::read(&target).map_err(|e| io_error(&e, &display(&target)))?;
    let found = find_all(&content, old);
    match found.len() {
        0 => {
            return Err(err(
                ErrorKind::NotFound,
                format!("the old text does not occur in {}", display(&target)),
            ));
        }
        1 => {}
        n if !replace_all => {
            return Err(err(
                ErrorKind::Conflict,
                format!(
                    "the old text occurs {n} times in {}; make it unique or replace all",
                    display(&target)
                ),
            ));
        }
        _ => {}
    }
    let mut out = Vec::with_capacity(content.len() + found.len() * new.len());
    let mut last = 0;
    for &at in &found {
        out.extend_from_slice(&content[last..at]);
        out.extend_from_slice(new);
        last = at + old.len();
    }
    out.extend_from_slice(&content[last..]);
    replace_file(&target, &out, meta.permissions().mode() & 0o7777)?;
    Ok(Response::Edited {
        replacements: found.len() as u64,
        sha256: Sha256::digest(&out).into(),
    })
}

/// `FileList`: depth first, each directory's entries sorted by name,
/// hidden files included, symlinks not followed.
///
/// # Errors
///
/// `InvalidArgument` for out-of-range limits, or the directory's error.
pub fn list(path: &[u8], depth: u32, max_entries: u32) -> Result<Response, Error> {
    let depth = match depth {
        0 => 1,
        1..=16 => depth,
        _ => return Err(err(ErrorKind::InvalidArgument, "depth is 1..=16")),
    };
    let max_entries = match max_entries {
        0 => 1000,
        1..=100_000 => max_entries as usize,
        _ => {
            return Err(err(
                ErrorKind::InvalidArgument,
                "max_entries is at most 100000",
            ));
        }
    };
    let root = resolve(path);
    let meta = fs::metadata(&root).map_err(|e| io_error(&e, &display(&root)))?;
    if !meta.is_dir() {
        return Err(err(
            ErrorKind::InvalidArgument,
            format!("{} is not a directory", display(&root)),
        ));
    }
    let mut walk = Walk {
        entries: Vec::new(),
        bytes: 0,
        max_entries,
        truncated: false,
    };
    walk.dir(&root, &[], depth)
        .map_err(|e| io_error(&e, &display(&root)))?;
    Ok(Response::Listing {
        entries: walk.entries,
        truncated: walk.truncated,
    })
}

struct Walk {
    entries: Vec<(Vec<u8>, Stat)>,
    bytes: usize,
    max_entries: usize,
    truncated: bool,
}

impl Walk {
    fn dir(&mut self, dir: &Path, prefix: &[u8], depth_left: u32) -> io::Result<()> {
        let mut names: Vec<OsString> = fs::read_dir(dir)?
            .filter_map(Result::ok)
            .map(|e| e.file_name())
            .collect();
        names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for name in names {
            if self.entries.len() >= self.max_entries || self.bytes >= ANSWER_BUDGET {
                self.truncated = true;
                return Ok(());
            }
            let path = dir.join(&name);
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            let mut rel = prefix.to_vec();
            if !rel.is_empty() {
                rel.push(b'/');
            }
            rel.extend_from_slice(name.as_bytes());
            let stat = stat_of(&path, &meta);
            self.bytes += rel.len() + 64 + stat.link_target.as_ref().map_or(0, Vec::len);
            self.entries.push((rel.clone(), stat));
            if meta.is_dir() && depth_left > 1 {
                // An unreadable subdirectory is listed but not entered.
                let _ = self.dir(&path, &rel, depth_left - 1);
                if self.truncated {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// The search options of `FileSearch`.
pub struct SearchSpec<'a> {
    pub pattern: &'a str,
    pub path: &'a [u8],
    pub globs: &'a [String],
    pub case_insensitive: bool,
    pub hidden: bool,
    pub max_matches: u32,
}

/// `FileSearch`, with ripgrep's defaults: `.gitignore` (in a git
/// repository) and `.ignore` files respected, hidden files skipped unless
/// `hidden`, binary files skipped, symlinks not followed. Paths are
/// relative to the searched directory.
///
/// # Errors
///
/// `InvalidArgument` for a bad pattern, glob or limit.
pub fn search(spec: &SearchSpec<'_>) -> Result<Response, Error> {
    use grep_regex::RegexMatcherBuilder;
    use grep_searcher::sinks::Bytes;
    use grep_searcher::{BinaryDetection, SearcherBuilder};
    use ignore::WalkBuilder;
    use ignore::overrides::OverrideBuilder;

    let max_matches = match spec.max_matches {
        0 => 200,
        1..=10_000 => spec.max_matches as usize,
        _ => {
            return Err(err(
                ErrorKind::InvalidArgument,
                "max_matches is at most 10000",
            ));
        }
    };
    let root = resolve(spec.path);
    fs::metadata(&root).map_err(|e| io_error(&e, &display(&root)))?;
    let matcher = RegexMatcherBuilder::new()
        .case_insensitive(spec.case_insensitive)
        .build(spec.pattern)
        .map_err(|e| err(ErrorKind::InvalidArgument, format!("pattern: {e}")))?;
    let mut overrides = OverrideBuilder::new(&root);
    for glob in spec.globs {
        overrides
            .add(glob)
            .map_err(|e| err(ErrorKind::InvalidArgument, format!("glob {glob:?}: {e}")))?;
    }
    let overrides = overrides
        .build()
        .map_err(|e| err(ErrorKind::InvalidArgument, format!("globs: {e}")))?;
    let walker = WalkBuilder::new(&root)
        .hidden(!spec.hidden)
        .overrides(overrides)
        .sort_by_file_name(std::cmp::Ord::cmp)
        .build();
    let mut searcher = SearcherBuilder::new()
        .binary_detection(BinaryDetection::quit(0))
        .line_number(true)
        .build();
    let mut found = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;
    for entry in walker {
        let Ok(entry) = entry else { continue };
        if !entry.file_type().is_some_and(|t| t.is_file()) {
            continue;
        }
        let path = entry.path();
        let rel = match path.strip_prefix(&root) {
            Ok(rel) if !rel.as_os_str().is_empty() => rel.as_os_str().as_bytes().to_vec(),
            _ => path
                .file_name()
                .map_or_else(Vec::new, |n| n.as_bytes().to_vec()),
        };
        let result = searcher.search_path(
            &matcher,
            path,
            Bytes(|line_number, line| {
                if found.len() >= max_matches || bytes >= ANSWER_BUDGET {
                    truncated = true;
                    return Ok(false);
                }
                let mut line = line;
                while let Some((&last, rest)) = line.split_last() {
                    if last == b'\n' || last == b'\r' {
                        line = rest;
                    } else {
                        break;
                    }
                }
                let line = line[..line.len().min(MAX_LINE)].to_vec();
                bytes += line.len() + rel.len() + 16;
                found.push(SearchMatch {
                    path: rel.clone(),
                    line_number,
                    line,
                });
                Ok(true)
            }),
        );
        // A file that cannot be read is skipped, as ripgrep does.
        let _ = result;
        if truncated {
            break;
        }
    }
    Ok(Response::Matches {
        matches: found,
        truncated,
    })
}

/// `FileHash`.
///
/// # Errors
///
/// The file's error.
pub fn hash(path: &[u8]) -> Result<Response, Error> {
    let path = resolve(path);
    let mut file = File::open(&path).map_err(|e| io_error(&e, &display(&path)))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut size = 0u64;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| io_error(&e, &display(&path)))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }
    Ok(Response::Hash {
        size,
        sha256: hasher.finalize().into(),
    })
}

/// `FileRemove`. A recursive removal of `/` or of `$HOME` is refused.
///
/// # Errors
///
/// The path's error, or `InvalidArgument` for the refused removals.
pub fn remove(path: &[u8], recursive: bool) -> Result<Response, Error> {
    let path = resolve(path);
    let meta = fs::symlink_metadata(&path).map_err(|e| io_error(&e, &display(&path)))?;
    let result = if meta.is_dir() {
        if recursive {
            let canonical = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
            let home = fs::canonicalize(home()).unwrap_or_else(|_| home());
            if canonical == Path::new("/") || canonical == home {
                return Err(err(
                    ErrorKind::InvalidArgument,
                    format!("refusing to remove {} recursively", display(&canonical)),
                ));
            }
            fs::remove_dir_all(&path)
        } else {
            fs::remove_dir(&path)
        }
    } else {
        fs::remove_file(&path)
    };
    result.map_err(|e| io_error(&e, &display(&path)))?;
    Ok(Response::Done)
}

/// `FileRename`; without `overwrite` an existing `to` is refused,
/// atomically.
///
/// # Errors
///
/// `AlreadyExists`, or the paths' error.
pub fn rename(from: &[u8], to: &[u8], overwrite: bool) -> Result<Response, Error> {
    let from = resolve(from);
    let to = resolve(to);
    let context = || format!("{} -> {}", display(&from), display(&to));
    if overwrite {
        fs::rename(&from, &to).map_err(|e| io_error(&e, &context()))?;
        return Ok(Response::Done);
    }
    // rustix makes the system call itself: nix has renameat2 only on glibc,
    // and ghostd is built for musl too.
    match rustix::fs::renameat_with(
        rustix::fs::CWD,
        &from,
        rustix::fs::CWD,
        &to,
        rustix::fs::RenameFlags::NOREPLACE,
    ) {
        Ok(()) => Ok(Response::Done),
        Err(rustix::io::Errno::INVAL | rustix::io::Errno::NOSYS) => {
            // A file system without RENAME_NOREPLACE.
            if fs::symlink_metadata(&to).is_ok() {
                return Err(err(
                    ErrorKind::AlreadyExists,
                    format!("{} exists", display(&to)),
                ));
            }
            fs::rename(&from, &to).map_err(|e| io_error(&e, &context()))?;
            Ok(Response::Done)
        }
        Err(e) => Err(io_error(&io::Error::from(e), &context())),
    }
}

/// `FileMkdir`.
///
/// # Errors
///
/// The path's error.
pub fn mkdir(path: &[u8], parents: bool, mode: Option<u32>) -> Result<Response, Error> {
    let path = resolve(path);
    DirBuilder::new()
        .recursive(parents)
        .mode(mode.unwrap_or(0o755) & 0o7777)
        .create(&path)
        .map_err(|e| io_error(&e, &display(&path)))?;
    Ok(Response::Done)
}

/// An upload in progress: a temp file beside its target.
struct Upload {
    tmp: PathBuf,
    file: File,
    target: PathBuf,
    mode: u32,
    written: u64,
    hasher: Sha256,
    done: bool,
}

impl Drop for Upload {
    fn drop(&mut self) {
        if !self.done {
            let _ = fs::remove_file(&self.tmp);
        }
    }
}

/// One connection's uploads. Dropping it (the connection ended) removes
/// every unfinished upload's temp file.
#[derive(Default)]
pub struct Uploads {
    next: AtomicU64,
    open: Mutex<HashMap<u64, Arc<Mutex<Upload>>>>,
}

fn unknown_upload(handle: u64) -> Error {
    err(
        ErrorKind::NotFound,
        format!("no upload {handle} on this connection"),
    )
}

impl Uploads {
    fn get(&self, handle: u64) -> Result<Arc<Mutex<Upload>>, Error> {
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&handle)
            .cloned()
            .ok_or_else(|| unknown_upload(handle))
    }

    fn take(&self, handle: u64) -> Result<Arc<Mutex<Upload>>, Error> {
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&handle)
            .ok_or_else(|| unknown_upload(handle))
    }

    /// `UploadBegin`.
    ///
    /// # Errors
    ///
    /// `Busy` with too many uploads open, or the target's error.
    pub fn begin(
        &self,
        path: &[u8],
        mode: Option<u32>,
        create_dirs: bool,
    ) -> Result<Response, Error> {
        if self
            .open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
            >= MAX_UPLOADS
        {
            return Err(err(
                ErrorKind::Busy,
                format!("at most {MAX_UPLOADS} uploads are open on a connection"),
            ));
        }
        let target = write_target(path, create_dirs)?;
        let mode = final_mode(&target, mode);
        let (tmp, file) = create_temp(&target)?;
        let handle = self.next.fetch_add(1, Ordering::Relaxed) + 1;
        let upload = Upload {
            tmp,
            file,
            target,
            mode,
            written: 0,
            hasher: Sha256::new(),
            done: false,
        };
        self.open
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(handle, Arc::new(Mutex::new(upload)));
        Ok(Response::Upload { handle })
    }

    /// `UploadChunk`: offsets must be contiguous.
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for a gap or overlap, `TooLarge` past 8 MiB.
    pub fn chunk(&self, handle: u64, offset: u64, data: &[u8]) -> Result<Response, Error> {
        if data.len() > MAX_DATA {
            return Err(too_large("a chunk", MAX_DATA));
        }
        let upload = self.get(handle)?;
        let mut upload = upload.lock().unwrap_or_else(PoisonError::into_inner);
        if offset != upload.written {
            return Err(err(
                ErrorKind::InvalidArgument,
                format!("chunk at offset {offset}, expected {}", upload.written),
            ));
        }
        let tmp = upload.tmp.clone();
        upload
            .file
            .write_all(data)
            .map_err(|e| io_error(&e, &display(&tmp)))?;
        upload.hasher.update(data);
        upload.written += data.len() as u64;
        Ok(Response::Done)
    }

    /// `UploadEnd`: checks the hash when given, then renames the file into
    /// place atomically.
    ///
    /// # Errors
    ///
    /// `Conflict` on a hash mismatch (the upload is discarded).
    pub fn end(&self, handle: u64, sha256: Option<[u8; 32]>) -> Result<Response, Error> {
        let upload = self.take(handle)?;
        let mut upload = upload.lock().unwrap_or_else(PoisonError::into_inner);
        let digest: [u8; 32] = std::mem::take(&mut upload.hasher).finalize().into();
        if let Some(expected) = sha256
            && expected != digest
        {
            return Err(err(
                ErrorKind::Conflict,
                "the sha256 does not match what was uploaded; the upload is discarded",
            ));
        }
        commit(&upload.tmp, &upload.file, &upload.target, upload.mode)
            .map_err(|e| io_error(&e, &display(&upload.target)))?;
        upload.done = true;
        Ok(Response::Written {
            size: upload.written,
            sha256: digest,
        })
    }

    /// `UploadAbort`.
    ///
    /// # Errors
    ///
    /// `NotFound` for an unknown handle.
    pub fn abort(&self, handle: u64) -> Result<Response, Error> {
        drop(self.take(handle)?);
        Ok(Response::Done)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occurrences() {
        assert_eq!(find_all(b"aaaa", b"aa"), vec![0, 2]);
        assert_eq!(find_all(b"abc", b"d"), Vec::<usize>::new());
        assert_eq!(find_all(b"xabxab", b"ab"), vec![1, 4]);
    }
}
