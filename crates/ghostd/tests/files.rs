//! File requests.

#![allow(clippy::too_many_lines)]

mod common;

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{PermissionsExt, symlink};

use common::Env;
use ghostd_client::{ClientError, Connection};
use ghostd_protocol::v1::{ErrorKind, FileKind, Request, Response};
use sha2::{Digest, Sha256};

async fn call(c: &Connection, r: Request) -> Response {
    c.call(r).await.unwrap()
}

async fn fails(c: &Connection, r: Request) -> ErrorKind {
    match c.call(r).await {
        Err(ClientError::Remote(e)) => e.kind,
        other => panic!("{other:?}"),
    }
}

fn mode(path: &std::path::Path) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}

fn temps(dir: &std::path::Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            std::path::Path::new(n)
                .extension()
                .is_some_and(|e| e == "tmp")
        })
        .collect()
}

#[tokio::test]
async fn read_write_and_stat() {
    let env = Env::new();
    let c = env.connect().await;
    let Response::Written { size, sha256 } = call(
        &c,
        Request::FileWrite {
            path: b"dir/a.txt".to_vec(),
            data: b"hello world".to_vec(),
            mode: None,
            create_dirs: true,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(size, 11);
    assert_eq!(sha256, <[u8; 32]>::from(Sha256::digest(b"hello world")));
    let path = env.home.join("dir/a.txt");
    assert_eq!(fs::read(&path).unwrap(), b"hello world");
    assert_eq!(mode(&path), 0o644);
    // A replaced file keeps its mode.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o751)).unwrap();
    call(
        &c,
        Request::FileWrite {
            path: path.as_os_str().as_bytes().to_vec(),
            data: b"second".to_vec(),
            mode: None,
            create_dirs: false,
        },
    )
    .await;
    assert_eq!(fs::read(&path).unwrap(), b"second");
    assert_eq!(mode(&path), 0o751);
    assert!(temps(&env.home.join("dir")).is_empty());
    let Response::FileData { data, size, eof } = call(
        &c,
        Request::FileRead {
            path: b"dir/a.txt".to_vec(),
            offset: 2,
            len: 3,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!((data.as_slice(), size, eof), (&b"con"[..], 6, false));
    let Response::FileData { data, eof, .. } = call(
        &c,
        Request::FileRead {
            path: b"dir/a.txt".to_vec(),
            offset: 4,
            len: 100,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!((data.as_slice(), eof), (&b"nd"[..], true));
    let Response::Stat(stat) = call(
        &c,
        Request::FileStat {
            path: b"dir/a.txt".to_vec(),
            follow: false,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(
        (stat.kind, stat.size, stat.mode),
        (FileKind::File, 6, 0o751)
    );
    symlink("a.txt", env.home.join("dir/link")).unwrap();
    let Response::Stat(link) = call(
        &c,
        Request::FileStat {
            path: b"dir/link".to_vec(),
            follow: false,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(link.kind, FileKind::Symlink);
    assert_eq!(link.link_target.as_deref(), Some(&b"a.txt"[..]));
    // Writing through a symlink replaces its target, not the link.
    call(
        &c,
        Request::FileWrite {
            path: b"dir/link".to_vec(),
            data: b"via link".to_vec(),
            mode: None,
            create_dirs: false,
        },
    )
    .await;
    assert!(
        fs::symlink_metadata(env.home.join("dir/link"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(fs::read(&path).unwrap(), b"via link");
    assert_eq!(
        fails(
            &c,
            Request::FileRead {
                path: b"missing".to_vec(),
                offset: 0,
                len: 1
            }
        )
        .await,
        ErrorKind::NotFound
    );
    assert_eq!(
        fails(
            &c,
            Request::FileRead {
                path: b"x".to_vec(),
                offset: 0,
                len: 9 * 1024 * 1024
            }
        )
        .await,
        ErrorKind::TooLarge
    );
}

#[tokio::test]
async fn uploads() {
    let env = Env::new();
    let c = env.connect().await;
    let data: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    let Response::Upload { handle } = call(
        &c,
        Request::UploadBegin {
            path: b"up/big.bin".to_vec(),
            mode: Some(0o600),
            create_dirs: true,
        },
    )
    .await
    else {
        panic!()
    };
    let mut offset = 0;
    for chunk in data.chunks(100_000) {
        call(
            &c,
            Request::UploadChunk {
                handle,
                offset,
                data: chunk.to_vec(),
            },
        )
        .await;
        offset += chunk.len() as u64;
    }
    // A gap is refused.
    assert_eq!(
        fails(
            &c,
            Request::UploadChunk {
                handle,
                offset: 1,
                data: b"x".to_vec()
            }
        )
        .await,
        ErrorKind::InvalidArgument
    );
    let sha: [u8; 32] = Sha256::digest(&data).into();
    let Response::Written { size, sha256 } = call(
        &c,
        Request::UploadEnd {
            handle,
            sha256: Some(sha),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!((size, sha256), (data.len() as u64, sha));
    let target = env.home.join("up/big.bin");
    assert_eq!(fs::read(&target).unwrap(), data);
    assert_eq!(mode(&target), 0o600);
    // A wrong hash discards the upload and keeps the old file.
    let Response::Upload { handle } = call(
        &c,
        Request::UploadBegin {
            path: b"up/big.bin".to_vec(),
            mode: None,
            create_dirs: false,
        },
    )
    .await
    else {
        panic!()
    };
    call(
        &c,
        Request::UploadChunk {
            handle,
            offset: 0,
            data: b"other".to_vec(),
        },
    )
    .await;
    assert_eq!(
        fails(
            &c,
            Request::UploadEnd {
                handle,
                sha256: Some([0; 32])
            }
        )
        .await,
        ErrorKind::Conflict
    );
    assert_eq!(fs::read(&target).unwrap(), data);
    assert!(temps(&env.home.join("up")).is_empty());
    // An abandoned upload's temp file goes with the connection.
    let Response::Upload { .. } = call(
        &c,
        Request::UploadBegin {
            path: b"up/abandoned".to_vec(),
            mode: None,
            create_dirs: false,
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(temps(&env.home.join("up")).len(), 1);
    drop(c);
    env.wait_for("the temp file removed", || {
        temps(&env.home.join("up")).is_empty()
    });
    assert!(!env.home.join("up/abandoned").exists());
}

#[tokio::test]
async fn edits() {
    let env = Env::new();
    let c = env.connect().await;
    let path = env.home.join("e.txt");
    fs::write(&path, b"one two two three").unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let edit = |old: &[u8], new: &[u8], all: bool| Request::FileEdit {
        path: b"e.txt".to_vec(),
        old: old.to_vec(),
        new: new.to_vec(),
        replace_all: all,
    };
    assert_eq!(
        fails(&c, edit(b"four", b"4", false)).await,
        ErrorKind::NotFound
    );
    assert_eq!(
        fails(&c, edit(b"two", b"2", false)).await,
        ErrorKind::Conflict
    );
    let Response::Edited { replacements, .. } = call(&c, edit(b"one", b"1", false)).await else {
        panic!()
    };
    assert_eq!(replacements, 1);
    let Response::Edited {
        replacements,
        sha256,
    } = call(&c, edit(b"two", b"2", true)).await
    else {
        panic!()
    };
    assert_eq!(replacements, 2);
    assert_eq!(fs::read(&path).unwrap(), b"1 2 2 three");
    assert_eq!(sha256, <[u8; 32]>::from(Sha256::digest(b"1 2 2 three")));
    assert_eq!(mode(&path), 0o640);
}

#[tokio::test]
async fn listings() {
    let env = Env::new();
    let c = env.connect().await;
    let root = env.home.join("tree");
    fs::create_dir_all(root.join("b/deep/deeper")).unwrap();
    fs::write(root.join("a.txt"), b"a").unwrap();
    fs::write(root.join(".hidden"), b"h").unwrap();
    fs::write(root.join("b/c.txt"), b"c").unwrap();
    fs::write(root.join("b/deep/deeper/d.txt"), b"d").unwrap();
    symlink("b", root.join("link")).unwrap();
    let odd = std::ffi::OsStr::from_bytes(b"odd\xff");
    fs::write(root.join(odd), b"o").unwrap();
    let list = |depth, max| Request::FileList {
        path: b"tree".to_vec(),
        depth,
        max_entries: max,
    };
    let Response::Listing { entries, truncated } = call(&c, list(1, 0)).await else {
        panic!()
    };
    let names: Vec<&[u8]> = entries.iter().map(|(n, _)| n.as_slice()).collect();
    assert_eq!(
        names,
        vec![&b".hidden"[..], b"a.txt", b"b", b"link", b"odd\xff"]
    );
    assert!(!truncated);
    let link = &entries[3].1;
    assert_eq!(link.kind, FileKind::Symlink);
    let Response::Listing { entries, .. } = call(&c, list(16, 0)).await else {
        panic!()
    };
    let names: Vec<String> = entries
        .iter()
        .map(|(n, _)| String::from_utf8_lossy(n).into_owned())
        .collect();
    assert!(
        names.contains(&"b/deep/deeper/d.txt".to_string()),
        "{names:?}"
    );
    // The symlinked directory is not entered.
    assert!(!names.iter().any(|n| n.starts_with("link/")), "{names:?}");
    let Response::Listing { entries, .. } = call(&c, list(2, 0)).await else {
        panic!()
    };
    assert!(entries.iter().any(|(n, _)| n == b"b/deep"));
    assert!(!entries.iter().any(|(n, _)| n == b"b/deep/deeper"));
    let Response::Listing { entries, truncated } = call(&c, list(16, 3)).await else {
        panic!()
    };
    assert_eq!(entries.len(), 3);
    assert!(truncated);
    assert_eq!(fails(&c, list(17, 0)).await, ErrorKind::InvalidArgument);
}

#[tokio::test]
async fn searches() {
    let env = Env::new();
    let c = env.connect().await;
    let root = env.home.join("repo");
    fs::create_dir_all(root.join(".git")).unwrap();
    fs::create_dir_all(root.join("src")).unwrap();
    fs::create_dir_all(root.join("target")).unwrap();
    fs::write(root.join(".gitignore"), b"target/\n").unwrap();
    fs::write(
        root.join("src/main.rs"),
        b"fn main() {\n    Needle();\n}\nneedle again\n",
    )
    .unwrap();
    fs::write(root.join("src/lib.txt"), b"a needle\n").unwrap();
    fs::write(root.join("target/out.rs"), b"needle ignored\n").unwrap();
    fs::write(root.join("bin.dat"), b"needle\0binary").unwrap();
    fs::write(root.join(".hidden.rs"), b"needle hidden\n").unwrap();
    let search = |pattern: &str, globs: &[&str], ci: bool, hidden: bool, max| Request::FileSearch {
        pattern: pattern.into(),
        path: b"repo".to_vec(),
        globs: globs.iter().map(|g| (*g).to_string()).collect(),
        case_insensitive: ci,
        hidden,
        max_matches: max,
    };
    let Response::Matches { matches, truncated } =
        call(&c, search("needle", &[], false, false, 0)).await
    else {
        panic!()
    };
    let found: Vec<(String, u64)> = matches
        .iter()
        .map(|m| (String::from_utf8_lossy(&m.path).into_owned(), m.line_number))
        .collect();
    assert_eq!(
        found,
        vec![
            ("src/lib.txt".to_string(), 1),
            ("src/main.rs".to_string(), 4)
        ]
    );
    assert!(!truncated);
    assert_eq!(matches[0].line, b"a needle");
    let Response::Matches { matches, .. } =
        call(&c, search("needle", &["*.rs"], true, true, 0)).await
    else {
        panic!()
    };
    let found: Vec<(String, u64)> = matches
        .iter()
        .map(|m| (String::from_utf8_lossy(&m.path).into_owned(), m.line_number))
        .collect();
    assert_eq!(
        found,
        vec![
            (".hidden.rs".to_string(), 1),
            ("src/main.rs".to_string(), 2),
            ("src/main.rs".to_string(), 4)
        ]
    );
    let Response::Matches { matches, truncated } =
        call(&c, search("needle", &[], true, false, 1)).await
    else {
        panic!()
    };
    assert_eq!(matches.len(), 1);
    assert!(truncated);
    assert_eq!(
        fails(&c, search("(", &[], false, false, 0)).await,
        ErrorKind::InvalidArgument
    );
}

#[tokio::test]
async fn hash_remove_rename_mkdir() {
    let env = Env::new();
    let c = env.connect().await;
    fs::write(env.home.join("h"), b"hash me").unwrap();
    let Response::Hash { size, sha256 } = call(
        &c,
        Request::FileHash {
            path: b"h".to_vec(),
        },
    )
    .await
    else {
        panic!()
    };
    assert_eq!(
        (size, sha256),
        (7, <[u8; 32]>::from(Sha256::digest(b"hash me")))
    );
    call(
        &c,
        Request::FileMkdir {
            path: b"m/n/o".to_vec(),
            parents: true,
            mode: Some(0o700),
        },
    )
    .await;
    assert_eq!(mode(&env.home.join("m/n/o")), 0o700);
    assert_eq!(
        fails(
            &c,
            Request::FileMkdir {
                path: b"x/y".to_vec(),
                parents: false,
                mode: None
            }
        )
        .await,
        ErrorKind::NotFound
    );
    fs::write(env.home.join("other"), b"o").unwrap();
    assert_eq!(
        fails(
            &c,
            Request::FileRename {
                from: b"h".to_vec(),
                to: b"other".to_vec(),
                overwrite: false
            }
        )
        .await,
        ErrorKind::AlreadyExists
    );
    call(
        &c,
        Request::FileRename {
            from: b"h".to_vec(),
            to: b"m/moved".to_vec(),
            overwrite: false,
        },
    )
    .await;
    assert_eq!(fs::read(env.home.join("m/moved")).unwrap(), b"hash me");
    call(
        &c,
        Request::FileRename {
            from: b"m/moved".to_vec(),
            to: b"other".to_vec(),
            overwrite: true,
        },
    )
    .await;
    assert_eq!(fs::read(env.home.join("other")).unwrap(), b"hash me");
    assert_eq!(
        fails(
            &c,
            Request::FileRemove {
                path: b"m".to_vec(),
                recursive: false
            }
        )
        .await,
        ErrorKind::Conflict
    );
    call(
        &c,
        Request::FileRemove {
            path: b"m".to_vec(),
            recursive: true,
        },
    )
    .await;
    assert!(!env.home.join("m").exists());
    assert_eq!(
        fails(
            &c,
            Request::FileRemove {
                path: Vec::new(),
                recursive: true
            }
        )
        .await,
        ErrorKind::InvalidArgument
    );
    // Non-UTF-8 names end to end.
    let name = b"bytes\xfe\xff.txt".to_vec();
    call(
        &c,
        Request::FileWrite {
            path: name.clone(),
            data: b"x".to_vec(),
            mode: None,
            create_dirs: false,
        },
    )
    .await;
    assert!(env.home.join(std::ffi::OsStr::from_bytes(&name)).exists());
    call(
        &c,
        Request::FileRemove {
            path: name,
            recursive: false,
        },
    )
    .await;
}

#[tokio::test]
async fn a_replaced_file_keeps_its_group_and_attributes() {
    use std::os::unix::fs::MetadataExt;
    let env = Env::new();
    let c = env.connect().await;
    // A group of ours other than the one new files get: what a non-root
    // user can give a file (root keeps the owner the same way).
    let primary = nix::unistd::getegid();
    let Some(group) = nix::unistd::getgroups()
        .unwrap_or_default()
        .into_iter()
        .find(|g| *g != primary)
    else {
        eprintln!("skipped: this user is in no second group");
        return;
    };
    let path = env.home.join("conf");
    fs::write(&path, b"a = 1\n").unwrap();
    std::os::unix::fs::chown(&path, None, Some(group.as_raw())).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let attributes = rustix::fs::setxattr(
        &path,
        "user.ghostd-test",
        b"kept",
        rustix::fs::XattrFlags::empty(),
    )
    .is_ok();
    let check = |what: &str| {
        let meta = fs::metadata(&path).unwrap();
        assert_eq!(meta.gid(), group.as_raw(), "{what} changed the group");
        assert_eq!(meta.mode() & 0o7777, 0o640, "{what} changed the mode");
        if attributes {
            let mut value = [0u8; 16];
            let n = rustix::fs::getxattr(&path, "user.ghostd-test", &mut value[..])
                .unwrap_or_else(|e| panic!("{what} dropped the attribute: {e}"));
            assert_eq!(&value[..n], b"kept");
        }
    };
    call(
        &c,
        Request::FileWrite {
            path: b"conf".to_vec(),
            data: b"a = 2\n".to_vec(),
            mode: None,
            create_dirs: false,
        },
    )
    .await;
    check("a write");
    call(
        &c,
        Request::FileEdit {
            path: b"conf".to_vec(),
            old: b"2".to_vec(),
            new: b"3".to_vec(),
            replace_all: false,
        },
    )
    .await;
    check("an edit");
    let Response::Upload { handle } = call(
        &c,
        Request::UploadBegin {
            path: b"conf".to_vec(),
            mode: None,
            create_dirs: false,
        },
    )
    .await
    else {
        panic!()
    };
    call(
        &c,
        Request::UploadChunk {
            handle,
            offset: 0,
            data: b"a = 4\n".to_vec(),
        },
    )
    .await;
    call(
        &c,
        Request::UploadEnd {
            handle,
            sha256: None,
        },
    )
    .await;
    check("an upload");
    assert_eq!(fs::read(&path).unwrap(), b"a = 4\n");
    if !attributes {
        eprintln!("attributes not checked: the file system takes no user attributes");
    }
}
