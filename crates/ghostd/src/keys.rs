//! Keys typed into a session, as the bytes an xterm sends for them.

use ghostd_protocol::v2::{Error, ErrorKind, Key, NamedKey};

/// The bytes for `keys`. `application_cursor`: the program asked for the
/// application cursor-key mode (`ESC [ ? 1 h`), in which the arrows, Home
/// and End are sent as `ESC O x` instead of `ESC [ x`.
///
/// # Errors
///
/// `InvalidArgument` for a `Ctrl` of a character that has none.
pub fn encode(keys: &[Key], application_cursor: bool) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    for key in keys {
        match key {
            Key::Text(text) => out.extend_from_slice(text.as_bytes()),
            Key::Bytes(bytes) => out.extend_from_slice(bytes),
            Key::Named(named) => named_key(*named, application_cursor, &mut out)?,
        }
    }
    Ok(out)
}

fn named_key(key: NamedKey, application_cursor: bool, out: &mut Vec<u8>) -> Result<(), Error> {
    let cursor = |c: u8| -> Vec<u8> {
        if application_cursor {
            vec![0x1b, b'O', c]
        } else {
            vec![0x1b, b'[', c]
        }
    };
    let bytes: Vec<u8> = match key {
        NamedKey::Enter => b"\r".to_vec(),
        NamedKey::Tab => b"\t".to_vec(),
        NamedKey::Escape => b"\x1b".to_vec(),
        NamedKey::Backspace => b"\x7f".to_vec(),
        NamedKey::Delete => b"\x1b[3~".to_vec(),
        NamedKey::Up => cursor(b'A'),
        NamedKey::Down => cursor(b'B'),
        NamedKey::Right => cursor(b'C'),
        NamedKey::Left => cursor(b'D'),
        NamedKey::Home => cursor(b'H'),
        NamedKey::End => cursor(b'F'),
        NamedKey::PageUp => b"\x1b[5~".to_vec(),
        NamedKey::PageDown => b"\x1b[6~".to_vec(),
        NamedKey::Insert => b"\x1b[2~".to_vec(),
        NamedKey::F1 => b"\x1bOP".to_vec(),
        NamedKey::F2 => b"\x1bOQ".to_vec(),
        NamedKey::F3 => b"\x1bOR".to_vec(),
        NamedKey::F4 => b"\x1bOS".to_vec(),
        NamedKey::F5 => b"\x1b[15~".to_vec(),
        NamedKey::F6 => b"\x1b[17~".to_vec(),
        NamedKey::F7 => b"\x1b[18~".to_vec(),
        NamedKey::F8 => b"\x1b[19~".to_vec(),
        NamedKey::F9 => b"\x1b[20~".to_vec(),
        NamedKey::F10 => b"\x1b[21~".to_vec(),
        NamedKey::F11 => b"\x1b[23~".to_vec(),
        NamedKey::F12 => b"\x1b[24~".to_vec(),
        NamedKey::Ctrl(c) => vec![ctrl(c)?],
        NamedKey::Alt(c) => {
            let mut bytes = vec![0x1b];
            let mut buf = [0u8; 4];
            bytes.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            bytes
        }
    };
    out.extend_from_slice(&bytes);
    Ok(())
}

fn ctrl(c: char) -> Result<u8, Error> {
    match c {
        'a'..='z' => Ok(c as u8 - b'a' + 1),
        'A'..='Z' => Ok(c as u8 - b'A' + 1),
        '[' => Ok(0x1b),
        '\\' => Ok(0x1c),
        ']' => Ok(0x1d),
        '^' => Ok(0x1e),
        '_' => Ok(0x1f),
        _ => Err(Error::new(
            ErrorKind::InvalidArgument,
            format!("Ctrl({c:?}) has no key: a letter, [, \\, ], ^ or _"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys() {
        let keys = [
            Key::Text("ls".into()),
            Key::Named(NamedKey::Enter),
            Key::Named(NamedKey::Ctrl('c')),
            Key::Named(NamedKey::Ctrl('D')),
            Key::Named(NamedKey::Alt('x')),
            Key::Named(NamedKey::Up),
            Key::Bytes(vec![0xff]),
        ];
        assert_eq!(
            encode(&keys, false).unwrap(),
            b"ls\r\x03\x04\x1bx\x1b[A\xff".to_vec()
        );
        assert_eq!(
            encode(&[Key::Named(NamedKey::Up), Key::Named(NamedKey::End)], true).unwrap(),
            b"\x1bOA\x1bOF".to_vec()
        );
        assert_eq!(
            encode(&[Key::Named(NamedKey::F5)], true).unwrap(),
            b"\x1b[15~".to_vec()
        );
        assert!(encode(&[Key::Named(NamedKey::Ctrl('1'))], false).is_err());
    }
}
