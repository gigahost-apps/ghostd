//! The marker, the hellos and the relay preamble. FROZEN forever: see the
//! crate's versioning rule. Never change a field of these types.

use serde::{Deserialize, Serialize};

/// The lowest protocol version this build speaks.
pub const PROTOCOL_MIN: u32 = 1;
/// The highest protocol version this build speaks.
pub const PROTOCOL_MAX: u32 = 1;

/// The 16 bytes a server sends before its [`ServerHello`] frame, on every
/// connection. A client discards whatever comes before them (a login
/// shell's banner, say). They start with a NUL and hold `0xff`, which no
/// UTF-8 text contains, so shell output cannot produce them by accident.
pub const MARKER: [u8; 16] = *b"\x00\xffghostd-hello\x00\x01";

/// How many bytes a client discards while looking for the marker before it
/// gives up: 1 MiB.
pub const MAX_PREAMBLE_SCAN: usize = 1024 * 1024;

/// The server's first frame, right after the marker. FROZEN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerHello {
    /// The server program's version, for people (`0.1.0`).
    pub program_version: String,
    /// The lowest protocol version the server speaks.
    pub min: u32,
    /// The highest protocol version the server speaks.
    pub max: u32,
}

/// The client's first frame, sent after it read the [`ServerHello`]. FROZEN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientHello {
    /// The client program's version, for people.
    pub program_version: String,
    /// The lowest protocol version the client speaks.
    pub min: u32,
    /// The highest protocol version the client speaks.
    pub max: u32,
}

/// The server's answer to a [`ClientHello`]. FROZEN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HelloAnswer {
    /// Both sides speak `version` from here on.
    Welcome { version: u32 },
    /// No version in common; the server closes the connection after this.
    Refused {
        server_min: u32,
        server_max: u32,
        message: String,
    },
}

/// The first frame `ghostd stdio` writes to the daemon's Unix socket, before
/// any of the client's bytes. Local to the machine, never seen by a client.
/// FROZEN.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayInfo {
    /// The relay's `--client <label>`.
    pub client_label: Option<String>,
    /// `$SSH_CONNECTION` of the relay, when it runs under sshd.
    pub ssh_connection: Option<String>,
}

/// The highest version in both ranges, `None` when they do not overlap (or
/// a range is empty).
#[must_use]
pub fn negotiate(a: (u32, u32), b: (u32, u32)) -> Option<u32> {
    let low = a.0.max(b.0);
    let high = a.1.min(b.1);
    (a.0 <= a.1 && b.0 <= b.1 && low <= high).then_some(high)
}

/// Which side should update when two ranges do not overlap: `true` when
/// side `a` is the older one (its maximum is lower).
#[must_use]
pub fn outdated_side(a: (u32, u32), b: (u32, u32)) -> bool {
    a.1 < b.1
}

/// What [`MarkerScanner::feed`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum MarkerScan {
    /// No marker yet; feed more.
    NeedMore,
    /// The marker; `rest` holds the bytes after it.
    Found { rest: Vec<u8> },
    /// More than [`MAX_PREAMBLE_SCAN`] bytes came without a marker.
    TooMuch,
}

/// Looks for [`MARKER`] in a stream, discarding what comes before it, and
/// keeps the first 200 discarded bytes to show in an error.
#[derive(Debug, Default)]
pub struct MarkerScanner {
    window: Vec<u8>,
    head: Vec<u8>,
    discarded: usize,
}

const HEAD_KEPT: usize = 200;

impl MarkerScanner {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Feeds received bytes.
    pub fn feed(&mut self, bytes: &[u8]) -> MarkerScan {
        self.window.extend_from_slice(bytes);
        if let Some(pos) = self.window.windows(MARKER.len()).position(|w| w == MARKER) {
            let before: Vec<u8> = self.window[..pos].to_vec();
            self.discard(&before);
            let rest = self.window[pos + MARKER.len()..].to_vec();
            self.window.clear();
            return if self.discarded > MAX_PREAMBLE_SCAN {
                MarkerScan::TooMuch
            } else {
                MarkerScan::Found { rest }
            };
        }
        let keep = MARKER.len() - 1;
        if self.window.len() > keep {
            let cut = self.window.len() - keep;
            let gone: Vec<u8> = self.window.drain(..cut).collect();
            self.discard(&gone);
        }
        if self.discarded > MAX_PREAMBLE_SCAN {
            MarkerScan::TooMuch
        } else {
            MarkerScan::NeedMore
        }
    }

    fn discard(&mut self, bytes: &[u8]) {
        let room = HEAD_KEPT.saturating_sub(self.head.len());
        self.head.extend_from_slice(&bytes[..room.min(bytes.len())]);
        self.discarded += bytes.len();
    }

    /// The first 200 discarded bytes (and any still in the window, at EOF),
    /// as lossy text.
    #[must_use]
    pub fn discarded_text(&self) -> String {
        let mut head = self.head.clone();
        let room = HEAD_KEPT.saturating_sub(head.len());
        head.extend_from_slice(&self.window[..room.min(self.window.len())]);
        String::from_utf8_lossy(&head).into_owned()
    }

    /// How many bytes were discarded so far.
    #[must_use]
    pub fn discarded(&self) -> usize {
        self.discarded + self.window.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation() {
        assert_eq!(negotiate((1, 1), (1, 1)), Some(1));
        assert_eq!(negotiate((1, 3), (2, 5)), Some(3));
        // A newer client.
        assert_eq!(negotiate((1, 2), (1, 5)), Some(2));
        // An older client.
        assert_eq!(negotiate((2, 4), (1, 2)), Some(2));
        // Disjoint.
        assert_eq!(negotiate((1, 1), (2, 3)), None);
        assert_eq!(negotiate((3, 4), (1, 2)), None);
        // An empty range.
        assert_eq!(negotiate((2, 1), (1, 3)), None);
        assert!(outdated_side((1, 1), (2, 3)));
        assert!(!outdated_side((3, 4), (1, 2)));
    }

    #[test]
    fn marker_found_across_feeds() {
        let mut s = MarkerScanner::new();
        let mut stream = b"Welcome to the machine\r\n".to_vec();
        stream.extend_from_slice(&MARKER);
        stream.extend_from_slice(b"after");
        let chunks: Vec<&[u8]> = stream.chunks(3).collect();
        let mut rest = None;
        for (i, chunk) in chunks.iter().enumerate() {
            if let MarkerScan::Found { rest: mut r } = s.feed(chunk) {
                for later in &chunks[i + 1..] {
                    r.extend_from_slice(later);
                }
                rest = Some(r);
                break;
            }
        }
        assert_eq!(rest.as_deref(), Some(&b"after"[..]));
        assert_eq!(s.discarded_text(), "Welcome to the machine\r\n");
    }

    #[test]
    fn too_much_junk() {
        let mut s = MarkerScanner::new();
        let junk = vec![b'x'; 64 * 1024];
        let mut last = MarkerScan::NeedMore;
        for _ in 0..17 {
            last = s.feed(&junk);
        }
        assert_eq!(last, MarkerScan::TooMuch);
        assert_eq!(s.discarded_text().len(), 200);
    }

    #[test]
    fn hellos_are_frozen() {
        // The exact bytes of the hellos: changing these breaks every
        // installed client or server. Never update this test.
        let hello = ServerHello {
            program_version: "0.1.0".into(),
            min: 1,
            max: 1,
        };
        assert_eq!(
            postcard::to_stdvec(&hello).unwrap(),
            b"\x050.1.0\x01\x01".to_vec()
        );
        let client = ClientHello {
            program_version: "x".into(),
            min: 1,
            max: 300,
        };
        assert_eq!(
            postcard::to_stdvec(&client).unwrap(),
            b"\x01x\x01\xac\x02".to_vec()
        );
        assert_eq!(
            postcard::to_stdvec(&HelloAnswer::Welcome { version: 1 }).unwrap(),
            vec![0, 1]
        );
        let refused = HelloAnswer::Refused {
            server_min: 1,
            server_max: 2,
            message: "m".into(),
        };
        assert_eq!(
            postcard::to_stdvec(&refused).unwrap(),
            vec![1, 1, 2, 1, b'm']
        );
        let relay = RelayInfo {
            client_label: Some("a".into()),
            ssh_connection: None,
        };
        assert_eq!(postcard::to_stdvec(&relay).unwrap(), vec![1, 1, b'a', 0]);
        assert_eq!(&MARKER, b"\x00\xffghostd-hello\x00\x01");
    }
}
