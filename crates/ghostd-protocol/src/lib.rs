//! The wire protocol of `ghostd`.
//!
//! A connection is a byte stream (an SSH channel's stdin and stdout, or the
//! daemon's Unix socket). The server opens it with [`MARKER`] and a
//! [`ServerHello`] frame; the client answers with a [`ClientHello`]; the
//! server answers that with a [`HelloAnswer`]. After a
//! [`HelloAnswer::Welcome`] both sides speak the agreed protocol version's
//! messages: those of [`v1`] or of [`v2`].
//!
//! # Versioning rule
//!
//! The marker, the frame format, the hellos and the relay preamble
//! ([`RelayInfo`]) are FROZEN forever: no field is ever added, removed,
//! reordered or retyped, so that every client and every server of every
//! release can always tell each other which versions they speak.
//!
//! Any change to any message after the hellos, however small, is a new
//! protocol version in a new module (`v2`, reusing the unchanged types of
//! `v1`), with [`PROTOCOL_MAX`] raised. The server keeps speaking the older
//! versions for a support window and only then raises [`PROTOCOL_MIN`].
//! There is no schema exchange and there are no unknown fields: postcard
//! encodes neither field names nor tags beyond enum variant indexes, so a
//! message is only ever decoded by the version that defined it.

mod frame;
mod hello;
pub mod v1;
pub mod v2;

pub use frame::{FrameDecoder, FrameError, MAX_FRAME, MAX_HELLO_FRAME, decode, encode_frame};
pub use hello::{
    ClientHello, HelloAnswer, MARKER, MAX_PREAMBLE_SCAN, MarkerScan, MarkerScanner, PROTOCOL_MAX,
    PROTOCOL_MIN, RelayInfo, ServerHello, negotiate, outdated_side,
};
