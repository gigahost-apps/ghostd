//! The protocol of a session shim's socket (`<session dir>/shim.sock`),
//! spoken by the worker. It opens like a client connection, with the
//! frozen marker and hellos ([`ghostd_protocol::ServerHello`] and the
//! rest), then carries frames of this module's messages, one request and
//! its answer at a time. A change to a message is a new [`VERSION`]: a shim
//! outlives the worker that started it (an update, a rollback), so the
//! worker of another build may be the one that talks to it.
//!
//! The payloads reuse protocol version 2's types, which never change.

use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;

use ghostd_protocol::v2::{Error, ErrorKind, Key, Screen, Until};
use ghostd_protocol::{
    ClientHello, FrameDecoder, HelloAnswer, MARKER, MAX_HELLO_FRAME, ServerHello, decode,
    encode_frame, negotiate,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The version of this module's messages.
pub const VERSION: u32 = 1;

/// The largest frame either side sends: requests and screens are small.
pub const MAX_SHIM_FRAME: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShimRequest {
    /// Queues the keys' bytes for the PTY.
    Send(Vec<Key>),
    Read {
        wait_ms: u64,
        until: Option<Until>,
        scrollback_lines: u32,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    /// To the PTY's foreground process group.
    Signal(i32),
    /// Hangs up and stops the session's whole tree; answered at once.
    Close {
        grace_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShimResponse {
    Done,
    Screen(Screen),
}

pub type ShimAnswer = Result<ShimResponse, Error>;

/// Reads one frame of at most `max` bytes from a blocking stream; `None`
/// at EOF.
///
/// # Errors
///
/// When reading fails or the frame is over the cap.
pub fn read_frame_blocking<R: Read>(
    reader: &mut R,
    decoder: &mut FrameDecoder,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = [0u8; 16 * 1024];
    loop {
        if let Some(frame) = decoder
            .next_frame()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
        {
            return Ok(Some(frame));
        }
        let n = reader.read(&mut buf)?;
        if n == 0 {
            return Ok(None);
        }
        decoder.feed(&buf[..n]);
    }
}

/// The shim's side of the opening: marker, hello, the worker's hello, the
/// answer. `true` when they agreed on [`VERSION`].
///
/// # Errors
///
/// When the stream fails.
pub fn accept_hello<S: Read + Write>(
    stream: &mut S,
    decoder: &mut FrameDecoder,
) -> std::io::Result<bool> {
    let mut opening = MARKER.to_vec();
    opening.extend(frame(&ServerHello {
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        min: VERSION,
        max: VERSION,
    })?);
    stream.write_all(&opening)?;
    decoder.set_max(MAX_HELLO_FRAME);
    let Some(body) = read_frame_blocking(stream, decoder)? else {
        return Ok(false);
    };
    let Ok(client) = decode::<ClientHello>(&body) else {
        return Ok(false);
    };
    let answer = match negotiate((VERSION, VERSION), (client.min, client.max)) {
        Some(version) => HelloAnswer::Welcome { version },
        None => HelloAnswer::Refused {
            server_min: VERSION,
            server_max: VERSION,
            message: format!(
                "this session's shim ({}) speaks {VERSION}..={VERSION}, the worker {}..={}",
                env!("CARGO_PKG_VERSION"),
                client.min,
                client.max
            ),
        },
    };
    let agreed = matches!(answer, HelloAnswer::Welcome { .. });
    stream.write_all(&frame(&answer)?)?;
    decoder.set_max(MAX_SHIM_FRAME);
    Ok(agreed)
}

/// One frame of `message`.
fn frame<T: Serialize>(message: &T) -> std::io::Result<Vec<u8>> {
    encode_frame(message)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Writes one answer frame.
///
/// # Errors
///
/// When the stream fails.
pub fn write_answer<W: Write>(stream: &mut W, answer: &ShimAnswer) -> std::io::Result<()> {
    stream.write_all(&frame(answer)?)
}

/// Why a call to a shim got no answer.
#[derive(Debug)]
pub enum CallError {
    /// No shim listens: it has exited (or never bound its socket).
    Unreachable,
    /// The shim answered with an error, or broke off.
    Failed(Error),
}

/// Sends one request to the shim of `dir` and waits up to `timeout` for
/// its answer.
///
/// # Errors
///
/// [`CallError::Unreachable`] when nothing listens, [`CallError::Failed`]
/// otherwise.
pub async fn call(
    dir: &Path,
    request: &ShimRequest,
    timeout: Duration,
) -> Result<ShimResponse, CallError> {
    let path = dir.join(crate::shim::SOCKET);
    let stream = tokio::net::UnixStream::connect(&path)
        .await
        .map_err(|_| CallError::Unreachable)?;
    match tokio::time::timeout(timeout, exchange(stream, request)).await {
        Ok(Ok(answer)) => answer.map_err(CallError::Failed),
        Ok(Err(message)) => Err(CallError::Failed(Error::new(
            ErrorKind::Internal,
            format!("the session's shim: {message}"),
        ))),
        Err(_) => Err(CallError::Failed(Error::new(
            ErrorKind::Internal,
            "the session's shim did not answer in time",
        ))),
    }
}

async fn exchange(
    mut stream: tokio::net::UnixStream,
    request: &ShimRequest,
) -> Result<ShimAnswer, String> {
    let mut decoder = FrameDecoder::with_max(MAX_HELLO_FRAME);
    let mut buf = vec![0u8; 16 * 1024];
    let mut opening = Vec::new();
    while opening.len() < MARKER.len() {
        let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("it closed before its hello".into());
        }
        opening.extend_from_slice(&buf[..n]);
    }
    if opening[..MARKER.len()] != MARKER {
        return Err("no marker".into());
    }
    decoder.feed(&opening[MARKER.len()..]);
    let hello = next(&mut stream, &mut decoder, &mut buf).await?;
    let _: ServerHello = decode(&hello).map_err(|e| e.to_string())?;
    let ours = ClientHello {
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        min: VERSION,
        max: VERSION,
    };
    let frame = encode_frame(&ours).map_err(|e| e.to_string())?;
    stream.write_all(&frame).await.map_err(|e| e.to_string())?;
    let answer = next(&mut stream, &mut decoder, &mut buf).await?;
    match decode::<HelloAnswer>(&answer).map_err(|e| e.to_string())? {
        HelloAnswer::Welcome { .. } => {}
        HelloAnswer::Refused { message, .. } => return Err(message),
    }
    decoder.set_max(MAX_SHIM_FRAME);
    let frame = encode_frame(request).map_err(|e| e.to_string())?;
    stream.write_all(&frame).await.map_err(|e| e.to_string())?;
    let body = next(&mut stream, &mut decoder, &mut buf).await?;
    decode::<ShimAnswer>(&body).map_err(|e| e.to_string())
}

async fn next(
    stream: &mut tokio::net::UnixStream,
    decoder: &mut FrameDecoder,
    buf: &mut [u8],
) -> Result<Vec<u8>, String> {
    loop {
        if let Some(frame) = decoder.next_frame().map_err(|e| e.to_string())? {
            return Ok(frame);
        }
        let n = stream.read(buf).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("it closed the connection".into());
        }
        decoder.feed(&buf[..n]);
    }
}
