//! Frames: a big-endian `u32` length, then that many bytes of postcard.

use serde::{Serialize, de::DeserializeOwned};

/// The largest frame either side ever sends or accepts: 16 MiB.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// The largest hello or relay preamble frame: 64 KiB.
pub const MAX_HELLO_FRAME: usize = 64 * 1024;

/// A frame that cannot be encoded or decoded.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The length prefix names more bytes than the cap allows. Checked
    /// before anything is allocated for the body.
    #[error("frame of {len} bytes exceeds the cap of {max} bytes")]
    TooLarge { len: usize, max: usize },
    /// The body is not a valid postcard encoding of the expected message,
    /// or it has bytes left over after it.
    #[error("undecodable frame: {0}")]
    Decode(String),
    /// The message cannot be encoded.
    #[error("unencodable message: {0}")]
    Encode(String),
}

/// Encodes `message` as one frame (length prefix included).
///
/// # Errors
///
/// [`FrameError::TooLarge`] when the encoding exceeds [`MAX_FRAME`].
pub fn encode_frame<T: Serialize>(message: &T) -> Result<Vec<u8>, FrameError> {
    let mut out = vec![0u8; 4];
    out = postcard::to_extend(message, out).map_err(|e| FrameError::Encode(e.to_string()))?;
    let len = out.len() - 4;
    if len > MAX_FRAME {
        return Err(FrameError::TooLarge {
            len,
            max: MAX_FRAME,
        });
    }
    let prefix = u32::try_from(len).map_err(|_| FrameError::TooLarge {
        len,
        max: MAX_FRAME,
    })?;
    out[..4].copy_from_slice(&prefix.to_be_bytes());
    Ok(out)
}

/// Decodes one frame body (without its length prefix), refusing bytes left
/// over after the message.
///
/// # Errors
///
/// [`FrameError::Decode`] when the body is not exactly one `T`.
pub fn decode<T: DeserializeOwned>(body: &[u8]) -> Result<T, FrameError> {
    let (value, rest) =
        postcard::take_from_bytes::<T>(body).map_err(|e| FrameError::Decode(e.to_string()))?;
    if !rest.is_empty() {
        return Err(FrameError::Decode(format!(
            "{} bytes left over after the message",
            rest.len()
        )));
    }
    Ok(value)
}

/// An incremental frame decoder: feed it bytes as they arrive, take whole
/// frame bodies out.
///
/// It never holds more than the cap plus the bytes of one `feed` call: the
/// length prefix is checked against the cap as soon as its four bytes are
/// in, before the body is waited for.
#[derive(Debug)]
pub struct FrameDecoder {
    buf: Vec<u8>,
    start: usize,
    max: usize,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    /// A decoder with the [`MAX_FRAME`] cap.
    #[must_use]
    pub fn new() -> Self {
        Self::with_max(MAX_FRAME)
    }

    /// A decoder with a smaller cap, for the hello phase.
    #[must_use]
    pub fn with_max(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            max: max.min(MAX_FRAME),
        }
    }

    /// Changes the cap (never above [`MAX_FRAME`]), keeping buffered bytes.
    pub fn set_max(&mut self, max: usize) {
        self.max = max.min(MAX_FRAME);
    }

    /// Appends received bytes.
    pub fn feed(&mut self, bytes: &[u8]) {
        if self.start > 0 && self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        self.buf.extend_from_slice(bytes);
    }

    /// The bytes buffered but not yet taken as frames.
    #[must_use]
    pub fn buffered(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    /// Takes the next whole frame body, `None` when more bytes are needed.
    ///
    /// # Errors
    ///
    /// [`FrameError::TooLarge`] as soon as a length prefix exceeds the cap;
    /// the stream cannot be resynchronised after it.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FrameError> {
        let pending = &self.buf[self.start..];
        if pending.len() < 4 {
            self.compact();
            return Ok(None);
        }
        let len = u32::from_be_bytes([pending[0], pending[1], pending[2], pending[3]]) as usize;
        if len > self.max {
            return Err(FrameError::TooLarge { len, max: self.max });
        }
        if pending.len() < 4 + len {
            self.compact();
            return Ok(None);
        }
        let body = pending[4..4 + len].to_vec();
        self.start += 4 + len;
        self.compact();
        Ok(Some(body))
    }

    fn compact(&mut self) {
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        } else if self.start > 64 * 1024 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_in_pieces() {
        let a = encode_frame(&(1u32, "hello".to_string())).unwrap();
        let b = encode_frame(&vec![7u8; 1000]).unwrap();
        let mut all = a.clone();
        all.extend_from_slice(&b);
        let mut d = FrameDecoder::new();
        let mut frames = Vec::new();
        for byte in &all {
            d.feed(std::slice::from_ref(byte));
            while let Some(f) = d.next_frame().unwrap() {
                frames.push(f);
            }
        }
        assert_eq!(frames.len(), 2);
        assert_eq!(
            decode::<(u32, String)>(&frames[0]).unwrap(),
            (1, "hello".into())
        );
        assert_eq!(decode::<Vec<u8>>(&frames[1]).unwrap(), vec![7u8; 1000]);
    }

    #[test]
    fn oversized_length_refused_before_the_body() {
        let mut d = FrameDecoder::new();
        let len = u32::try_from(MAX_FRAME + 1).unwrap();
        d.feed(&len.to_be_bytes());
        assert!(matches!(d.next_frame(), Err(FrameError::TooLarge { .. })));
        let mut d = FrameDecoder::with_max(10);
        d.feed(&11u32.to_be_bytes());
        assert!(matches!(
            d.next_frame(),
            Err(FrameError::TooLarge { len: 11, max: 10 })
        ));
    }

    #[test]
    fn leftover_bytes_refused() {
        let mut body = postcard::to_stdvec(&5u32).unwrap();
        body.push(0);
        assert!(decode::<u32>(&body).is_err());
    }
}
