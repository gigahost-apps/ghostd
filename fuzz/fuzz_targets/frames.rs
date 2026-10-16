//! Arbitrary bytes into the frame decoder, the marker scanner and every
//! message decoder: none may panic or allocate past the caps.

#![no_main]

use ghostd_protocol::v1::{ClientFrame, ServerFrame};
use ghostd_protocol::{
    ClientHello, FrameDecoder, HelloAnswer, MarkerScanner, RelayInfo, ServerHello, decode,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = decode::<ClientFrame>(data);
    let _ = decode::<ServerFrame>(data);
    let _ = decode::<ServerHello>(data);
    let _ = decode::<ClientHello>(data);
    let _ = decode::<HelloAnswer>(data);
    let _ = decode::<RelayInfo>(data);
    let mut scanner = MarkerScanner::new();
    let _ = scanner.feed(data);
    let mut decoder = FrameDecoder::new();
    for chunk in data.chunks(7) {
        decoder.feed(chunk);
        while let Ok(Some(body)) = decoder.next_frame() {
            let _ = decode::<ClientFrame>(&body);
            let _ = decode::<ServerFrame>(&body);
        }
    }
});
