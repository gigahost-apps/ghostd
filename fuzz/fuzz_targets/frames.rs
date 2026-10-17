//! Arbitrary bytes into the frame decoder, the marker scanner and every
//! message decoder: none may panic or allocate past the caps.

#![no_main]

use ghostd_protocol::{
    ClientHello, FrameDecoder, HelloAnswer, MarkerScanner, RelayInfo, ServerHello, decode, v1, v2,
};
use libfuzzer_sys::fuzz_target;

fn messages(body: &[u8]) {
    let _ = decode::<v1::ClientFrame>(body);
    let _ = decode::<v1::ServerFrame>(body);
    let _ = decode::<v2::ClientFrame>(body);
    let _ = decode::<v2::ServerFrame>(body);
}

fuzz_target!(|data: &[u8]| {
    messages(data);
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
            messages(&body);
        }
    }
});
