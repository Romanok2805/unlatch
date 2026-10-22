#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| unlatch::fuzz::passkey(data));
