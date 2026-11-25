#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    aerobox_protocol_checks::vision::check(data);
});
