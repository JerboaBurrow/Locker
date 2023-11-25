#![no_main]

use libfuzzer_sys::fuzz_target;

extern crate locker;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let v = vec!(s.to_string());
        let _ = locker::arguments::extract_arguments(v);
    }
});
