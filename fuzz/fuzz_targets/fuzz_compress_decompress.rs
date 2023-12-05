#![no_main]

use libfuzzer_sys::fuzz_target;

extern crate locker;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let c = locker::util::compress(s.as_bytes()).unwrap();
        let result = locker::util::decompress(c).unwrap();
        if result != s 
        {
            panic!("decompressed data not the same");
        }
    }
});
