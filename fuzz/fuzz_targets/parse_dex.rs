#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
   let _ = pokedex::dex::Dex::parse(data.to_vec());
});
