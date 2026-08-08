# pokedex

`pokedex` reads DEX files for tools that need stable method comparisons.

It exposes correct MUTF-8 decoding, parsed DEX tables, instruction streams, recovered
control-flow graphs, and configurable method hashing. Parsing and instruction walking
do not trigger hashing.

Container support for APK, JAR, ZIP, and VDEX inputs is enabled by default and can
be removed with `--no-default-features`.

The hashing API separates opcode normalization, register handling, literal values,
operand data, and block ordering. `hash::Config::recompilation_stable()` ignores
block placement and register identity while separating literals into the full hash.
It is tuned for comparisons across recompilations rather than serving as a canonical
DEX hash.

## Usage

This is published as `libpokedex` in crates.io because `pokedex` was already taken,
so add `libpokedex = "0.1"` to your Cargo.toml, and import it as `pokedex`.

Add the following to your Cargo.toml

```toml
[dependencies]
libpokedex = "0.1"
```

The following snippet is an example that pulls the DEX payloads out of an APK, walkas
every method, and prints the recovered control flow alongside a hash that survives
recompilation.

```rust
use std::{error::Error, fs::File};

use pokedex::{containers::DexFile, dex::Dex, hash::Config};

fn main() -> Result<(), Box<dyn Error>> {
   let config = Config::recompilation_stable();

   for dex_file in DexFile::from_zip(File::open("app.apk")?)? {
      let dex = Dex::parse(dex_file.bytes)?;

      for method in dex.methods() {
         let Some(code) = dex.decode(method)? else {
            continue;
         };

         let hashes = code.hashes(&config);
         println!(
            "{method} {} instructions, {} blocks, structural {}",
            code.instructions().len(),
            code.blocks().len(),
            hex(&hashes.structural),
         );
      }
   }

   Ok(())
}

fn hex(digest: &[u8; 32]) -> String {
   digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
```

`decode` returns `None` for abstract and native methods, which have no body.
`Dex::parse` also takes a bare `.dex` payload, so the container step is
optional.

## License

Licensed under the [Mozilla Public License 2.0](LICENSE).
