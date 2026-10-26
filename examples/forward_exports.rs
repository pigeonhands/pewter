//! Generates a proxy DLL that forwards every export of an existing DLL or ELF
//! shared object to it.
//!
//! ```text
//! cargo run --example forward_exports -- <input.dll|input.so> <output.dll> [target]
//! ```
//!
//! `target` is the module the forwarders point at, without the `.dll` extension
//! (the loader adds it). It defaults to the input's name up to the first dot.

use std::{env, error::Error, path::Path};

use pewter::{
    image::{AnyImage, LoadedImage},
    pe::{definition::PEImageDef, sections::edata},
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let [input, output, target @ ..] = args.as_slice() else {
        return Err("usage: forward_exports <input.dll|input.so> <output.dll> [target]".into());
    };
    let target = match target.first() {
        Some(target) => target.as_str(),
        None => file_name(input)?.split('.').next().unwrap_or_default(),
    };

    let data = std::fs::read(input)?;
    let image = AnyImage::load(&data)?;
    let machine = image
        .machine()
        .ok_or("input machine has no PE equivalent")?;
    let source_exports = image.exports()?;
    let (ordinal_base, exports) = edata::forward_all_exports(&source_exports, target);

    let mut dll = PEImageDef::new_dll(machine);
    dll.add_export_table(file_name(output)?, ordinal_base, &exports)?;
    std::fs::write(output, dll.write_file()?)?;

    println!(
        "wrote {output} forwarding {} exports to {target}",
        source_exports.len()
    );
    Ok(())
}

fn file_name(path: &str) -> Result<&str, Box<dyn Error>> {
    Ok(Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{path} has no file name"))?)
}
