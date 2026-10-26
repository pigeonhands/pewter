//! Generates a proxy DLL that forwards every export of an existing DLL or ELF
//! shared object to it, except one export, which is replaced by a method
//! compiled into the proxy itself (a "hook").
//!
//! ```text
//! cargo run --example hook_export -- <input.dll|input.so> <output.dll> <export> [target]
//! ```
//!
//! `export` is the name to hook. `target` is the module the other exports
//! forward to, without its `.dll` extension; it defaults to the input's name up
//! to the first dot. The input may be a PE or an ELF; the output is always a PE.
//!
//! The replacement method here just returns the constant `42`. In a real tool
//! you would assemble it (e.g. with `iced-x86`) and pass the encoded bytes to
//! `new_section(...).add_data(..)` the same way.

use std::{env, error::Error, path::Path};

use pewter::{
    image::{AnyImage, LoadedImage},
    pe::{
        coff::ImageFileMachine,
        definition::PEImageDef,
        sections::{
            edata::{self, ExportTarget},
            SectionFlags,
        },
    },
};

/// A function body returning `42`, for the input's machine. x86 and x86-64 share
/// the same encoding here (`mov eax, 42; ret`).
fn stub_method(machine: ImageFileMachine) -> Result<&'static [u8], Box<dyn Error>> {
    match machine {
        // mov eax, 0x2A  (B8 2A 00 00 00)
        // ret            (C3)
        ImageFileMachine::I386 | ImageFileMachine::Amd64 => {
            Ok(&[0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3])
        }
        other => Err(format!("no stub bytecode for machine {other:?}").into()),
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let [input, output, export, target @ ..] = args.as_slice() else {
        return Err(
            "usage: hook_export <input.dll|input.so> <output.dll> <export> [target]".into(),
        );
    };
    let module = match target.first() {
        Some(target) => target.as_str(),
        None => file_name(input)?.split('.').next().unwrap_or_default(),
    };

    let data = std::fs::read(input)?;
    let image = AnyImage::load(&data)?;
    let machine = image
        .machine()
        .ok_or("input machine has no PE equivalent")?;
    let source_exports = image.exports()?;
    if !source_exports
        .iter()
        .any(|e| e.name.as_deref() == Some(export.as_str()))
    {
        return Err(format!("{input} does not export {export}").into());
    }

    let mut dll = PEImageDef::new_dll(machine);

    // Write the replacement method into a code section and remember its address.
    let hook_rva = dll
        .new_section(
            ".text",
            SectionFlags::CNT_CODE | SectionFlags::MEM_EXECUTE | SectionFlags::MEM_READ,
        )
        .add_data(stub_method(machine)?) as u32;

    // Forward every export to `module`, except the hooked one, which points at
    // the method we just wrote instead of being forwarded.
    let (ordinal_base, exports) = edata::forward_exports(&source_exports, |e| {
        if e.name.as_deref() == Some(export.as_str()) {
            Some(ExportTarget::Rva(hook_rva))
        } else {
            e.forwarder_in(module).map(ExportTarget::Forwarder)
        }
    });

    dll.add_export_table(file_name(output)?, ordinal_base, &exports)?;
    std::fs::write(output, dll.write_file()?)?;

    println!(
        "wrote {output}: hooked {export} (RVA {hook_rva:#x}), forwarded {} exports to {module}",
        source_exports.len() - 1
    );
    Ok(())
}

fn file_name(path: &str) -> Result<&str, Box<dyn Error>> {
    Ok(Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("{path} has no file name"))?)
}
