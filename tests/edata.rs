use pewter::PEFile;

/// A DLL with both regular and forwarded exports, from a Wine install.
fn sample() -> Option<Vec<u8>> {
    let path = std::env::var_os("PEWTER_TEST_EXPORTS_PE")
        .map(Into::into)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/lib/wine/x86_64-windows/kernel32.dll"));
    let data = std::fs::read(&path).ok();
    if data.is_none() {
        eprintln!("skipping: set PEWTER_TEST_EXPORTS_PE or install Wine to provide a test image");
    }
    data
}

#[test]
fn export_table_is_read() {
    let Some(data) = sample() else { return };
    let pe = PEFile::parse(&data).unwrap();
    let export_dir = pe.optional_header.as_ref().unwrap().data_directories.export_table;
    let exports = pe.read_export_table().unwrap().unwrap();
    let dir = &exports.export_directory_table;

    assert!(exports.dll_name.eq_ignore_ascii_case("kernel32.dll"));
    assert_eq!(exports.export_address_table.len(), dir.address_table_entries as usize);
    assert_eq!(exports.export_name_table.len(), dir.number_of_name_pointers as usize);
    assert_eq!(exports.export_ordinal_table.len(), exports.export_name_table.len());
    assert!(exports.export_name_table.windows(2).all(|w| w[0] < w[1]));

    let lookup = |name: &str| {
        let i = exports.export_name_table.iter().position(|n| n == name)?;
        let ordinal = exports.export_ordinal_table[i].0 as usize;
        Some(&exports.export_address_table[ordinal])
    };

    let forwarded = lookup("AcquireSRWLockExclusive").unwrap();
    assert!(forwarded.is_forwarder(&export_dir));
    let target = pe.sections.find_rva_data(forwarded.0 as usize).unwrap();
    assert!(target.starts_with(b"NTDLL.RtlAcquireSRWLockExclusive\0"));

    let local = lookup("CreateFileA").unwrap();
    assert!(!local.is_forwarder(&export_dir));
    assert!(pe.sections.find_rva(local.0 as usize).is_some());
}

#[test]
fn built_export_table_is_read() {
    use pewter::pe::{
        coff::{ImageFileCharacteristics, ImageFileMachine},
        definition::PEImageDef,
        optional_header::{ImageSubsystem, OptionalHeader},
        sections::{
            edata::{ExportDef, ExportTarget},
            SectionFlags,
        },
    };

    let mut def = PEImageDef::new(
        ImageFileMachine::Amd64,
        ImageFileCharacteristics::EXECUTABLE_IMAGE | ImageFileCharacteristics::FILE_DLL,
        OptionalHeader::new_pe32_plus(ImageSubsystem::WindowsCui, 0x1_8000_0000),
    );
    let text = def
        .new_section(".text", SectionFlags::CNT_CODE | SectionFlags::MEM_EXECUTE | SectionFlags::MEM_READ)
        .add_data(&[0xC3; 16]) as u32;

    let exports = [
        ExportDef::rva("Zeta", text),
        ExportDef::forwarder("AcquireLock", "NTDLL.RtlAcquireSRWLockExclusive"),
        ExportDef { name: None, target: ExportTarget::Rva(text + 8) },
        ExportDef::rva("Alpha", text + 4),
    ];
    let rva = def.add_export_table("test.dll", 1, &exports).unwrap();

    let written = def.write_file().unwrap();
    let pe = PEFile::parse(&written).unwrap();
    let export_dir = pe.optional_header.as_ref().unwrap().data_directories.export_table;
    assert_eq!(export_dir.virtual_address, rva);
    assert_eq!(pe.sections.find_rva(rva as usize).unwrap().row.name_str(), ".edata");

    let table = pe.read_export_table().unwrap().unwrap();
    assert_eq!(table.dll_name, "test.dll");
    assert_eq!(table.export_directory_table.ordinal_base, 1);
    assert_eq!(table.export_address_table.len(), 4);
    assert_eq!(table.export_name_table.0, ["AcquireLock", "Alpha", "Zeta"]);
    let ordinals: Vec<u16> = table.export_ordinal_table.iter().map(|o| o.0).collect();
    assert_eq!(ordinals, [1, 3, 0]);

    let addresses = &table.export_address_table;
    assert_eq!(addresses[0].0, text);
    assert_eq!(addresses[2].0, text + 8);
    assert_eq!(addresses[3].0, text + 4);
    assert!(!addresses[0].is_forwarder(&export_dir));
    assert!(addresses[1].is_forwarder(&export_dir));
    let target = pe.sections.find_rva_data(addresses[1].0 as usize).unwrap();
    assert!(target.starts_with(b"NTDLL.RtlAcquireSRWLockExclusive\0"));
}

#[test]
fn bad_exports_are_rejected() {
    use pewter::pe::sections::edata::{build_export_data, ExportDef};

    let forwarder = [ExportDef::forwarder("A", "NoDot")];
    assert!(build_export_data(0x1000, "x.dll", 1, &forwarder).is_err());
    let duplicate = [ExportDef::rva("A", 0x10), ExportDef::rva("A", 0x20)];
    assert!(build_export_data(0x1000, "x.dll", 1, &duplicate).is_err());
}

#[test]
fn loaded_pe_exports_include_forwarders() {
    use pewter::image::{AnyImage, ExportLocation, LoadedImage};

    let Some(data) = sample() else { return };
    let image = AnyImage::load(&data).unwrap();
    assert!(matches!(image, AnyImage::Pe(_)));
    let exports = image.exports().unwrap();
    let find = |name: &str| exports.iter().find(|e| e.name.as_deref() == Some(name)).unwrap();

    assert_eq!(
        find("AcquireSRWLockExclusive").location,
        ExportLocation::Forwarder("NTDLL.RtlAcquireSRWLockExclusive".into())
    );
    let ExportLocation::Address(vaddr) = find("CreateFileA").location else { panic!() };
    assert!(image.is_mapped(vaddr));
}

#[test]
fn forward_exports_keeps_ordinals() {
    use pewter::{
        image::{Export, ExportLocation},
        pe::sections::edata::{forward_all_exports, ExportTarget},
    };

    let export = |name: Option<&str>, ordinal: Option<u32>| Export {
        name: name.map(Into::into),
        ordinal,
        location: ExportLocation::Address(0x1000),
    };
    let exports = [
        export(Some("A"), Some(5)),
        export(None, Some(7)),
        export(Some("Alias"), Some(5)),
        export(Some("Elf"), None),
    ];
    let (base, defs) = forward_all_exports(&exports, "real");
    assert_eq!(base, 5);
    let targets: Vec<_> = defs.iter().map(|d| (d.name.as_deref(), &d.target)).collect();
    let fwd = |s: &str| ExportTarget::Forwarder(s.into());
    assert_eq!(
        targets,
        [
            (Some("A"), &fwd("real.A")),
            (None, &ExportTarget::Rva(0)),
            (None, &fwd("real.#7")),
            (Some("Alias"), &fwd("real.Alias")),
            (Some("Elf"), &fwd("real.Elf")),
        ]
    );
}

#[test]
fn forward_exports_callback_chooses_each_target() {
    use pewter::{
        image::{Export, ExportLocation},
        pe::sections::edata::{forward_exports, ExportTarget},
    };

    let export = |name: &str| Export {
        name: Some(name.into()),
        ordinal: None,
        location: ExportLocation::Address(0x1000),
    };
    let exports = [export("Hooked"), export("Dropped"), export("Passed")];
    let (base, defs) = forward_exports(&exports, |e| match e.name.as_deref()? {
        "Hooked" => Some(ExportTarget::Rva(0x2000)),
        "Dropped" => None,
        _ => e.forwarder_in("real").map(ExportTarget::Forwarder),
    });
    assert_eq!(base, 1);
    let targets: Vec<_> = defs.iter().map(|d| (d.name.as_deref().unwrap(), &d.target)).collect();
    assert_eq!(
        targets,
        [
            ("Hooked", &ExportTarget::Rva(0x2000)),
            ("Passed", &ExportTarget::Forwarder("real.Passed".into())),
        ]
    );
}
