use pewter::pe::{
    definition::PEImageDef,
    sections::{cor20::ImageCor20Header, SectionFlags},
    PEFile,
};

/// PE files to test with: `PEWTER_TEST_PE` if set, otherwise an installed .NET framework.
fn test_images() -> Vec<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("PEWTER_TEST_PE") {
        return vec![path.into()];
    }
    let roots = ["/usr/share/dotnet", "/usr/lib/dotnet", r"C:\Program Files\dotnet"];
    let mut images: Vec<_> = roots
        .iter()
        .map(|r| std::path::Path::new(r).join("shared/Microsoft.NETCore.App"))
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flatten()
        .filter_map(|v| std::fs::read_dir(v.ok()?.path()).ok())
        .flatten()
        .filter_map(|f| Some(f.ok()?.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "dll"))
        .collect();
    images.sort();
    if images.is_empty() {
        eprintln!("skipping: set PEWTER_TEST_PE or install .NET to provide test images");
    }
    images
}

fn sample() -> Option<Vec<u8>> {
    let images = test_images();
    let path = images
        .iter()
        .find(|p| p.file_name().is_some_and(|n| n == "System.Runtime.dll"))
        .or(images.first())?;
    Some(std::fs::read(path).unwrap())
}

#[test]
fn unmodified_write_is_identical() {
    for path in test_images() {
        let data = std::fs::read(&path).unwrap();
        let Ok(mut def) = PEImageDef::parse(&data) else {
            continue;
        };
        let written = def.write_file().unwrap();
        assert!(written == data, "{} differs after rewriting", path.display());
    }
}

#[test]
fn added_section_is_readable() {
    let Some(sample) = sample() else { return };
    let mut def = PEImageDef::parse(&sample).unwrap();
    let alignment = def.section_alignment();
    let last_end = def
        .sections
        .iter()
        .map(|s| s.virtual_address as usize + s.virtual_size())
        .max()
        .unwrap();

    let rva = def
        .new_section(".extra", SectionFlags::CNT_INITIALIZED_DATA | SectionFlags::MEM_READ)
        .add_data(b"pewter") as u32;
    assert_eq!(rva as usize % alignment, 0);
    assert!(rva as usize >= last_end);

    let written = def.write_file().unwrap();
    let pe = PEFile::parse(&written).unwrap();
    assert_eq!(&pe.sections.find_rva_data(rva as usize).unwrap()[..6], b"pewter");

    let original = PEFile::parse(&sample).unwrap();
    for (a, b) in original.sections.0.iter().zip(pe.sections.0.iter()) {
        assert_eq!(a.row.virtual_address, b.row.virtual_address);
        assert_eq!(a.data, b.data);
    }
    assert_eq!(pe.coff_header.machine, original.coff_header.machine);
    assert_eq!(
        pe.read_clr_runtime_header().unwrap(),
        original.read_clr_runtime_header().unwrap()
    );
}

#[test]
fn cor20_header_round_trips_in_place() {
    let Some(sample) = sample() else { return };
    let pe = PEFile::parse(&sample).unwrap();
    let header = pe.read_clr_runtime_header().unwrap().unwrap();
    let rva = pe
        .optional_header
        .as_ref()
        .unwrap()
        .data_directories
        .clr_runtime_header
        .virtual_address;

    let mut def = PEImageDef::from_pe_file(pe);
    let mut bytes = Vec::new();
    pewter::io::Writer::write(&mut bytes, &header).unwrap();
    assert_eq!(def.read_at_rva(rva, ImageCor20Header::SIZE).unwrap(), &bytes[..]);
    def.write_at_rva(rva, &bytes).unwrap();
    assert!(def.write_file().unwrap() == sample);
}


#[test]
fn new_image_from_scratch() {
    use pewter::pe::{
        coff::{ImageFileCharacteristics, ImageFileMachine},
        optional_header::{ImageSubsystem, OptionalHeader},
    };

    let mut def = PEImageDef::new(
        ImageFileMachine::I386,
        ImageFileCharacteristics::EXECUTABLE_IMAGE | ImageFileCharacteristics::FILE_DLL,
        OptionalHeader::new_pe32(ImageSubsystem::WindowsCui, 0x1000_0000),
    );
    let rva = def
        .new_section(".text", SectionFlags::CNT_CODE | SectionFlags::MEM_EXECUTE | SectionFlags::MEM_READ)
        .add_data(b"code");
    assert_eq!(rva, 0x2000);

    let written = def.write_file().unwrap();
    assert!(written.windows(39).any(|w| w == b"This program cannot be run in DOS mode."));
    let pe = PEFile::parse(&written).unwrap();
    assert_eq!(pe.coff_header.machine, ImageFileMachine::I386);
    let header = pe.optional_header.as_ref().unwrap();
    assert_eq!(header.windows_specific_fields.size_of_image(), 0x4000);
    assert_eq!(header.standard_fields.base_of_code, 0x2000);
    assert_eq!(&pe.sections.find_rva_data(0x2000).unwrap()[..4], b"code");
}
