use pewter::pe::{
    definition::PEImageDef,
    sections::{cor20::ImageCor20Header, SectionFlags},
    PEFile,
};

const SAMPLE: &[u8] = include_bytes!("fixtures/Sample.dll");

#[test]
fn unmodified_write_is_identical() {
    let mut def = PEImageDef::parse(SAMPLE).unwrap();
    let written = def.write_file().unwrap();
    assert_eq!(written.len(), SAMPLE.len());
    assert!(written == SAMPLE, "rewritten image differs from the original");
}

#[test]
fn added_section_is_readable() {
    let mut def = PEImageDef::parse(SAMPLE).unwrap();
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

    let original = PEFile::parse(SAMPLE).unwrap();
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
    let pe = PEFile::parse(SAMPLE).unwrap();
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
    assert!(def.write_file().unwrap() == SAMPLE);
}

