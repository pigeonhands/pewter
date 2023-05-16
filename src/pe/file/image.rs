use super::*;
/// same as [PEFile](super::PEFile) except it must have an
/// optional header
#[derive(Debug, Clone)]
pub struct PEImage {
    pub dos_header: dos::ImageDosHeader,
    pub signature: [u8; 4],
    pub coff_header: coff::CoffFileHeader,
    pub optional_header: optional_header::OptionalHeader,
    pub section_table: SectionTable,
    pub special_sections: sections::SpecialSections,
}

impl PEImage {
    #[inline(always)]
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_with_options(data, Options::default())
    }

    pub fn parse_with_options(_data: &[u8], _parse_options: Options) -> Result<Self> {
        todo!()
    }
}
