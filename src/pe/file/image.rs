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

    pub fn parse_with_options(data: &[u8], parse_options: Options) -> Result<Self> {
        let PEFile {
            dos_header,
            signature,
            coff_header,
            optional_header,
            section_table,
            special_sections,
        } = PEFile::parse_with_options(data, parse_options)?;

        Ok(Self {
            dos_header,
            signature,
            coff_header,
            optional_header: optional_header
                .ok_or_else(|| PerwError::invalid_image_format("No optional header."))?,
            section_table,
            special_sections,
        })
    }
}
