pub mod coff;
pub mod dos;
pub mod optional_header;
pub mod sections;

use crate::{
    error::{PerwError, Result},
    io::{ReadData, Reader},
};

use self::sections::SectionTable;

#[derive(Debug)]
pub struct PEFile {
    pub dos_header: dos::ImageDosHeader,
    pub signature: [u8; 4],
    pub coff_header: coff::CoffFileHeader,
    pub optional_header: Option<optional_header::OptionalHeader>,
    pub section_table: SectionTable,
    pub special_sections: sections::SpecialSections,
}

impl PEFile {
    pub const SIGNATURE: [u8; 4] = [b'P', b'E', 0, 0];

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let dos_header = dos::ImageDosHeader::read(&mut data.as_ref())?;
        let pe_offset = dos_header.e_lfanew as usize;

        if data.len() < pe_offset {
            return Err(PerwError::not_enough_data(pe_offset));
        }

        let read_ptr = &mut data[pe_offset..].as_ref();
        let signature = read_ptr.read()?;

        if signature != Self::SIGNATURE {
            return Err(PerwError::invalid_image_format("Bad PE signature."));
        }

        let coff_header: coff::CoffFileHeader = read_ptr.read()?;

        let optional_header: Option<optional_header::OptionalHeader> =
            (coff_header.size_of_optional_header > 0)
                // should probaby limit this read to size_of_optional_header
                .then(|| read_ptr.read())
                .transpose()?;

        let section_table =
            SectionTable::new_linear(read_ptr, coff_header.number_of_sections as usize)?;

        let special_sections = match &optional_header {
            Some(optioal_header) => sections::SpecialSections::parse(
                data,
                &coff_header,
                &optioal_header,
                &section_table,
            )?,
            None => Default::default(),
        };

        Ok(Self {
            dos_header,
            signature,
            coff_header,
            optional_header,
            section_table,
            special_sections,
        })
    }
}
