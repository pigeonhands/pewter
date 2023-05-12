mod image;
pub mod definition;
pub use image::PEImage;

use crate::{
    error::{PerwError, Result},
    io::{ReadData, Reader, WriteData},
};

use crate::pe::{coff, dos, optional_header, options::Options, sections, sections::SectionTable};

#[derive(Debug, Clone, PartialEq)]
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

    /// Parse with [`Options::default()`]
    #[inline(always)]
    pub fn parse(data: &[u8]) -> Result<Self> {
        Self::parse_with_options(data, Options::default())
    }

    /// Parse with [`Options::minimal()`]
    #[inline(always)]
    pub fn parse_minimal(data: &[u8]) -> Result<Self> {
        Self::parse_with_options(data, Options::minimal())
    }

    pub fn parse_with_options(data: &[u8], parse_options: Options) -> Result<Self> {
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
                parse_options.parse_special_sections,
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

    /// Patches a pe file with the changes made.
    /// `data` should be (roughly) the same data that was used when parsing.
    /// 
    /// This will not re-calculate any RVAs/virtual addresses or check that
    /// values make sense before writing, so if some properties have changed 
    /// size or virtual addresses are changed it may retrun an error or produce 
    /// a corrupted ececutable.
    /// 
    /// e.g. if [`CoffFileHeader::number_of_sections`](coff::CoffFileHeader::number_of_sections)
    /// is set to 5, but there are 10 items in [`PEFile::section_table`], the file will be corrupt.
    /// 
    /// Here is a working example, removing the debug data directory:
    /// ```no_run
    /// # use std::fs;
    /// # use pewter::PEFile;
    /// let mut data = std::fs::read("Example.exe").unwrap();
    /// 
    /// let mut pe_file = PEFile::parse_minimal(&data).unwrap();
    /// 
    /// if let Some(optional_header) = &mut pe_file.optional_header {
    ///     optional_header.data_directories.debug = Default::default();
    /// }
    /// 
    /// pe_file.patch(&mut data).unwrap();
    /// ```
    /// the debug data will still be in the file, but will not have a data directory
    /// pointing to it.
    pub fn patch(&self, data: &mut [u8]) -> Result<()> {

        self.dos_header.write_to(&mut data.as_mut())?;
        
        let mut image_header_writer = &mut data[self.dos_header.e_lfanew as usize..];

        self.signature.write_to(&mut image_header_writer)?;
        self.coff_header.write_to(&mut image_header_writer)?;
        if let Some(optional_header) = &self.optional_header {
            optional_header.write_to(&mut image_header_writer)?;
        }

        self.section_table.write_to(&mut image_header_writer)?;

        Ok(())
    }

}
