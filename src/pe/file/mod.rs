pub mod definition;

use crate::{
    error::{PewterError, Result},
    io::{ReadData, Reader},
};

use crate::pe::{coff, dos, optional_header, options::Options, sections::SectionTable};

use super::{
    optional_header::data_directories::{DataDirectories, ImageDataDirectory},
    sections::{
        base_relocation, certificate, edata, idata, pdata, rsrc,cor20, ParseSectionData, Sections,
    },
};

#[derive(Debug, Clone, PartialEq)]
pub struct PEFile<'a> {
    pub dos_header: dos::ImageDosHeader,
    pub coff_header: coff::CoffFileHeader,
    pub optional_header: Option<optional_header::OptionalHeader>,
    pub sections: Sections<'a>,
}

impl<'a> PEFile<'a> {
    pub const SIGNATURE: [u8; 4] = [b'P', b'E', 0, 0];

    /// Parse with [`Options::default()`]
    #[inline(always)]
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        Self::parse_with_options(data, Options::default())
    }

    /// Parse with [`Options::minimal()`].
    /// Does not parse any [`special_sections`](PEFile::special_sections).
    #[inline(always)]
    pub fn parse_minimal(data: &'a [u8]) -> Result<Self> {
        Self::parse_with_options(data, Options::minimal())
    }

    pub fn parse_with_options(data: &'a [u8], _parse_options: Options) -> Result<Self> {
        let dos_header = dos::ImageDosHeader::read(&mut data.as_ref())?;
        let pe_offset = dos_header.e_lfanew as usize;

        if data.len() < pe_offset {
            return Err(PewterError::not_enough_data(pe_offset));
        }

        let read_ptr = &mut data[pe_offset..].as_ref();
        let signature: [u8; 4] = read_ptr.read()?;

        if signature != Self::SIGNATURE {
            return Err(PewterError::invalid_image_format("Bad PE signature."));
        }

        let coff_header: coff::CoffFileHeader = read_ptr.read()?;

        let optional_header: Option<optional_header::OptionalHeader> =
            (coff_header.size_of_optional_header > 0)
                // should probaby limit this read to size_of_optional_header
                .then(|| read_ptr.read())
                .transpose()?;

        let sections = {
            let section_table =
                SectionTable::new_linear(read_ptr, coff_header.number_of_sections as usize)?;
            Sections::parse(data, section_table)?
        };

        Ok(Self {
            dos_header,
            coff_header,
            optional_header,
            sections,
        })
    }

    fn read_section_data<T: ParseSectionData>(
        &self,
        data_dir_fn: impl FnOnce(&DataDirectories) -> &ImageDataDirectory,
    ) -> Result<Option<T>> {
        self.optional_header
            .as_ref()
            .map(|optional_header| {
                let data_dir = data_dir_fn(&optional_header.data_directories);
                self.sections
                    .find_data_directory_data_map(&data_dir, |data| {
                        T::parse(data, &self.sections, &optional_header, &self.coff_header)
                    })
            })
            .transpose()
            .map(|x| x.flatten())
    }

    #[inline(always)]
    pub fn read_export_table(&self) -> Result<Option<edata::ExportTableDataDirectory>> {
        self.read_section_data(|dirs| &dirs.export_table)
    }

    #[inline(always)]
    pub fn read_import_table(&self) -> Result<Option<idata::ImportTableDataDirectory>> {
        self.read_section_data(|dirs| &dirs.import_table)
    }

    #[inline(always)]
    pub fn read_resource_directory(&self) -> Result<Option<rsrc::ResourceDataDirectory>> {
        self.read_section_data(|dirs: &DataDirectories| &dirs.resource_table)
    }

    #[inline(always)]
    pub fn read_exeption_table(&self) -> Result<Option<pdata::ExceptionHandlerDataDirectory>> {
        self.read_section_data(|dirs| &dirs.exception_table)
    }

    #[inline(always)]
    pub fn read_certificate_table(&self) -> Result<Option<certificate::CertificateDataDirectory>> {
        self.read_section_data(|dirs| &dirs.certificate_table)
    }

    #[inline(always)]
    pub fn read_base_relocation_table(
        &self,
    ) -> Result<Option<base_relocation::BaseRelocationDataDitectory>> {
        self.read_section_data(|dirs| &dirs.base_relocation_table)
    }

    #[inline(always)]
    pub fn read_clr_runtime_header(
        &self,
    ) -> Result<Option<cor20::ImageCor20Header>> {
        self.read_section_data(|dirs| &dirs.clr_runtime_header)
    }
}
