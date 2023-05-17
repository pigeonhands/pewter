use crate::{
    error::{Result, PewterError},
    io::Reader,
    pe::{
        coff::CoffFileHeader,
        optional_header::{data_directories::ImageDataDirectory, OptionalHeader},
    },
};

use super::ParseSectionData;

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ImageCor20Header {
    pub major_rt_version: u16,
    pub minor_rt_version: u16,
    pub metadata: ImageDataDirectory,
    pub flags: u32,
    pub entrypoint_token_or_rva: u32,
    pub resources: ImageDataDirectory,
    pub strong_name_signature: ImageDataDirectory,
    pub code_manager_table: ImageDataDirectory,
    pub vtable_fixups: ImageDataDirectory,
    pub export_address_table_jumps: ImageDataDirectory,
    pub managed_native_header: ImageDataDirectory,
}

impl ParseSectionData for ImageCor20Header {
    fn parse(
        section_data: &[u8],
        _: &super::Sections,
        _: &OptionalHeader,
        _: &CoffFileHeader,
    ) -> Result<Self> {
        let mut reader = section_data;

        let cb: u32 = reader.read()?;
        if cb < 0x48 {
            return Err(PewterError::invalid_image_format(
                "Invalid IMAGE_COR20_HEADER.cb value",
            ));
        }
        Ok(Self {
            major_rt_version: reader.read()?,
            minor_rt_version: reader.read()?,
            metadata: reader.read()?,
            flags: reader.read()?,
            entrypoint_token_or_rva: reader.read()?,
            resources: reader.read()?,
            strong_name_signature: reader.read()?,
            code_manager_table: reader.read()?,
            vtable_fixups: reader.read()?,
            export_address_table_jumps: reader.read()?,
            managed_native_header: reader.read()?,
        })
    }
}
