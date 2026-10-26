use bitflags::bitflags;

use crate::{
    error::{Result, PewterError},
    io::{Reader, WriteData, Writer},
    pe::{
        coff::CoffFileHeader,
        optional_header::{data_directories::ImageDataDirectory, OptionalHeader},
    },
};

use super::ParseSectionData;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[cfg_attr(feature = "reflect", derive(facet::Facet), facet(opaque))]
    pub struct Cor20Flags: u32 {
        const IL_ONLY = 0x00000001;
        const REQUIRED_32BIT = 0x00000002;
        const IL_LIBRARY = 0x00000004;
        const STRONG_NAME_SIGNED = 0x00000008;
        const NATIVE_ENTRYPOINT = 0x00000010;
        const TRACK_DEBUG_DATA = 0x00010000;
        const PREFER_32BIT = 0x00020000;
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
pub struct ImageCor20Header {
    pub major_rt_version: u16,
    pub minor_rt_version: u16,
    pub metadata: ImageDataDirectory,
    pub flags: Cor20Flags,
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
        Self::parse_bytes(section_data)
    }
}

impl ImageCor20Header {
    pub fn parse_bytes(section_data: &[u8]) -> Result<Self> {
        let mut reader = section_data;

        let cb: u32 = reader.read()?;
        if (cb as usize) < Self::SIZE {
            return Err(PewterError::invalid_image_format(
                "Invalid IMAGE_COR20_HEADER.cb value",
            ));
        }
        Ok(Self {
            major_rt_version: reader.read()?,
            minor_rt_version: reader.read()?,
            metadata: reader.read()?,
            flags: Cor20Flags::from_bits_retain(reader.read()?),
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

impl ImageCor20Header {
    pub const SIZE: usize = 0x48;
}

impl WriteData for &ImageCor20Header {
    fn write_to(self, writer: &mut impl Writer) -> Result<()> {
        writer.write(ImageCor20Header::SIZE as u32)?;
        writer.write(self.major_rt_version)?;
        writer.write(self.minor_rt_version)?;
        writer.write(self.metadata)?;
        writer.write(self.flags.bits())?;
        writer.write(self.entrypoint_token_or_rva)?;
        writer.write(self.resources)?;
        writer.write(self.strong_name_signature)?;
        writer.write(self.code_manager_table)?;
        writer.write(self.vtable_fixups)?;
        writer.write(self.export_address_table_jumps)?;
        writer.write(self.managed_native_header)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vec::Vec;

    #[test]
    fn read_write_cor20_header() {
        let header = ImageCor20Header {
            major_rt_version: 2,
            minor_rt_version: 5,
            metadata: ImageDataDirectory { virtual_address: 0x2000, size: 0x100 },
            flags: Cor20Flags::IL_ONLY,
            entrypoint_token_or_rva: 0x06000001,
            ..Default::default()
        };
        let mut buffer = Vec::new();
        header.write_to(&mut buffer).unwrap();
        assert_eq!(buffer.len(), ImageCor20Header::SIZE);
        let parsed = ImageCor20Header::parse_bytes(&buffer).unwrap();
        assert_eq!(parsed, header);
    }
}
