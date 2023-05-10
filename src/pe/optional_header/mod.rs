pub mod data_directories;
mod fields;
pub use fields::*;

use crate::{
    error::PerwError,
    io::{ReadData, WriteData},
};

use self::data_directories::{DataDirectories, DataDirectoryName, ImageDataDirectory};

/// Every image file has an optional header that provides information to the loader. 
/// This header is optional in the sense that some files (specifically, object files) do not have it. 
/// For image files, this header is required. 
/// An object file can have an optional header, but generally this header has no function in an object 
/// file except to increase its size.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct OptionalHeader {
    /// The first eight fields of the optional header are standard fields that are defined for
    /// every implementation of COFF. These fields contain general information that is
    /// useful for loading and running an executable file. They are unchanged for the PE32+ format.
    pub standard_fields: OptionalHeaderStandardFields,
    /// The next 21 fields are an extension to the COFF optional header format.
    /// They contain additional information that is required by the linker and loader in Windows.
    pub windows_specific_fields: OptionalHeaderWindowsSpecific,
    /// Data directories in current PE32/PE32+ file.
    ///
    /// Each field in the [`DataDirectories`] struct wil be read/written sequentially
    /// up to [OptionalHeaderWindowsSpecific::number_of_rva_and_sizes](OptionalHeaderWindowsSpecific::number_of_rva_and_sizes).
    pub data_directories: DataDirectories,
}

impl CalulateOptVariantSize<Pe32> for OptionalHeader {
    fn calculate_size() -> usize {
        OptionalHeaderStandardFields::SIZE_PE + OptionalHeaderWindowsSpecificFields::<Pe32>::SIZE
    }
}

impl CalulateOptVariantSize<Pe32Plus> for OptionalHeader {
    fn calculate_size() -> usize {
        OptionalHeaderStandardFields::SIZE_PE_PLUS
            + OptionalHeaderWindowsSpecificFields::<Pe32Plus>::SIZE
    }
}

impl OptionalHeader {
    /// The size of the Optional Header in PE32. (With zero data directories)
    pub const fn size_pe32() -> usize {
        OptionalHeaderStandardFields::SIZE_PE + OptionalHeaderWindowsSpecificFields::<Pe32>::SIZE
    }

    /// The size of the Optional Header in PE32+. (With zero data directories)
    pub const fn size_pe32_plus() -> usize {
        OptionalHeaderStandardFields::SIZE_PE_PLUS
            + OptionalHeaderWindowsSpecificFields::<Pe32Plus>::SIZE
    }

    /// The size of this Optional Header variant.
    pub fn size(&self) -> usize {
        match &self.windows_specific_fields {
            OptionalHeaderWindowsSpecific::PE32(pe) => {
                <Self as CalulateOptVariantSize<Pe32>>::calculate_size()
                    + (pe.number_of_rva_and_sizes as usize * ImageDataDirectory::SIZE)
            }
            OptionalHeaderWindowsSpecific::PE32Plus(pe) => {
                <Self as CalulateOptVariantSize<Pe32Plus>>::calculate_size()
                    + (pe.number_of_rva_and_sizes as usize * ImageDataDirectory::SIZE)
            }
        }
    }

    /// Get the dada directory if index is less than
    /// [OptionalHeaderWindowsSpecific::number_of_rva_and_sizes](OptionalHeaderWindowsSpecificFields::number_of_rva_and_sizes).
    pub fn try_get_data_directory(&self, name: DataDirectoryName) -> Option<ImageDataDirectory> {
        (self.windows_specific_fields.number_of_rva_and_sizes() < name as u32)
            .then(|| self.data_directories.get_directory(name))
    }
}

impl ReadData for OptionalHeader {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        let standard_fields: OptionalHeaderStandardFields = reader.read()?;
        let windows_specific_fields = match &standard_fields.magic {
            OptionalHeaderMagic::PE32 => OptionalHeaderWindowsSpecific::PE32(reader.read()?),
            OptionalHeaderMagic::PE32Plus => {
                OptionalHeaderWindowsSpecific::PE32Plus(reader.read()?)
            }
        };

        let mut data_directories = DataDirectories::default();
        for data_dir_name in DataDirectories::ALL_DATA_DIRECTORIES
            .into_iter()
            .take(windows_specific_fields.number_of_rva_and_sizes() as usize)
        {
            data_directories.set_directory(data_dir_name, reader.read()?);
        }

        Ok(Self {
            standard_fields,
            windows_specific_fields,
            data_directories,
        })
    }
}

impl WriteData for &OptionalHeader {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(&self.standard_fields)?;
        match (self.standard_fields.magic, &self.windows_specific_fields) {
            (OptionalHeaderMagic::PE32, OptionalHeaderWindowsSpecific::PE32(pe)) => writer.write(pe)?,
            (OptionalHeaderMagic::PE32Plus, OptionalHeaderWindowsSpecific::PE32(pe)) => writer.write(pe)?,
            _ => return Err(PerwError::invalid_image_format("Mismatching Optiional Header standard_fields.magic value and windows_specific_fields variant."))
        }

        for data_dir_name in DataDirectories::ALL_DATA_DIRECTORIES
            .into_iter()
            .take(self.windows_specific_fields.number_of_rva_and_sizes() as usize)
        {
            writer.write(self.data_directories.get_directory(data_dir_name))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_header_pe32_is_96() {
        let mut buffer = [0u8; OptionalHeader::size_pe32()];
        buffer[..2].copy_from_slice(&OptionalHeaderMagic::PE32.to_u16().to_le_bytes());
        let read_ptr = &mut buffer.as_slice();
        OptionalHeader::read(read_ptr).unwrap();
        assert_eq!(read_ptr.len(), 0);
    }

    #[test]
    fn optional_header_pe32_plus_is_112() {
        let mut buffer = [0u8; OptionalHeader::size_pe32_plus()];
        buffer[..2].copy_from_slice(&OptionalHeaderMagic::PE32Plus.to_u16().to_le_bytes());
        let read_ptr = &mut buffer.as_slice();
        OptionalHeader::read(read_ptr).unwrap();
        assert_eq!(read_ptr.len(), 0);
    }
}
