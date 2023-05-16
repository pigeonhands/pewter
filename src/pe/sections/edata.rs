//! The .edata Section (Image Only)
//!
//! The export data section, named .edata, contains information about symbols
//! that other images can access through dynamic linking. Exported symbols are
//! generally found in DLLs, but DLLs can also import symbols.

use crate::{
    containers::Table,
    error::{PewterError, Result},
    io::{ReadData, WriteData},
};

use super::SectionTable;

use crate::{vec::Vec, string::String};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportTableDataDirectory {
    /// The export directory table contains address information that is used to resolve
    /// imports to the entry points within this image.
    pub export_directory_table: ExportDirectory,
    /// The export address table contains the address of exported entry points and exported data and absolutes.
    /// An ordinal number is used as an index into the export address table.
    pub export_address_table: Table<ExportAddress>,
    /// The export name pointer table is an array of addresses (RVAs) into the export name table.
    /// The pointers are 32 bits each and are relative to the image base. The pointers are ordered lexically
    /// to allow binary searches.
    pub name_pointer_table: Table<ExportNamePointer>,
    /// An array of the ordinals that correspond to members of the name pointer table.
    /// The correspondence is by position; therefore, the name pointer table and the ordinal
    /// table must have the same number of members. Each ordinal is an index into the export address table.
    pub export_ordinal_table: Table<ExportOrtinal>,
    // The export name table contains the actual string data that was pointed to by the export name pointer table.
    // The strings in this table are public names that other images can use to import the symbols.
    // These public export names are not necessarily the same as the private symbol names that the symbols have
    // in their own image file and source code, although they can be.
    pub export_name_table: Table<String>,
}

impl ExportTableDataDirectory {
    pub fn parse(file_bytes: &[u8], section_base: &[u8], sections: &SectionTable) -> Result<Self> {
        let export_directory_table = ExportDirectory::read(&mut section_base.as_ref())?;

        let export_address_table_data = sections
            .find_rva_data(
                file_bytes,
                export_directory_table.export_address_table as usize,
            )
            .ok_or_else(|| {
                PewterError::invalid_image_format(
                    "Failed to map export_address_table_data inside image",
                )
            })?;

        let name_pointer_table_data = sections
            .find_rva_data(
                file_bytes,
                export_directory_table.export_address_table as usize,
            )
            .ok_or_else(|| {
                PewterError::invalid_image_format(
                    "Failed to map name_pointer_table_data inside image",
                )
            })?;

        let export_ordinal_table_data = sections
            .find_rva_data(
                file_bytes,
                export_directory_table.export_address_table as usize,
            )
            .ok_or_else(|| {
                PewterError::invalid_image_format(
                    "Failed to map export_ordinal_table_data inside image",
                )
            })?;

        let export_name_data = sections
            .find_rva_data(file_bytes, export_directory_table.name_rva as usize)
            .ok_or_else(|| {
                PewterError::invalid_image_format(
                    "Failed to map export_ordinal_table_data inside image",
                )
            })?;

        let export_name_table = {
            let mut values =
                Vec::with_capacity(export_directory_table.number_of_name_pointers as usize);
            let mut offset = 0;
            for _ in 0..export_directory_table.number_of_name_pointers as usize {
                let current_str_start = &export_name_data[offset..];
                let null_term_pos = current_str_start.iter().position(|c| *c == 0).unwrap_or(0);
                values.push(String::from_utf8_lossy(&current_str_start[..null_term_pos]).into());
                offset += null_term_pos;
            }
            Table(values)
        };

        Ok(Self {
            export_address_table: Table::new_linear(
                &mut export_address_table_data.as_ref(),
                export_directory_table.address_table_entries as usize,
            )?,
            name_pointer_table: Table::new_linear(
                &mut name_pointer_table_data.as_ref(),
                export_directory_table.number_of_name_pointers as usize,
            )?,
            export_ordinal_table: Table::new_linear(
                &mut export_ordinal_table_data.as_ref(),
                export_directory_table.number_of_name_pointers as usize,
            )?,
            export_name_table,
            export_directory_table,
        })
    }
}

/// The export symbol information begins with the export directory table,
/// which describes the remainder of the export symbol information.
/// The export directory table contains address information that is used to
/// resolve imports to the entry points within this image.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportDirectory {
    /// Reserved, must be 0.
    pub export_flags: u32,
    /// The time and date that the export data was created.
    pub time_date_stamp: u32,
    /// The major version number. The major and minor version numbers can be set by the user.
    pub major_version: u16,
    /// The minor version number.
    pub minor_version: u16,
    /// The address of the ASCII string that contains the name of the DLL.
    /// This address is relative to the image base.
    pub name_rva: u32,
    /// The starting ordinal number for exports in this image. This field specifies the starting
    /// ordinal number for the export address table. It is usually set to 1.
    pub ordinal_base: u32,
    /// The number of entries in the export address table.
    pub address_table_entries: u32,
    /// The number of entries in the name pointer table.
    /// This is also the number of entries in the ordinal table.
    pub number_of_name_pointers: u32,
    /// The address of the export address table, relative to the image base.
    pub export_address_table: u32,
    /// The address of the export name pointer table, relative to the image base.
    /// The table size is given by the Number of Name Pointers field.
    pub name_pointer_rva: u32,
    /// The address of the ordinal table, relative to the image base.
    pub ordinal_table_rva: u32,
}

impl ReadData for ExportDirectory {
    fn read(reader: &mut impl crate::io::Reader) -> Result<Self> {
        Ok(Self {
            export_flags: reader.read()?,
            time_date_stamp: reader.read()?,
            major_version: reader.read()?,
            minor_version: reader.read()?,
            name_rva: reader.read()?,
            ordinal_base: reader.read()?,
            address_table_entries: reader.read()?,
            number_of_name_pointers: reader.read()?,
            export_address_table: reader.read()?,
            name_pointer_rva: reader.read()?,
            ordinal_table_rva: reader.read()?,
        })
    }
}

impl WriteData for ExportDirectory {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> Result<()> {
        writer.write(self.export_flags)?;
        writer.write(self.time_date_stamp)?;
        writer.write(self.major_version)?;
        writer.write(self.minor_version)?;
        writer.write(self.name_rva)?;
        writer.write(self.ordinal_base)?;
        writer.write(self.address_table_entries)?;
        writer.write(self.number_of_name_pointers)?;
        writer.write(self.export_address_table)?;
        writer.write(self.name_pointer_rva)?;
        writer.write(self.ordinal_table_rva)?;
        Ok(())
    }
}

/// Each entry in the export address table is a field that uses one of two formats in the following table.
/// If the address specified is not within the export section (as defined by the address and length that are
/// indicated in the optional header), the field is an export RVA, which is an actual address in code or data.
/// Otherwise, the field is a forwarder RVA, which names a symbol in another DLL.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportAddress {
    /// The address of the exported symbol when loaded into memory,
    /// relative to the image base. For example, the address of an exported function.
    pub export_rva: u32,
    /// The pointer to a null-terminated ASCII string in the export section.
    /// This string must be within the range that is given by the export table data directory entry.
    /// See [DataDirectories::export_table](super::optional_header::data_directories::DataDirectories::export_table)
    ///
    /// This string gives the DLL name and the name of the export (for example, "MYDLL.expfunc") or the DLL name and
    /// the ordinal number of the export (for example, "MYDLL.#27").
    pub forwarder_rva: u32,
}

impl ReadData for ExportAddress {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            export_rva: reader.read()?,
            forwarder_rva: reader.read()?,
        })
    }
}

impl WriteData for ExportAddress {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.export_rva)?;
        writer.write(self.forwarder_rva)?;
        Ok(())
    }
}

/// Pointer into the export name table.
/// An export name is defined only if the export name pointer table contains a pointer to it.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportNamePointer(pub u32);

impl ReadData for ExportNamePointer {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self(reader.read()?))
    }
}

impl WriteData for ExportNamePointer {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.0)?;
        Ok(())
    }
}

/// Index into the export address table. Ordinals are biased by the Ordinal Base field of the export directory table.
/// In other words, the ordinal base must be subtracted from the ordinals to obtain true indexes into the export address table.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportOrtinal(pub u16);

impl ReadData for ExportOrtinal {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self(reader.read()?))
    }
}

impl WriteData for ExportOrtinal {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.0)?;
        Ok(())
    }
}

/// Every exported symbol has an ordinal value, which is just the index into the export address table.
/// Use of export names, however, is optional. Some, all, or none of the exported symbols can have export names.
/// For exported symbols that do have export names, corresponding entries in the export name pointer table and
/// export ordinal table work together to associate each name with an ordinal.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportName(pub u16);

impl ReadData for ExportName {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self(reader.read()?))
    }
}

impl WriteData for ExportName {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.0)?;
        Ok(())
    }
}
