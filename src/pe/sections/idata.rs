//! The .idata Section
//!
//! All image files that import symbols, including virtually all executable (EXE) files,
//! have an .idata section.
use super::{ParseSectionData, Sections};
use crate::{
    containers::Table,
    error::{PewterError, Result},
    io::{ReadData, Reader, WriteData},
    pe::{
        coff::CoffFileHeader,
        optional_header::{OptionalHeader, OptionalHeaderMagic},
    },
};

use crate::{string::String, vec::Vec};

/// The import directory table contains address information that is used to resolve fixup
/// references to the entry points within a DLL image. The import directory table consists of
/// an array of import directory entries, one entry for each DLL to which the image refers.
/// The last directory entry is empty (filled with null values), which indicates the end of the directory table.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ImportTableDataDirectory {
    /// The import directory table contains address information that is used to resolve fixup references
    /// to the entry points within a DLL image. The import directory table consists of an array of import
    /// directory entries, one entry for each DLL to which the image refers. The last directory entry is
    /// empty (filled with null values), which indicates the end of the directory table.
    pub entries: Table<ImportTableDataDirectoryEntry>,
}

impl ParseSectionData for ImportTableDataDirectory {
    fn parse(
        section_data: &[u8],
        sections: &super::Sections,
        optional_header: &OptionalHeader,
        _: &CoffFileHeader,
    ) -> Result<Self> {
        let entries = {
            let mut import_lookup_table_ptr = section_data.as_ref();
            let mut import_directory_tables = Vec::with_capacity(5);
            loop {
                let dir: ImportDirectoryTable = import_lookup_table_ptr.read()?;
                if dir.is_null() {
                    break;
                }

                import_directory_tables.push(ImportTableDataDirectoryEntry::parse(
                    dir,
                    sections,
                    optional_header.standard_fields.magic,
                )?);
            }
            Table(import_directory_tables)
        };

        Ok(Self { entries })
    }
}

/// This is not how data is atcualy structered in the PE file.
/// This groups the `import_directory_table` and `import_lookup_table`
/// to the imoported dll.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ImportTableDataDirectoryEntry {
    /// The import directory table consists of an array of import
    /// directory entries, one entry for each DLL to which the image refers.
    pub import_directory_table: ImportDirectoryTable,
    /// from [`ImportDirectoryTable::name_rva`]
    pub dll_name: String,
    /// An import lookup table is an array of 32-bit numbers for PE32 or an array of 64-bit numbers for PE32+.
    /// Each entry uses the bit-field format that is described in the following table. In this format, bit 31
    /// is the most significant bit for PE32 and bit 63 is the most significant bit for PE32+.
    /// The collection of these entries describes all imports from a given DLL. The last entry is set to
    /// zero (NULL) to indicate the end of the table.
    pub import_lookup_table: Table<ImportTableRow>,
}

impl ImportTableDataDirectoryEntry {
    pub fn parse(
        import_directory_table: ImportDirectoryTable,
        sections: &Sections,
        magic: OptionalHeaderMagic,
    ) -> Result<Self> {
        let import_lookup_table_data = sections
            .find_rva_data(import_directory_table.import_lookup_table_rva as usize)
            .ok_or_else(|| {
                PewterError::invalid_image_format(
                    "Failed to map import_lookup_table_rva inside image",
                )
            })?;

        let import_lookup_table = {
            let mut lookup_table_data_ptr = import_lookup_table_data;
            let mut lookup_items = Vec::new();
            loop {
                let lookup_entry = match magic {
                    OptionalHeaderMagic::PE32 => {
                        ImportTableRow::from_u32(sections, u32::read(&mut lookup_table_data_ptr)?)?
                    }
                    OptionalHeaderMagic::PE32Plus => {
                        ImportTableRow::from_u64(sections, u64::read(&mut lookup_table_data_ptr)?)?
                    }
                };

                if let Some(lookup_entry) = lookup_entry {
                    lookup_items.push(lookup_entry);
                } else {
                    break;
                }
            }
            Table(lookup_items)
        };

        let dll_name = {
            let dll_name_data = sections
                .find_rva_data(import_directory_table.name_rva as usize)
                .ok_or_else(|| {
                    PewterError::invalid_image_format(
                        "Failed to map import_directory_table.name_rva inside image",
                    )
                })?;
            let null_terminator = dll_name_data.iter().position(|c| *c == 0).unwrap_or(0);
            String::from_utf8_lossy(&dll_name_data[..null_terminator]).into()
        };

        Ok(Self {
            import_directory_table,
            dll_name,
            import_lookup_table,
        })
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ImportDirectoryTable {
    /// The RVA of the import lookup table.
    /// This table contains a name or ordinal for each import.
    /// (The name "Characteristics" is used in Winnt.h, but no longer describes this field.)
    pub import_lookup_table_rva: u32,
    /// The stamp that is set to zero until the image is bound. After the image is bound,
    /// this field is set to the time/data stamp of the DLL.
    pub time_date_stamp: u32,
    /// The index of the first forwarder reference.
    pub fowarder_chain: u32,
    /// The address of an ASCII string that contains the name of the DLL.
    /// This address is relative to the image base.
    pub name_rva: u32,
    /// The RVA of the import address table. The contents of this table are identical
    /// to the contents of the import lookup table until the image is bound.
    pub import_address_table_rva: u32,
}

impl ImportDirectoryTable {
    pub fn is_null(&self) -> bool {
        self == &ImportDirectoryTable::default()
    }
}

impl ReadData for ImportDirectoryTable {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            import_lookup_table_rva: reader.read()?,
            time_date_stamp: reader.read()?,
            fowarder_chain: reader.read()?,
            name_rva: reader.read()?,
            import_address_table_rva: reader.read()?,
        })
    }
}

impl WriteData for &ImportDirectoryTable {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.import_lookup_table_rva)?;
        writer.write(self.time_date_stamp)?;
        writer.write(self.fowarder_chain)?;
        writer.write(self.name_rva)?;
        writer.write(self.import_address_table_rva)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ImportTableRow {
    /// If this bit is set, import by ordinal. Otherwise, import by name.
    /// Bit is masked as 0x80000000 for PE32, 0x8000000000000000 for PE32+.
    Ordinal(u16),
    HintName {
        /// A 16-bit ordinal number. This field is used only if the Ordinal/Name
        /// Flag bit field is 1 (import by ordinal). Bits 30-15 or 62-15 must be 0.
        hint: u16,
        /// A 31-bit RVA of a hint/name table entry. This field is used only if the
        /// Ordinal/Name Flag bit field is 0 (import by name). For PE32+ bits 62-31 must be zero.
        name_rva: u32,
        /// The name read from the name_rva
        name: String,
    },
}

impl ImportTableRow {
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Ordinal(0))
    }
    fn from_lower_bits(
        sections: &Sections,
        import_by_ordinal: bool,
        rest_of_fields: u32,
    ) -> Result<Self> {
        if import_by_ordinal {
            return Ok(ImportTableRow::Ordinal((rest_of_fields & 0xFF_FF) as u16));
        }

        let name_rva = (rest_of_fields & 0x7F_FF_FF_FF) as u32;

        let mut hint_rva_location = sections.find_rva_data(name_rva as usize).ok_or_else(|| {
            PewterError::invalid_image_format("Failed to map \"Hint/Name Table RVA\" inside image")
        })?;

        let hint = u16::read(&mut hint_rva_location)?;
        let str_pos = hint_rva_location.iter().position(|c| *c == 0).unwrap_or(0);
        Ok(ImportTableRow::HintName {
            hint,
            name_rva,
            name: String::from_utf8_lossy(&hint_rva_location[..str_pos]).into(),
        })
    }

    pub fn from_u32(sections: &Sections, val: u32) -> Result<Option<Self>> {
        const PE32_LOOKUP_TABLE_ORDINAL_MASK: u32 = 0x80000000;
        if val == 0 {
            return Ok(None);
        }
        let import_by_ordinal = (val & PE32_LOOKUP_TABLE_ORDINAL_MASK) != 0;
        let rest_of_fields = (val & !PE32_LOOKUP_TABLE_ORDINAL_MASK) as u32;
        Self::from_lower_bits(sections, import_by_ordinal, rest_of_fields).map(Some)
    }

    pub fn from_u64(sections: &Sections, val: u64) -> Result<Option<Self>> {
        const PE32_PLUS_LOOKUP_TABLE_ORDINAL_MASK: u64 = 0x8000000000000000;
        if val == 0 {
            return Ok(None);
        }
        let import_by_ordinal = (val & PE32_PLUS_LOOKUP_TABLE_ORDINAL_MASK) != 0;
        let rest_of_fields = (val & !PE32_PLUS_LOOKUP_TABLE_ORDINAL_MASK) as u32;
        Self::from_lower_bits(sections, import_by_ordinal, rest_of_fields).map(Some)
    }
}

impl Default for ImportTableRow {
    fn default() -> Self {
        Self::Ordinal(0)
    }
}
