pub mod edata;
pub mod idata;
pub mod rsrc;
use crate::containers::Table;
use crate::error::Result;
use crate::io::{ReadData, WriteData};
use bitflags::bitflags;
use core::fmt::Debug;
use std::ops::{Deref, DerefMut};

#[derive(Debug, Default, Clone, PartialEq)]
pub struct SectionTable(Table<SectionTableRow>);

impl SectionTable {
    pub fn new_linear(data_ptr: &mut &[u8], items_count: usize) -> Result<Self> {
        Table::new_linear(data_ptr, items_count).map(Self)
    }

    pub fn new_with_reader(
        data_ptr: &mut &[u8],
        items_count: usize,
        read_item: impl FnMut(&mut &[u8]) -> Result<SectionTableRow>,
    ) -> Result<Self> {
        Table::new_with_reader(data_ptr, items_count, read_item).map(Self)
    }

    pub fn find_rva(&self, virtual_address: usize) -> Option<&SectionTableRow> {
        self.0.iter().find(|row| {
            virtual_address >= (row.virtual_address as usize)
                && virtual_address < (row.virtual_address as usize + row.virtual_size as usize)
        })
    }

    pub fn find_rva_map<T>(
        &self,
        virtual_address: usize,
        func: impl FnMut(&SectionTableRow) -> Result<T>,
    ) -> Result<Option<T>> {
        self.find_rva(virtual_address).map(func).transpose()
    }

    pub fn find_rva_data<'a>(
        &self,
        image_base: &'a [u8],
        virtual_address: usize,
    ) -> Option<&'a [u8]> {
        self.find_rva(virtual_address)
            .map(|section| section.get_data(image_base, virtual_address))
    }

    pub fn find_rva_data_map<T>(
        &self,
        image_base: &[u8],
        virtual_address: usize,
        func: impl FnMut(&[u8]) -> Result<T>,
    ) -> Result<Option<T>> {
        self.find_rva_data(image_base, virtual_address)
            .map(func)
            .transpose()
    }
}

impl Deref for SectionTable {
    type Target = Table<SectionTableRow>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SectionTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct SectionFlags : u32 {
        /// The section should not be padded to the next boundary. 
        /// This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. 
        /// This is valid only for object files. 
        const TYPE_NO_PAD = 0x00000008;
        /// The section contains executable code. 
        const CNT_CODE  = 0x00000020;
        /// The section contains initialized data. 
        const CNT_INITIALIZED_DATA  = 0x00000040;
        /// The section contains uninitialized data. 
        const CNT_UNINITIALIZED_DATA = 0x00000080;
        /// Reserved for future use. 
        const LNK_OTHER = 0x00000100;
        /// The section contains comments or other information. 
        /// The .drectve section has this type. 
        /// This is valid for object files only. 
        const LNK_INFO = 0x00000200;
        /// The section will not become part of the image. 
        /// This is valid only for object files. 
        const LNK_REMOVE = 0x00000800;
        /// The section contains COMDAT data. 
        /// This is valid only for object files. 
        const LNK_COMDAT = 0x00001000;
        /// The section contains data referenced through the global pointer (GP). 
        const SCN_GPREL = 0x00008000;
        /// Reserved for future use.  
        const MEM_PURGEABLE = 0x00020000;
        /// Reserved for future use.  
        const MEM_16BIT = 0x00020000;
        /// Reserved for future use.  
        const MEM_LOCKED = 0x00040000;
        /// Reserved for future use.  
        const MEM_PRELOAD = 0x00080000;
        /// Align data on a 1-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_1BYTES = 0x00100000;
        /// Align data on a 2-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_2BYTES  = 0x00200000;
        /// Align data on a 4-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_4BYTES  = 0x00300000;
        /// Align data on a 8-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_8BYTES   = 0x00400000;
        /// Align data on a 16-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_16BYTES = 0x00500000;
        /// Align data on a 32-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_32BYTES   = 0x00600000;
        /// Align data on a 64-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_64BYTES = 0x00700000;
        /// Align data on a 128-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_127BYTES = 0x00800000;
        /// Align data on a 256-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_256BYTES = 0x00900000;
        /// Align data on a 512-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_512BYTES = 0x00A00000;
        /// Align data on a 1024-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_1024BYTES = 0x00B00000;
        /// Align data on a 2048-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_2048BYTES = 0x00C00000;
        /// Align data on a 4096-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_4096BYTES = 0x00D00000 ;
        /// Align data on a 8192-byte boundary. 
        /// Valid only for object files. 
        const ALIGN_8192BYTES = 0x00E00000;
        /// The section contains extended relocations. 
        const LNK_NRELOC_OVFL = 0x01000000 ;
        /// The section can be discarded as needed. 
        const MEM_DISCARDABLE = 0x02000000;
        /// The section cannot be cached. 
        const MEM_NOT_CACHED = 0x04000000;
        /// The section is not pageable. 
        const MEM_NOT_PAGED = 0x08000000;
        /// The section can be shared in memory. 
        const MEM_SHARED  = 0x10000000 ;
        /// The section can be executed as code. 
        const MEM_EXECUTE = 0x20000000 ;
        /// The section can be read. 
        const MEM_READ = 0x40000000 ;
        /// The section can be written to. 
        const MEM_WRITE  = 0x80000000;
    }
}


#[derive(Debug, Default, Clone, PartialEq)]
pub struct SectionTableRow {
    /// An 8-byte, null-padded UTF-8 encoded string.
    /// If the string is exactly 8 characters long, there is no terminating null.
    /// For longer names, this field contains a slash (/) that is followed by an
    /// ASCII representation of a decimal number that is an offset into the string table.
    /// Executable images do not use a string table and do not support section names
    /// longer than 8 characters. Long names in object files are truncated if they
    /// are emitted to an executable file.
    pub name: [u8; 8],
    /// The total size of the section when loaded into memory. If this value is
    /// greater than SizeOfRawData, the section is zero-padded. This field is valid
    /// only for executable images and should be set to zero for object files.
    pub virtual_size: u32,
    /// For executable images, the address of the first byte of the section relative
    /// to the image base when the section is loaded into memory. For object files,
    /// this field is the address of the first byte before relocation is applied; for
    /// simplicity, compilers should set this to zero. Otherwise, it is an arbitrary
    /// value that is subtracted from offsets during relocation.
    pub virtual_address: u32,
    /// The size of the section (for object files) or the size of the initialized
    /// data on disk (for image files). For executable images, this must be a multiple
    /// of FileAlignment from the optional header. If this is less than VirtualSize,
    /// the remainder of the section is zero-filled. Because the SizeOfRawData field
    /// is rounded but the VirtualSize field is not, it is possible for SizeOfRawData
    /// to be greater than VirtualSize as well. When a section contains only uninitialized
    /// data, this field should be zero.
    pub size_of_raw_data: u32,
    /// The file pointer to the first page of the section within the COFF file.
    /// For executable images, this must be a multiple of FileAlignment from the optional header.
    /// For object files, the value should be aligned on a 4-byte boundary for best performance.
    /// When a section contains only uninitialized data, this field should be zero.
    pub pointer_to_raw_data: u32,
    /// The file pointer to the beginning of relocation entries for the section.
    /// This is set to zero for executable images or if there are no relocations.
    pub pointer_to_relocations: u32,
    /// The file pointer to the beginning of line-number entries for the section.
    /// This is set to zero if there are no COFF line numbers. This value should be zero for an
    /// image because COFF debugging information is deprecated.
    pub pointer_to_line_numbers: u32,
    /// The number of relocation entries for the section.
    /// This is set to zero for executable images.
    pub number_of_relocaions: u16,
    /// The number of line-number entries for the section. This value should be zero
    /// for an image because COFF debugging information is deprecated.
    pub number_of_line_numbers: u16,
    /// The flags that describe the characteristics of the section.
    pub characteristiics: SectionFlags,
}

impl SectionTableRow {
    pub const SIZE: usize = 40;

    pub fn get_data_range(&self, virtual_address: usize) -> (usize, usize) {
        let section_offset = virtual_address - self.virtual_address as usize;
        let section_start = self.pointer_to_raw_data as usize + section_offset;
        let section_end = self.pointer_to_raw_data as usize + self.size_of_raw_data as usize;
        (section_start, section_end)
    }
    pub fn get_data<'a>(&self, image_base: &'a [u8], virtual_address: usize) -> &'a [u8] {
        let (section_start, section_end) = self.get_data_range(virtual_address);
        &image_base[section_start..section_end]
    }

    pub fn try_get_data<'a>(
        &self,
        image_base: &'a [u8],
        virtual_address: usize,
    ) -> Option<&'a [u8]> {
        if virtual_address < self.virtual_address as usize {
            return None;
        }
        let (section_start, section_end) = self.get_data_range(virtual_address);
        (section_start < section_end && section_end < image_base.len())
            .then(|| &image_base[section_start..section_end])
    }
}

impl ReadData for SectionTableRow {
    fn read(reader: &mut impl crate::io::Reader) -> Result<Self> {
        Ok(Self {
            name: reader.read()?,
            virtual_size: reader.read()?,
            virtual_address: reader.read()?,
            size_of_raw_data: reader.read()?,
            pointer_to_raw_data: reader.read()?,
            pointer_to_relocations: reader.read()?,
            pointer_to_line_numbers: reader.read()?,
            number_of_relocaions: reader.read()?,
            number_of_line_numbers: reader.read()?,
            characteristiics: SectionFlags::from_bits_retain(reader.read()?),
        })
    }
}

impl WriteData for SectionTableRow {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> Result<()> {
        writer.write(self.name)?;
        writer.write(self.virtual_address)?;
        writer.write(self.size_of_raw_data)?;
        writer.write(self.pointer_to_raw_data)?;
        writer.write(self.pointer_to_relocations)?;
        writer.write(self.pointer_to_line_numbers)?;
        writer.write(self.number_of_relocaions)?;
        writer.write(self.number_of_line_numbers)?;
        writer.write(self.characteristiics.bits())?;
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SpecialSections {
    /// .edata section
    pub edata: Option<edata::ExportTableDataDirectory>,
    // .idata section
    pub idata: Option<idata::ImportTableDataDirectory>,
}

impl SpecialSections {
    pub fn parse(
        file_bytes: &[u8],
        optional_header: &super::optional_header::OptionalHeader,
        section_table: &SectionTable,
    ) -> Result<Self> {
        let dd = &optional_header.data_directories;

        Ok(Self {
            edata: section_table.find_rva_data_map(
                file_bytes,
                dd.export_table.virtual_address as usize,
                |edata_bytes| {
                    edata::ExportTableDataDirectory::parse(file_bytes, edata_bytes, section_table)
                },
            )?,
            idata: section_table.find_rva_data_map(
                file_bytes,
                dd.import_table.virtual_address as usize,
                |idata_bytes| {
                    idata::ImportTableDataDirectory::parse(
                        file_bytes,
                        idata_bytes,
                        section_table,
                        optional_header.standard_fields.magic,
                    )
                },
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn section_table_row_is_40_bytes() {
        let buffer = [0u8; SectionTableRow::SIZE];
        let read_ptr = &mut buffer.as_slice();
        SectionTableRow::read(read_ptr).unwrap();
        assert!(read_ptr.is_empty());
    }
}
