
//! The MS-DOS stub is a valid application that runs under MS-DOS. 
//! It is placed at the front of the EXE image. The linker places a default stub here, 
//! which prints out the message "This program cannot be run in DOS mode" when the image is 
//! run in MS-DOS. The user can specify a different stub by using the /STUB linker option.
//! At location 0x3c, the stub has the file offset to the PE signature. 
//! This information enables Windows to properly execute the image file, even though it has an MS-DOS stub. 
//! This file offset is placed at location 0x3c during linking.
use crate::io::{ReadData, WriteData};

/// This is the structure at the beginning of every PE file.
/// It mainaly contains legacy MS-DOS header that are not relivant
/// to modern windows. The field of importants is  `e_lfanew`, witch
/// points to the new windows header.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ImageDosHeader {
    /// Magic number
    pub e_magic: u16,
    /// Bytes on last page of file
    pub e_cblp: u16,
    /// Pages in file
    pub e_cp: u16,
    /// Relocations
    pub e_crlc: u16,
    /// Size of header in paragraphs needed
    pub e_cparhdr: u16,
    /// Minimum extra paragraphs needed
    pub e_minalloc: u16,
    /// Maximum  extra paragraphs needed
    pub e_maxalloc: u16,
    /// Initial (relative) SS value
    pub e_ss: u16,
    /// Initial SP value
    pub e_sp: u16,
    /// Checksum
    pub e_csum: u16,
    /// Initial IP value
    pub e_ip: u16,
    /// Initial (relative) CS value
    pub e_cs: u16,
    /// File address of relocation table
    pub e_lfarlc: u16,
    /// Overlay number
    pub e_ovno: u16,
    /// Reserved words
    pub e_res: [u16; 4],
    /// OEM identifier (for e_oeminfo)
    pub e_oemid: u16,
    /// OEM information; e_oemid specific
    pub e_oeminfo: u16,
    /// Reserved words
    pub e_res2: [u16; 10],
    ///  File address of new exe header
    pub e_lfanew: u32,
}

impl ImageDosHeader {
    /// The expected value of `e_magic`.
    pub const MAGIC_CONSTANT : u16 = 0x5A4D ;

    pub const SIZE : usize = 64;
}

impl ReadData for ImageDosHeader {
    fn read_from(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            e_magic: reader.read()?,
            e_cblp: reader.read()?,
            e_cp: reader.read()?,
            e_crlc: reader.read()?,
            e_cparhdr: reader.read()?,
            e_minalloc: reader.read()?,
            e_maxalloc: reader.read()?,
            e_ss: reader.read()?,
            e_sp: reader.read()?,
            e_csum: reader.read()?,
            e_ip: reader.read()?,
            e_cs: reader.read()?,
            e_lfarlc: reader.read()?,
            e_ovno: reader.read()?,
            e_res: reader.read()?,
            e_oemid: reader.read()?,
            e_oeminfo: reader.read()?,
            e_res2: reader.read()?,
            e_lfanew: reader.read()?,
        })
    }
}

impl WriteData for ImageDosHeader {
    fn write_to(&self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.e_magic)?;
        writer.write(self.e_cblp)?;
        writer.write(self.e_cp)?;
        writer.write(self.e_crlc)?;
        writer.write(self.e_cparhdr)?;
        writer.write(self.e_minalloc)?;
        writer.write(self.e_maxalloc)?;
        writer.write(self.e_ss)?;
        writer.write(self.e_sp)?;
        writer.write(self.e_csum)?;
        writer.write(self.e_ip)?;
        writer.write(self.e_cs)?;
        writer.write(self.e_lfarlc)?;
        writer.write(self.e_ovno)?;
        writer.write(self.e_res)?;
        writer.write(self.e_oemid)?;
        writer.write(self.e_oeminfo)?;
        writer.write(self.e_res2)?;
        writer.write(self.e_lfanew)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ImageDosHeader;
    use crate::io::*;
    #[test]
    fn dos_header_is_64_bytes() {
        let buffer = [0u8;ImageDosHeader::SIZE];
        let read_ptr = &mut buffer.as_slice();

        ImageDosHeader::read_from(read_ptr).unwrap();
        assert!(read_ptr.is_empty());
    }


    #[test]
    fn read_dos_header() {
        let mut dos_bytes = [0u8;ImageDosHeader::SIZE];
        dos_bytes[0..2].copy_from_slice(&ImageDosHeader::MAGIC_CONSTANT.to_le_bytes());
        dos_bytes[60..ImageDosHeader::SIZE].copy_from_slice(&123456u32.to_le_bytes());
        let out_dos = ImageDosHeader::read_from(&mut dos_bytes.as_slice()).unwrap();
        let expected_dos = ImageDosHeader{
            e_magic: ImageDosHeader::MAGIC_CONSTANT,
            e_lfanew: 123456u32,
            ..Default::default()
        };
        assert_eq!(out_dos, expected_dos);
    }

    #[test]
    fn read_write_dos_header() {
        let expected_dos = ImageDosHeader{
            e_magic: ImageDosHeader::MAGIC_CONSTANT,
            e_cp: 0xAF,
            e_ip: 0xDE,
            e_minalloc:12,
            e_res2: [0xAA;10],
            e_lfanew: 123456u32,
            ..Default::default()
        };

        let mut dos_bytes = [0u8;ImageDosHeader::SIZE];
        expected_dos.write_to(&mut dos_bytes.as_mut_slice()).unwrap();
        
        let out_dos: ImageDosHeader = ImageDosHeader::read_from(&mut dos_bytes.as_slice()).unwrap();
        assert_eq!(out_dos, expected_dos);
    }
}