use bitflags::bitflags;

use crate::io::{ReadData, WriteData};

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ImageFileMachine {
    #[default]
    /// The content of this field is
    /// assumed to be applicable to any machine type
    Unknown = 0x0,
    /// Alpha AXP, 32-bit address space
    Alpha = 0x184,
    /// Alpha 64, 64-bit address space
    Alpha64 = 0x284,
    /// Matsushita AM33
    Am33 = 0x1d3,
    /// x64
    Amd64 = 0x8664,
    /// ARM little endian
    Arm = 0x1c0,
    /// ARM64 little endian
    Arm64 = 0xaa64,
    /// ARM Thumb-2 little endian
    ArmNT = 0x1c4,
    // AXP 64 (Same as Alpha 64)
    // AXP64 = 0x284,
    /// EFI byte code
    Ebc = 0xebc,
    /// Intel 386 or later processors and compatible processors
    I386 = 0x14c,
    /// Intel Itanium processor family
    IA64 = 0x200,
    /// LoongArch 32-bit processor family
    LoongArchH32 = 0x6232,
    /// LoongArch 64-bit processor family
    LoongArch64 = 0x6264,
    /// Mitsubishi M32R little endian
    M32R = 0x9041,
    /// MIPS16
    Mips16 = 0x266,
    /// MIPS with FPU
    MipsFPU = 0x366,
    /// MIPS16 with FPU
    MipsFPU16 = 0x466,
    /// Power PC little endian
    PowerPC = 0x1f0,
    /// Power PC with floating point support
    PowerPCFP = 0x1f1,
    /// MIPS little endian
    R4000 = 0x166,
    /// RISC-V 32-bit address space
    RiscV32 = 0x5032,
    /// RISC-V 64-bit address space
    RiscV64 = 0x5064,
    /// RISC-V 128-bit address space
    RiscV128 = 0x5128,
    /// Hitachi SH3
    Sh3 = 0x1a2,
    // Hitachi SH3 DSP
    // SH3DSP = 0x1a2,
    /// Hitachi SH4
    Sh4 = 0x1a6,
    /// Hitachi Sh5
    Sh5 = 0x1a8,
    /// Thumb
    Thumb = 0x1c2,
    /// MIPS little-endian WCE v2
    WceMipsV2 = 0x169,
    /// Other machine type
    Other(u16),
}

impl ImageFileMachine {
    pub fn from_u16(nachine_type: u16) -> Self {
        match nachine_type {
            0x0 => Self::Unknown,
            0x184 => Self::Alpha,
            0x284 => Self::Alpha64,
            0x1d3 => Self::Am33,
            0x8664 => Self::Amd64,
            0x1c0 => Self::Arm,
            0xaa64 => Self::Arm64,
            0x1c4 => Self::ArmNT,
            0xebc => Self::Ebc,
            0x14c => Self::I386,
            0x200 => Self::IA64,
            0x6232 => Self::LoongArchH32,
            0x6264 => Self::LoongArch64,
            0x9041 => Self::M32R,
            0x266 => Self::Mips16,
            0x366 => Self::MipsFPU,
            0x466 => Self::MipsFPU16,
            0x1f0 => Self::PowerPC,
            0x1f1 => Self::PowerPCFP,
            0x166 => Self::R4000,
            0x5032 => Self::RiscV32,
            0x5064 => Self::RiscV64,
            0x5128 => Self::RiscV128,
            0x1a2 => Self::Sh3,
            0x1a6 => Self::Sh4,
            0x1a8 => Self::Sh5,
            0x1c2 => Self::Thumb,
            0x169 => Self::WceMipsV2,
            n => Self::Other(n),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Unknown => 0x0,
            Self::Alpha => 0x184,
            Self::Alpha64 => 0x284,
            Self::Am33 => 0x1d3,
            Self::Amd64 => 0x8664,
            Self::Arm => 0x1c0,
            Self::Arm64 => 0xaa64,
            Self::ArmNT => 0x1c4,
            Self::Ebc => 0xebc,
            Self::I386 => 0x14c,
            Self::IA64 => 0x200,
            Self::LoongArchH32 => 0x6232,
            Self::LoongArch64 => 0x6264,
            Self::M32R => 0x9041,
            Self::Mips16 => 0x266,
            Self::MipsFPU => 0x366,
            Self::MipsFPU16 => 0x466,
            Self::PowerPC => 0x1f0,
            Self::PowerPCFP => 0x1f1,
            Self::R4000 => 0x166,
            Self::RiscV32 => 0x5032,
            Self::RiscV64 => 0x5064,
            Self::RiscV128 => 0x5128,
            Self::Sh3 => 0x1a2,
            Self::Sh4 => 0x1a6,
            Self::Sh5 => 0x1a8,
            Self::Thumb => 0x1c2,
            Self::WceMipsV2 => 0x169,
            Self::Other(n) => *n,
        }
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ImageFileCharacteristics: u16 {
        /// Image only, Windows CE, and Microsoft Windows NT and later.
        /// This indicates that the file does not contain base relocations
        /// and must therefore be loaded at its preferred base address.
        /// If the base address is not available, the loader reports an error.
        /// The default behavior of the linker is to strip base relocations
        /// from executable (EXE) files.
        const RELOCS_STRIPPED = 0x0001;
        /// Image only. This indicates that the image file is valid and can be run.
        /// If this flag is not set, it indicates a linker error.
        const EXECUTABLE_IMAGE = 0x0002;
        /// COFF line numbers have been removed. This flag is deprecated and should be zero.
        const LINE_NUMBERS_SCRIPPED = 0x0004;
        /// COFF symbol table entries for local symbols have been removed. 
        /// This flag is deprecated and should be zero.
        const LINE_LOCAL_SYMS_STRIPPED = 0x0008 ;
        /// Obsolete. Aggressively trim working set. This flag is deprecated for Windows
        /// 2000 and later and must be zero.
        const AGGRESSIVE_WS_TRIM = 0x0008;
        /// Application can handle > 2-GB addresses.
        const LARGE_ADDRESS_AWARE = 0x0020;
        /// This flag is reserved for future use.
        const RESERVED = 0x0040;
        /// Little endian: the least significant bit (LSB) precedes the most
        /// significant bit (MSB) in memory. his flag is deprecated and should be zero.
        const BYTES_REVERSED_LO = 0x0080;
        /// Machine is based on a 32-bit-word architecture.
        const FOR_32BIT_MACHINE = 0x0100;
        /// Debugging information is removed from the image file.
        const DEBUG_STRIPPED = 0x0200;
        /// If the image is on removable media, fully load it and copy it to the swap file.
        const REMOVABLE_RUN_FROM_SWAP = 0x0400;
        /// If the image is on network media, fully load it and copy it to the swap file.
        const NET_RUN_FROM_SWAP = 0x0800;
        /// The image file is a system file, not a user program.
        const FILE_SYSTEM = 0x1000;
        /// The image file is a dynamic-link library (DLL).
        /// Such files are considered executable files for almost all purposes,
        /// although they cannot be directly run.
        const FILE_DLL  = 0x2000;
        /// The file should be run only on a uniprocessor machine.
        const FILE_UP_SYSTEM_ONLY = 0x4000;
        /// Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
        const BYTES_REVERSED_HI = 0x8000;
    }
}

/// At the beginning of an object file, or immediately after the signature of an image file,
/// is a standard COFF file header in the following format. Note that the Windows
/// loader limits the number of sections to 96.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct CoffFileHeader {
    /// The number that identifies the type of target machine.
    pub machine: ImageFileMachine,
    /// The number of sections. This indicates the size of the section table,
    /// which immediately follows the headers.
    pub number_of_sections: u16,
    /// The low 32 bits of the number of seconds since 00:00 January 1, 1970
    /// (a C run-time time_t value), which indicates when the file was created.
    pub date_time_stamp: u32,
    /// The file offset of the COFF symbol table, or zero if no COFF symbol table is present.
    /// This value should be zero for an image because COFF debugging information is deprecated.
    pub pointer_to_symbol_table: u32,
    /// The number of entries in the symbol table. This data can be used to locate the
    /// string table, which immediately follows the symbol table. This value should be zero
    /// for an image because COFF debugging information is deprecated.
    pub number_of_symbols: u32,
    /// The size of the optional header, which is required for executable files but not
    /// for object files. This value should be zero for an object file. For a description
    /// of the header format, see Optional Header (Image Only).
    pub size_of_optional_header: u16,
    /// The flags that indicate the attributes of the file. For specific flag values, see Characteristics.
    pub characteristics: ImageFileCharacteristics,
}

impl CoffFileHeader {
    pub const SIZE: usize = 20;
}

impl ReadData for CoffFileHeader {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            machine: ImageFileMachine::from_u16(reader.read()?),
            number_of_sections: reader.read()?,
            date_time_stamp: reader.read()?,
            pointer_to_symbol_table: reader.read()?,
            number_of_symbols: reader.read()?,
            size_of_optional_header: reader.read()?,
            characteristics: ImageFileCharacteristics::from_bits_retain(reader.read()?),
        })
    }
}

impl WriteData for &CoffFileHeader {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.machine.to_u16())?;
        writer.write(self.number_of_sections)?;
        writer.write(self.date_time_stamp)?;
        writer.write(self.pointer_to_symbol_table)?;
        writer.write(self.number_of_symbols)?;
        writer.write(self.size_of_optional_header)?;
        writer.write(self.characteristics.bits())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn coff_header_is_20_bytes() {
        let buffer = [0u8; CoffFileHeader::SIZE];
        let read_ptr = &mut buffer.as_slice();
        CoffFileHeader::read(read_ptr).unwrap();
        assert_eq!(read_ptr.len(), 0);
    }

    #[test]
    fn read_coff_image_header() {
        let mut dos_bytes = [0u8; 20];
        dos_bytes[0..2].copy_from_slice(&ImageFileMachine::RiscV64.to_u16().to_le_bytes());
        dos_bytes[18..20].copy_from_slice(
            &(ImageFileCharacteristics::FILE_DLL | ImageFileCharacteristics::FOR_32BIT_MACHINE)
                .bits()
                .to_le_bytes(),
        );
        let out_dos = CoffFileHeader::read(&mut dos_bytes.as_slice()).unwrap();
        let expected_dos = CoffFileHeader {
            machine: ImageFileMachine::RiscV64,
            characteristics: ImageFileCharacteristics::FILE_DLL
                | ImageFileCharacteristics::FOR_32BIT_MACHINE,
            ..Default::default()
        };
        assert_eq!(out_dos, expected_dos);
    }

    #[test]
    fn read_write_coff_image_header() {
        let expected_dos = CoffFileHeader {
            machine: ImageFileMachine::Other(0xABCD),
            characteristics: ImageFileCharacteristics::FILE_DLL
                | ImageFileCharacteristics::FOR_32BIT_MACHINE,
            number_of_symbols: 100,
            number_of_sections: 22,
            pointer_to_symbol_table: 33,
            date_time_stamp: 84934,
            size_of_optional_header: 123,
        };
        let mut coff_header = [0u8; 20];
        expected_dos
            .write_to(&mut coff_header.as_mut_slice())
            .unwrap();

        let out_dos = CoffFileHeader::read(&mut coff_header.as_slice()).unwrap();
        assert_eq!(out_dos, expected_dos);
    }
}
