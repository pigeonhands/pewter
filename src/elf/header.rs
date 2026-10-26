use strum::FromRepr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
pub enum ElfClass {
    Elf32 = 1,
    Elf64 = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
pub enum ElfData {
    Little = 1,
    Big = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u16)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
pub enum ElfType {
    None = 0,
    /// Relocatable object file.
    Rel = 1,
    /// Executable.
    Exec = 2,
    /// Shared object (also position independent executables).
    Dyn = 3,
    Core = 4,
    Other(u16) = 0xFFFF,
}

impl ElfType {
    pub fn from_u16(value: u16) -> Self {
        Self::from_repr(value).unwrap_or(Self::Other(value))
    }

    pub fn to_u16(&self) -> u16 {
        crate::open_enum_value!(self, u16)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u16)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
pub enum ElfMachine {
    None = 0,
    X86 = 3,
    Arm = 40,
    X86_64 = 62,
    AArch64 = 183,
    RiscV = 243,
    Other(u16) = 0xFFFF,
}

impl ElfMachine {
    pub fn from_u16(value: u16) -> Self {
        Self::from_repr(value).unwrap_or(Self::Other(value))
    }

    pub fn to_u16(&self) -> u16 {
        crate::open_enum_value!(self, u16)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
pub struct ElfHeader {
    pub class: ElfClass,
    pub byte_order: ElfData,
    pub os_abi: u8,
    pub abi_version: u8,
    pub file_type: ElfType,
    pub machine: ElfMachine,
    pub version: u32,
    pub entry: u64,
    pub program_header_offset: u64,
    pub section_header_offset: u64,
    pub flags: u32,
    pub header_size: u16,
    pub program_header_entry_size: u16,
    pub program_header_count: u16,
    pub section_header_entry_size: u16,
    pub section_header_count: u16,
    /// Index of the section holding section names.
    pub section_name_index: u16,
}
