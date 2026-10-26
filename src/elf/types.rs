use bitflags::bitflags;
use strum::FromRepr;

use super::ElfReader;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum ElfClass {
    Elf32 = 1,
    Elf64 = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum ElfData {
    Little = 1,
    Big = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u16)]
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

    /// The `R_*_RELATIVE` relocation type: `base + addend`.
    pub fn relative_relocation_type(&self) -> Option<u32> {
        Some(match self {
            Self::X86 | Self::X86_64 => 8,
            Self::Arm => 23,
            Self::AArch64 => 1027,
            Self::RiscV => 3,
            _ => return None,
        })
    }

    /// Relocations that store a symbol's address: absolute, `GLOB_DAT` and `JUMP_SLOT`.
    pub fn absolute_relocation_types(&self) -> &'static [u32] {
        match self {
            Self::X86 | Self::X86_64 => &[1, 6, 7],
            Self::Arm => &[2, 21, 22],
            Self::AArch64 => &[257, 1025, 1026],
            Self::RiscV => &[1, 2, 5],
            _ => &[],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0,
    Load = 1,
    Dynamic = 2,
    Interp = 3,
    Note = 4,
    ShLib = 5,
    Phdr = 6,
    Tls = 7,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelro = 0x6474_E552,
    GnuProperty = 0x6474_E553,
    Other(u32) = 0xFFFF_FFFF,
}

impl SegmentType {
    pub fn from_u32(value: u32) -> Self {
        Self::from_repr(value).unwrap_or(Self::Other(value))
    }

    pub fn to_u32(&self) -> u32 {
        crate::open_enum_value!(self, u32)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct SegmentFlags: u32 {
        const EXECUTE = 0x1;
        const WRITE = 0x2;
        const READ = 0x4;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramHeader {
    pub segment_type: SegmentType,
    pub flags: SegmentFlags,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub align: u64,
}

impl ProgramHeader {
    pub(crate) fn read(r: &mut ElfReader) -> Result<Self> {
        let segment_type = SegmentType::from_u32(r.u32()?);
        if r.is_64 {
            Ok(Self {
                segment_type,
                flags: SegmentFlags::from_bits_retain(r.u32()?),
                offset: r.u64()?,
                vaddr: r.u64()?,
                paddr: r.u64()?,
                file_size: r.u64()?,
                memory_size: r.u64()?,
                align: r.u64()?,
            })
        } else {
            let offset = r.u32()? as u64;
            let vaddr = r.u32()? as u64;
            let paddr = r.u32()? as u64;
            let file_size = r.u32()? as u64;
            let memory_size = r.u32()? as u64;
            let flags = SegmentFlags::from_bits_retain(r.u32()?);
            Ok(Self {
                segment_type,
                flags,
                offset,
                vaddr,
                paddr,
                file_size,
                memory_size,
                align: r.u32()? as u64,
            })
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u32)]
pub enum SectionType {
    Null = 0,
    ProgBits = 1,
    SymTab = 2,
    StrTab = 3,
    Rela = 4,
    Hash = 5,
    Dynamic = 6,
    Note = 7,
    NoBits = 8,
    Rel = 9,
    ShLib = 10,
    DynSym = 11,
    InitArray = 14,
    FiniArray = 15,
    PreinitArray = 16,
    Group = 17,
    SymTabShndx = 18,
    GnuHash = 0x6FFF_FFF6,
    GnuVerDef = 0x6FFF_FFFD,
    GnuVerNeed = 0x6FFF_FFFE,
    GnuVerSym = 0x6FFF_FFFF,
    Other(u32) = 0xFFFF_FFFF,
}

impl SectionType {
    pub fn from_u32(value: u32) -> Self {
        Self::from_repr(value).unwrap_or(Self::Other(value))
    }

    pub fn to_u32(&self) -> u32 {
        crate::open_enum_value!(self, u32)
    }
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct SectionFlags: u64 {
        const WRITE = 0x1;
        const ALLOC = 0x2;
        const EXECINSTR = 0x4;
        const MERGE = 0x10;
        const STRINGS = 0x20;
        const INFO_LINK = 0x40;
        const TLS = 0x400;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionHeader {
    /// Offset of the name in the section name string table.
    pub name: u32,
    pub section_type: SectionType,
    pub flags: SectionFlags,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addr_align: u64,
    pub entry_size: u64,
}

impl SectionHeader {
    pub(crate) fn read(r: &mut ElfReader) -> Result<Self> {
        Ok(Self {
            name: r.u32()?,
            section_type: SectionType::from_u32(r.u32()?),
            flags: SectionFlags::from_bits_retain(r.word()?),
            addr: r.word()?,
            offset: r.word()?,
            size: r.word()?,
            link: r.u32()?,
            info: r.u32()?,
            addr_align: r.word()?,
            entry_size: r.word()?,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum SymbolType {
    NoType = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
    Common = 5,
    Tls = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum SymbolBinding {
    Local = 0,
    Global = 1,
    Weak = 2,
    /// `STB_GNU_UNIQUE`
    GnuUnique = 10,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol<'a> {
    pub name: &'a str,
    pub name_offset: u32,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub section_index: u16,
    /// From `.dynsym` rather than `.symtab`.
    pub dynamic: bool,
}

impl Symbol<'_> {
    pub(crate) fn read(r: &mut ElfReader, is_64: bool) -> Result<Self> {
        let name_offset = r.u32()?;
        let (value, size, info, other, section_index) = if is_64 {
            let info = r.u8()?;
            let other = r.u8()?;
            let section_index = r.u16()?;
            (r.u64()?, r.u64()?, info, other, section_index)
        } else {
            let value = r.u32()? as u64;
            let size = r.u32()? as u64;
            (value, size, r.u8()?, r.u8()?, r.u16()?)
        };
        Ok(Self {
            name: "",
            name_offset,
            value,
            size,
            info,
            other,
            section_index,
            dynamic: false,
        })
    }

    pub fn symbol_type(&self) -> Option<SymbolType> {
        SymbolType::from_repr(self.info & 0xF)
    }

    pub fn binding(&self) -> Option<SymbolBinding> {
        SymbolBinding::from_repr(self.info >> 4)
    }

    /// Defined in this file, rather than imported.
    pub fn is_defined(&self) -> bool {
        self.section_index != 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    pub offset: u64,
    /// Index into the symbol table the section links to (`.dynsym` for dynamic relocations).
    pub symbol: u32,
    pub relocation_type: u32,
    /// `None` for `SHT_REL`, where the addend is stored at `offset`.
    pub addend: Option<i64>,
}

impl Relocation {
    pub(crate) fn read(r: &mut ElfReader, is_64: bool, has_addend: bool) -> Result<Self> {
        let offset = r.word()?;
        let info = r.word()?;
        let (symbol, relocation_type) = if is_64 {
            ((info >> 32) as u32, (info & 0xFFFF_FFFF) as u32)
        } else {
            ((info >> 8) as u32, (info & 0xFF) as u32)
        };
        let addend = if has_addend {
            Some(if is_64 { r.u64()? as i64 } else { r.u32()? as i32 as i64 })
        } else {
            None
        };
        Ok(Self {
            offset,
            symbol,
            relocation_type,
            addend,
        })
    }
}
