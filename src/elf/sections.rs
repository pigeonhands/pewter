use bitflags::bitflags;
use strum::FromRepr;

use super::ElfReader;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u32)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
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
    #[cfg_attr(feature = "reflect", derive(facet::Facet), facet(opaque))]
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
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
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

/// A section with its name and contents.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
pub struct Section<'a> {
    pub header: SectionHeader,
    pub name: &'a str,
    /// Empty for `SHT_NOBITS` sections such as `.bss`.
    pub data: &'a [u8],
}
