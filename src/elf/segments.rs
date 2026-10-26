use bitflags::bitflags;
use strum::FromRepr;

use super::ElfReader;
use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u32)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
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
    #[cfg_attr(feature = "reflect", derive(facet::Facet), facet(opaque))]
    pub struct SegmentFlags: u32 {
        const EXECUTE = 0x1;
        const WRITE = 0x2;
        const READ = 0x4;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
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
