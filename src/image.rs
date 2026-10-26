//! A read-only view of a loaded executable by virtual address, over PE or ELF.
//!
//! Reads bytes and pointer-sized values at the virtual addresses they will have
//! once loaded (after relocation), and enumerates the non-executable data
//! segments. Useful for scanning a mapped image for data structures, such as an
//! Il2Cpp game's registration tables.

use crate::{
    elf::{ElfFile, RelocatedPointers, SegmentFlags, SegmentType},
    error::Result,
    pe::{file::definition::PEImageDef, sections::SectionFlags},
    vec::Vec,
};

/// Reads a loaded binary by virtual address, as it will be after relocation.
pub trait LoadedImage {
    /// Whether pointers are 64-bit.
    fn is_64(&self) -> bool;
    /// `len` bytes at virtual address `vaddr`, or `None` if unmapped.
    fn bytes(&self, vaddr: u64, len: usize) -> Option<&[u8]>;
    /// A pointer-sized value at `vaddr`, after relocation.
    fn pointer(&self, vaddr: u64) -> Option<u64>;
    /// Virtual-address ranges of the loaded, non-executable segments (where
    /// data such as tables of pointers lives).
    fn data_segments(&self) -> Vec<(u64, u64)>;

    fn pointer_size(&self) -> u64 {
        if self.is_64() {
            8
        } else {
            4
        }
    }

    fn u32(&self, vaddr: u64) -> Option<u32> {
        self.bytes(vaddr, 4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
    }

    fn u8(&self, vaddr: u64) -> Option<u8> {
        self.bytes(vaddr, 1).map(|b| b[0])
    }

    /// Whether `vaddr` is a non-null, mapped address.
    fn is_mapped(&self, vaddr: u64) -> bool {
        vaddr != 0 && self.bytes(vaddr, 1).is_some()
    }
}

/// A loaded ELF image (e.g. a `.so`). Pointers are resolved through the
/// relocation table, since ELF stores relative relocations rather than absolute
/// addresses.
pub struct ElfImage<'a> {
    elf: ElfFile<'a>,
    pointers: RelocatedPointers,
}

impl<'a> ElfImage<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self> {
        let elf = ElfFile::parse(data)?;
        let pointers = elf.relocated_pointers()?;
        Ok(Self { elf, pointers })
    }
}

impl LoadedImage for ElfImage<'_> {
    fn is_64(&self) -> bool {
        self.elf.is_64()
    }

    fn bytes(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        self.elf.data_at_vaddr(vaddr)?.get(..len)
    }

    fn pointer(&self, vaddr: u64) -> Option<u64> {
        let value = self.elf.read_pointer(vaddr, &self.pointers)?;
        Some(if self.is_64() {
            value
        } else {
            value & 0xFFFF_FFFF
        })
    }

    fn data_segments(&self) -> Vec<(u64, u64)> {
        self.elf
            .program_headers
            .iter()
            .filter(|p| {
                p.segment_type == SegmentType::Load && !p.flags.contains(SegmentFlags::EXECUTE)
            })
            .map(|p| (p.vaddr, p.vaddr + p.file_size))
            .collect()
    }
}

/// A loaded PE image (e.g. a `.dll`). Pointers stored in a PE hold absolute
/// virtual addresses at the preferred image base, so no relocation step is
/// needed: the on-disk values and the addresses computed here share that base.
pub struct PeImage {
    pe: PEImageDef,
    image_base: u64,
}

impl PeImage {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let pe = PEImageDef::parse(data)?;
        let image_base = pe.optional_header.windows_specific_fields.image_base();
        Ok(Self { pe, image_base })
    }

    /// The parsed image.
    pub fn file(&self) -> &PEImageDef {
        &self.pe
    }

    /// The preferred image base.
    pub fn image_base(&self) -> u64 {
        self.image_base
    }
}

impl LoadedImage for PeImage {
    fn is_64(&self) -> bool {
        self.pe
            .optional_header
            .windows_specific_fields
            .is_pe32_plus()
    }

    fn bytes(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        let rva = vaddr.checked_sub(self.image_base)?;
        self.pe.read_at_rva(u32::try_from(rva).ok()?, len)
    }

    fn pointer(&self, vaddr: u64) -> Option<u64> {
        let size = self.pointer_size() as usize;
        let bytes = self.bytes(vaddr, size)?;
        let mut buf = [0u8; 8];
        buf[..size].copy_from_slice(bytes);
        Some(u64::from_le_bytes(buf))
    }

    fn data_segments(&self) -> Vec<(u64, u64)> {
        self.pe
            .sections
            .iter()
            .filter(|s| {
                !s.characteristics.contains(SectionFlags::MEM_EXECUTE)
                    && !s.characteristics.contains(SectionFlags::CNT_CODE)
            })
            .map(|s| {
                let start = self.image_base + s.virtual_address as u64;
                (start, start + s.virtual_size() as u64)
            })
            .collect()
    }
}
