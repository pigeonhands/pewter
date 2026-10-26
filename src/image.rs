//! A read-only view of a loaded executable by virtual address, over PE or ELF.
//!
//! Reads bytes and pointer-sized values at the virtual addresses they will have
//! once loaded (after relocation), and enumerates the non-executable data
//! segments. Useful for scanning a mapped image for data structures, such as an
//! Il2Cpp game's registration tables.
//!
//! [`AnyImage::load`] detects the format.

use crate::{
    boxed::Box,
    elf::{ElfFile, RelocatedPointers, SegmentFlags, SegmentType, SymbolBinding, SymbolType},
    error::Result,
    format,
    pe::{coff::ImageFileMachine, file::definition::PEImageDef, sections::SectionFlags},
    string::String,
    vec::Vec,
};

/// A symbol exported by an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// `None` for a PE export by ordinal only.
    pub name: Option<String>,
    /// The PE ordinal. ELF symbols have none.
    pub ordinal: Option<u32>,
    pub location: ExportLocation,
}

impl Export {
    /// A PE forwarder string for the same symbol in `module`: `module.Name`, or
    /// `module.#N` for an export by ordinal only.
    pub fn forwarder_in(&self, module: &str) -> Option<String> {
        match (&self.name, self.ordinal) {
            (Some(name), _) => Some(format!("{module}.{name}")),
            (None, Some(ordinal)) => Some(format!("{module}.#{ordinal}")),
            (None, None) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExportLocation {
    /// A virtual address in this image.
    Address(u64),
    /// A PE forwarder to a symbol in another DLL, such as `"NTDLL.RtlAllocateHeap"`.
    Forwarder(String),
}

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
    /// The exported symbols: a PE's export table, or an ELF's defined dynamic
    /// functions and objects.
    fn exports(&self) -> Result<Vec<Export>>;
    /// The machine as a PE machine type, or `None` if PE has no equivalent.
    fn machine(&self) -> Option<ImageFileMachine>;

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

    /// The `index`th pointer of an array at `base`, i.e. the pointer at
    /// `base + index * pointer_size()`. Saves spelling out the stride when
    /// walking a table of pointers.
    fn pointer_at(&self, base: u64, index: u64) -> Option<u64> {
        self.pointer(base + index * self.pointer_size())
    }

    /// `count` consecutive pointers starting at `vaddr`, or `None` if any is
    /// unmapped.
    fn pointers(&self, vaddr: u64, count: u64) -> Option<Vec<u64>> {
        (0..count).map(|i| self.pointer_at(vaddr, i)).collect()
    }

    /// The NUL-terminated string at `vaddr`, decoded as lossy UTF-8, or `None`
    /// if `vaddr` is unmapped. Reads to a NUL byte or the end of the mapping.
    fn c_str(&self, vaddr: u64) -> Option<String> {
        let mut bytes = Vec::new();
        let mut addr = vaddr;
        loop {
            match self.u8(addr)? {
                0 => break,
                byte => bytes.push(byte),
            }
            addr += 1;
        }
        Some(String::from_utf8_lossy(&bytes).into())
    }

    /// The pointer-sized slots of `segment` (a [`data_segments`](Self::data_segments)
    /// range), as the virtual addresses `start`, `start + pointer_size()`, ... that
    /// each still hold a full pointer. Useful for scanning a segment for a structure.
    fn pointer_slots(&self, segment: (u64, u64)) -> impl Iterator<Item = u64> {
        let (start, end) = segment;
        let stride = self.pointer_size();
        let count = end.saturating_sub(start) / stride;
        (0..count).map(move |i| start + i * stride)
    }

    /// Whether `vaddr` is a non-null, mapped address.
    fn is_mapped(&self, vaddr: u64) -> bool {
        vaddr != 0 && self.bytes(vaddr, 1).is_some()
    }
}

/// The bytes of the NUL-terminated string at the start of `data`, excluding the
/// NUL (all of `data` if there is none).
pub fn c_str_bytes(data: &[u8]) -> &[u8] {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    &data[..end]
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

    /// The underlying parsed ELF.
    pub fn elf(&self) -> &ElfFile<'a> {
        &self.elf
    }
}

impl LoadedImage for ElfImage<'_> {
    fn is_64(&self) -> bool {
        self.elf.is_64()
    }

    fn bytes(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        self.elf.data_at_vaddr(vaddr)?.get(..len)
    }

    fn c_str(&self, vaddr: u64) -> Option<String> {
        let data = self.elf.data_at_vaddr(vaddr)?;
        Some(String::from_utf8_lossy(c_str_bytes(data)).into())
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

    fn exports(&self) -> Result<Vec<Export>> {
        let mut exports: Vec<Export> = self
            .elf
            .symbols()?
            .into_iter()
            .filter(|s| {
                s.dynamic
                    && s.is_defined()
                    && !s.name.is_empty()
                    && matches!(
                        s.binding(),
                        Some(SymbolBinding::Global | SymbolBinding::Weak)
                    )
                    && matches!(s.symbol_type(), Some(SymbolType::Func | SymbolType::Object))
            })
            .map(|s| Export {
                name: Some(s.name.into()),
                ordinal: None,
                location: ExportLocation::Address(s.value),
            })
            .collect();
        exports.sort_by(|a, b| a.name.cmp(&b.name));
        exports.dedup_by(|a, b| a.name == b.name);
        Ok(exports)
    }

    fn machine(&self) -> Option<ImageFileMachine> {
        ImageFileMachine::from_elf(self.elf.header.machine)
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

    fn c_str(&self, vaddr: u64) -> Option<String> {
        let rva = u32::try_from(vaddr.checked_sub(self.image_base)?).ok()?;
        let data = self.pe.data_at_rva(rva)?;
        Some(String::from_utf8_lossy(c_str_bytes(data)).into())
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

    fn exports(&self) -> Result<Vec<Export>> {
        let Some(table) = self.pe.read_export_table()? else {
            return Ok(Vec::new());
        };
        let dir = self.pe.optional_header.data_directories.export_table;
        let base = table.export_directory_table.ordinal_base;

        let mut exports = Vec::new();
        for (i, address) in table.export_address_table.iter().enumerate() {
            if address.0 == 0 {
                continue;
            }
            let location = if address.is_forwarder(&dir) {
                let data = self.pe.data_at_rva(address.0).unwrap_or_default();
                ExportLocation::Forwarder(String::from_utf8_lossy(c_str_bytes(data)).into())
            } else {
                ExportLocation::Address(self.image_base + address.0 as u64)
            };
            let ordinal = Some(base + i as u32);
            let mut names = table
                .export_ordinal_table
                .iter()
                .zip(table.export_name_table.iter())
                .filter(|(o, _)| o.0 as usize == i)
                .map(|(_, name)| Some(name.clone()))
                .peekable();
            if names.peek().is_none() {
                exports.push(Export {
                    name: None,
                    ordinal,
                    location,
                });
                continue;
            }
            for name in names {
                exports.push(Export {
                    name,
                    ordinal,
                    location: location.clone(),
                });
            }
        }
        Ok(exports)
    }

    fn machine(&self) -> Option<ImageFileMachine> {
        Some(self.pe.coff_header.machine)
    }
}

/// A PE or ELF image, as detected by [`AnyImage::load`].
pub enum AnyImage<'a> {
    Elf(ElfImage<'a>),
    Pe(Box<PeImage>),
}

impl<'a> AnyImage<'a> {
    /// Parses a PE or ELF image, detecting which it is.
    pub fn load(data: &'a [u8]) -> Result<Self> {
        Ok(if ElfFile::is_elf(data) {
            Self::Elf(ElfImage::parse(data)?)
        } else {
            Self::Pe(Box::new(PeImage::parse(data)?))
        })
    }

    /// The ELF image, if this is one.
    pub fn as_elf(&self) -> Option<&ElfImage<'a>> {
        match self {
            Self::Elf(image) => Some(image),
            Self::Pe(_) => None,
        }
    }

    /// The PE image, if this is one.
    pub fn as_pe(&self) -> Option<&PeImage> {
        match self {
            Self::Pe(image) => Some(image),
            Self::Elf(_) => None,
        }
    }
}

impl LoadedImage for AnyImage<'_> {
    fn is_64(&self) -> bool {
        match self {
            Self::Elf(image) => image.is_64(),
            Self::Pe(image) => image.is_64(),
        }
    }

    fn bytes(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
        match self {
            Self::Elf(image) => image.bytes(vaddr, len),
            Self::Pe(image) => image.bytes(vaddr, len),
        }
    }

    fn pointer(&self, vaddr: u64) -> Option<u64> {
        match self {
            Self::Elf(image) => image.pointer(vaddr),
            Self::Pe(image) => image.pointer(vaddr),
        }
    }

    fn c_str(&self, vaddr: u64) -> Option<String> {
        match self {
            Self::Elf(image) => image.c_str(vaddr),
            Self::Pe(image) => image.c_str(vaddr),
        }
    }

    fn data_segments(&self) -> Vec<(u64, u64)> {
        match self {
            Self::Elf(image) => image.data_segments(),
            Self::Pe(image) => image.data_segments(),
        }
    }

    fn exports(&self) -> Result<Vec<Export>> {
        match self {
            Self::Elf(image) => image.exports(),
            Self::Pe(image) => image.exports(),
        }
    }

    fn machine(&self) -> Option<ImageFileMachine> {
        match self {
            Self::Elf(image) => image.machine(),
            Self::Pe(image) => image.machine(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A flat little-endian 64-bit address space starting at `base`.
    struct Flat {
        base: u64,
        data: Vec<u8>,
    }

    impl LoadedImage for Flat {
        fn is_64(&self) -> bool {
            true
        }
        fn bytes(&self, vaddr: u64, len: usize) -> Option<&[u8]> {
            let start = vaddr.checked_sub(self.base)? as usize;
            self.data.get(start..start + len)
        }
        fn pointer(&self, vaddr: u64) -> Option<u64> {
            self.bytes(vaddr, 8)
                .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
        }
        fn data_segments(&self) -> Vec<(u64, u64)> {
            Vec::from([(self.base, self.base + self.data.len() as u64)])
        }
        fn exports(&self) -> Result<Vec<Export>> {
            Ok(Vec::new())
        }
        fn machine(&self) -> Option<ImageFileMachine> {
            None
        }
    }

    #[test]
    fn pointer_helpers_walk_an_array() {
        let mut data = Vec::new();
        for value in [10u64, 20, 30] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        let image = Flat { base: 0x1000, data };

        assert_eq!(image.pointer_at(0x1000, 0), Some(10));
        assert_eq!(image.pointer_at(0x1000, 2), Some(30));
        assert_eq!(image.pointers(0x1000, 3), Some(Vec::from([10, 20, 30])));
        // One element past the end makes the whole read fail.
        assert_eq!(image.pointers(0x1000, 4), None);
    }

    #[test]
    fn pointer_slots_cover_whole_pointers_only() {
        let image = Flat {
            base: 0x1000,
            data: Vec::from([0u8; 20]),
        };
        // 20 bytes at 8 bytes each: slots at 0x1000 and 0x1008; the trailing 4
        // bytes cannot hold a pointer.
        let slots: Vec<u64> = image.pointer_slots((0x1000, 0x1014)).collect();
        assert_eq!(slots, [0x1000, 0x1008]);
    }

    #[test]
    fn c_str_reads_to_nul_via_default() {
        let mut data = Vec::from(*b"hello\0 rest");
        data.push(0);
        let image = Flat { base: 0x1000, data };
        assert_eq!(image.c_str(0x1000).as_deref(), Some("hello"));
        // Unmapped start reads nothing.
        assert_eq!(image.c_str(0x2000), None);
    }
}
