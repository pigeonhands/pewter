//! Reading ELF files (32 and 64 bit, either byte order).

mod types;

pub use types::*;

use crate::{
    error::{PewterError, Result},
    vec::Vec,
};

/// Reads fields with the file's byte order and word size.
#[derive(Clone)]
pub(crate) struct ElfReader<'a> {
    data: &'a [u8],
    position: usize,
    little_endian: bool,
    is_64: bool,
}

impl<'a> ElfReader<'a> {
    fn at(&self, position: usize) -> Self {
        Self {
            position,
            ..self.clone()
        }
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self
            .data
            .get(self.position..self.position + N)
            .ok_or_else(|| PewterError::not_enough_data(N))?;
        self.position += N;
        Ok(slice.try_into().unwrap())
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.bytes::<1>().map(|b| b[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.bytes()?;
        Ok(if self.little_endian { u16::from_le_bytes(b) } else { u16::from_be_bytes(b) })
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.bytes()?;
        Ok(if self.little_endian { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) })
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.bytes()?;
        Ok(if self.little_endian { u64::from_le_bytes(b) } else { u64::from_be_bytes(b) })
    }

    /// An address or offset sized for the file's class.
    pub fn word(&mut self) -> Result<u64> {
        if self.is_64 {
            self.u64()
        } else {
            self.u32().map(u64::from)
        }
    }
}

/// A section with its name and contents.
#[derive(Debug, Clone, PartialEq)]
pub struct Section<'a> {
    pub header: SectionHeader,
    pub name: &'a str,
    /// Empty for `SHT_NOBITS` sections such as `.bss`.
    pub data: &'a [u8],
}

#[derive(Clone, PartialEq)]
pub struct ElfFile<'a> {
    pub header: ElfHeader,
    pub program_headers: Vec<ProgramHeader>,
    pub sections: Vec<Section<'a>>,
    file_bytes: &'a [u8],
}

impl core::fmt::Debug for ElfFile<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ElfFile")
            .field("header", &self.header)
            .field("program_headers", &self.program_headers)
            .field("sections", &self.sections.iter().map(|s| s.name).collect::<Vec<_>>())
            .finish()
    }
}

fn c_str(data: &[u8], offset: usize) -> &str {
    let data = data.get(offset..).unwrap_or(&[]);
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    core::str::from_utf8(&data[..end]).unwrap_or("")
}

impl<'a> ElfFile<'a> {
    pub const MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

    pub fn is_elf(data: &[u8]) -> bool {
        data.starts_with(&Self::MAGIC)
    }

    pub fn parse(data: &'a [u8]) -> Result<Self> {
        if !Self::is_elf(data) || data.len() < 16 {
            return Err(PewterError::invalid_image_format("Bad ELF magic."));
        }
        let class = ElfClass::from_repr(data[4])
            .ok_or_else(|| PewterError::invalid_image_format("Unknown ELF class."))?;
        let byte_order = ElfData::from_repr(data[5])
            .ok_or_else(|| PewterError::invalid_image_format("Unknown ELF byte order."))?;
        let mut reader = ElfReader {
            data,
            position: 16,
            little_endian: byte_order == ElfData::Little,
            is_64: class == ElfClass::Elf64,
        };

        let header = ElfHeader {
            class,
            byte_order,
            os_abi: data[7],
            abi_version: data[8],
            file_type: ElfType::from_u16(reader.u16()?),
            machine: ElfMachine::from_u16(reader.u16()?),
            version: reader.u32()?,
            entry: reader.word()?,
            program_header_offset: reader.word()?,
            section_header_offset: reader.word()?,
            flags: reader.u32()?,
            header_size: reader.u16()?,
            program_header_entry_size: reader.u16()?,
            program_header_count: reader.u16()?,
            section_header_entry_size: reader.u16()?,
            section_header_count: reader.u16()?,
            section_name_index: reader.u16()?,
        };

        let program_headers = (0..header.program_header_count as usize)
            .map(|i| {
                let offset = header.program_header_offset as usize + i * header.program_header_entry_size as usize;
                ProgramHeader::read(&mut reader.at(offset))
            })
            .collect::<Result<Vec<_>>>()?;

        let section_headers = (0..header.section_header_count as usize)
            .map(|i| {
                let offset = header.section_header_offset as usize + i * header.section_header_entry_size as usize;
                SectionHeader::read(&mut reader.at(offset))
            })
            .collect::<Result<Vec<_>>>()?;

        let section_data = |h: &SectionHeader| -> Result<&'a [u8]> {
            if h.section_type == SectionType::NoBits || h.section_type == SectionType::Null {
                return Ok(&[]);
            }
            let start = h.offset as usize;
            data.get(start..start + h.size as usize)
                .ok_or_else(|| PewterError::invalid_image_format("Section data is outside the file."))
        };
        let names = match section_headers.get(header.section_name_index as usize) {
            Some(h) => section_data(h)?,
            None => &[],
        };
        let sections = section_headers
            .into_iter()
            .map(|h| {
                Ok(Section {
                    name: c_str(names, h.name as usize),
                    data: section_data(&h)?,
                    header: h,
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            header,
            program_headers,
            sections,
            file_bytes: data,
        })
    }

    fn reader(&self, position: usize) -> ElfReader<'a> {
        ElfReader {
            data: self.file_bytes,
            position,
            little_endian: self.header.byte_order == ElfData::Little,
            is_64: self.header.class == ElfClass::Elf64,
        }
    }

    pub fn file_bytes(&self) -> &'a [u8] {
        self.file_bytes
    }

    pub fn is_64(&self) -> bool {
        self.header.class == ElfClass::Elf64
    }

    pub fn section_by_name(&self, name: &str) -> Option<&Section<'a>> {
        self.sections.iter().find(|s| s.name == name)
    }

    /// The file offset of virtual address `vaddr`, through the `PT_LOAD` segments.
    pub fn vaddr_to_offset(&self, vaddr: u64) -> Option<usize> {
        self.program_headers
            .iter()
            .filter(|p| p.segment_type == SegmentType::Load)
            .find(|p| vaddr >= p.vaddr && vaddr < p.vaddr + p.file_size)
            .map(|p| (vaddr - p.vaddr + p.offset) as usize)
    }

    /// The file offset to virtual address, the inverse of [`ElfFile::vaddr_to_offset`].
    pub fn offset_to_vaddr(&self, offset: usize) -> Option<u64> {
        let offset = offset as u64;
        self.program_headers
            .iter()
            .filter(|p| p.segment_type == SegmentType::Load)
            .find(|p| offset >= p.offset && offset < p.offset + p.file_size)
            .map(|p| offset - p.offset + p.vaddr)
    }

    /// The file data from `vaddr` to the end of its segment.
    pub fn data_at_vaddr(&self, vaddr: u64) -> Option<&'a [u8]> {
        let segment = self
            .program_headers
            .iter()
            .filter(|p| p.segment_type == SegmentType::Load)
            .find(|p| vaddr >= p.vaddr && vaddr < p.vaddr + p.file_size)?;
        let start = (vaddr - segment.vaddr + segment.offset) as usize;
        let end = (segment.offset + segment.file_size) as usize;
        self.file_bytes.get(start..end)
    }

    /// Symbols from `.symtab` and `.dynsym`.
    pub fn symbols(&self) -> Result<Vec<Symbol<'a>>> {
        let mut symbols = Vec::new();
        for section in &self.sections {
            if !matches!(section.header.section_type, SectionType::SymTab | SectionType::DynSym) {
                continue;
            }
            let strings = self
                .sections
                .get(section.header.link as usize)
                .map(|s| s.data)
                .unwrap_or(&[]);
            let entry_size = if self.is_64() { 24 } else { 16 };
            let count = section.data.len() / entry_size;
            for i in 0..count {
                let mut reader = self.reader(section.header.offset as usize + i * entry_size);
                let mut symbol = Symbol::read(&mut reader, self.is_64())?;
                symbol.name = c_str(strings, symbol.name_offset as usize);
                symbol.dynamic = section.header.section_type == SectionType::DynSym;
                symbols.push(symbol);
            }
        }
        Ok(symbols)
    }

    pub fn find_symbol(&self, name: &str) -> Result<Option<Symbol<'a>>> {
        Ok(self.symbols()?.into_iter().find(|s| s.name == name))
    }

    /// Relocations from every `SHT_REL` and `SHT_RELA` section.
    pub fn relocations(&self) -> Result<Vec<Relocation>> {
        let mut relocations = Vec::new();
        for section in &self.sections {
            let has_addend = match section.header.section_type {
                SectionType::Rela => true,
                SectionType::Rel => false,
                _ => continue,
            };
            let entry_size = match (self.is_64(), has_addend) {
                (true, true) => 24,
                (true, false) => 16,
                (false, true) => 12,
                (false, false) => 8,
            };
            for i in 0..section.data.len() / entry_size {
                let mut reader = self.reader(section.header.offset as usize + i * entry_size);
                relocations.push(Relocation::read(&mut reader, self.is_64(), has_addend)?);
            }
        }
        Ok(relocations)
    }

    /// Resolves the value each relocated pointer will hold once loaded at its
    /// preferred address (`R_*_RELATIVE` and absolute symbol relocations).
    pub fn relocated_pointers(&self) -> Result<RelocatedPointers> {
        let relative = self.header.machine.relative_relocation_type();
        let absolute = self.header.machine.absolute_relocation_types();
        let symbols = self.symbols()?;
        let dynamic: Vec<&Symbol> = symbols.iter().filter(|s| s.dynamic).collect();
        let mut pointers = Vec::new();
        for r in self.relocations()? {
            let implicit_addend = || -> u64 {
                self.vaddr_to_offset(r.offset)
                    .and_then(|o| self.reader(o).word().ok())
                    .unwrap_or(0)
            };
            let addend = r.addend.map(|a| a as u64).unwrap_or_else(implicit_addend);
            let value = if Some(r.relocation_type) == relative {
                addend
            } else if absolute.contains(&r.relocation_type) {
                match dynamic.get(r.symbol as usize) {
                    Some(s) if s.value != 0 => s.value.wrapping_add(addend),
                    _ => continue,
                }
            } else {
                continue;
            };
            pointers.push((r.offset, value));
        }
        pointers.sort_unstable_by_key(|(offset, _)| *offset);
        Ok(RelocatedPointers(pointers))
    }

    /// Reads the pointer at `vaddr` as it will be after relocation.
    pub fn read_pointer(&self, vaddr: u64, relocations: &RelocatedPointers) -> Option<u64> {
        if let Some(value) = relocations.get(vaddr) {
            return Some(value);
        }
        self.reader(self.vaddr_to_offset(vaddr)?).word().ok()
    }
}

/// Pointer values from [`ElfFile::relocated_pointers`], sorted by address.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelocatedPointers(pub Vec<(u64, u64)>);

impl RelocatedPointers {
    pub fn get(&self, vaddr: u64) -> Option<u64> {
        self.0
            .binary_search_by_key(&vaddr, |(offset, _)| *offset)
            .ok()
            .map(|i| self.0[i].1)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
