use super::{
    ElfClass, ElfData, ElfHeader, ElfMachine, ElfReader, ElfType, ProgramHeader, Section,
    SectionHeader, SectionType, SegmentType,
};
use crate::{
    error::{PewterError, Result},
    vec::Vec,
};

#[derive(Clone, PartialEq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
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
            .field(
                "sections",
                &self.sections.iter().map(|s| s.name).collect::<Vec<_>>(),
            )
            .finish()
    }
}

pub(crate) fn c_str(data: &[u8], offset: usize) -> &str {
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
                let offset = header.program_header_offset as usize
                    + i * header.program_header_entry_size as usize;
                ProgramHeader::read(&mut reader.at(offset))
            })
            .collect::<Result<Vec<_>>>()?;

        let section_headers = (0..header.section_header_count as usize)
            .map(|i| {
                let offset = header.section_header_offset as usize
                    + i * header.section_header_entry_size as usize;
                SectionHeader::read(&mut reader.at(offset))
            })
            .collect::<Result<Vec<_>>>()?;

        let section_data = |h: &SectionHeader| -> Result<&'a [u8]> {
            if h.section_type == SectionType::NoBits || h.section_type == SectionType::Null {
                return Ok(&[]);
            }
            let start = h.offset as usize;
            data.get(start..start + h.size as usize).ok_or_else(|| {
                PewterError::invalid_image_format("Section data is outside the file.")
            })
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

    pub(crate) fn reader(&self, position: usize) -> ElfReader<'a> {
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
}
