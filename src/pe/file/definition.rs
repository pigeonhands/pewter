use core::ops::{Deref, DerefMut};

use strum::IntoEnumIterator;

use crate::{
    containers::Table,
    error::{PewterError, Result},
    io::{WriteData, Writer},
    pe::{
        coff::CoffFileHeader,
        dos::ImageDosHeader,
        optional_header::{
            self,
            data_directories::{ImageDataDirectory, SectionName},
        },
        sections::{SectionFlags, SectionTableRow, Sections},
    },
    string::String,
    vec::Vec,
    PEFile,
};

#[inline]
pub fn align_up(value: usize, alignment: usize) -> usize {
    if alignment <= 1 {
        return value;
    }
    (value + alignment - 1) & !(alignment - 1)
}

/// An owned, editable PE image that can be written back to bytes.
#[derive(Debug, Clone)]
pub struct PEImageDef {
    pub dos_header: ImageDosHeader,
    /// Bytes between the DOS header and the PE signature.
    pub dos_stub: Vec<u8>,
    pub coff_header: CoffFileHeader,
    pub optional_header: optional_header::OptionalHeader,
    pub sections: SectionDefinitions,
    /// Data after the last section (e.g. the certificate table).
    pub overlay: Vec<u8>,
    overlay_offset: usize,
    first_raw_offset: usize,
}

impl PEImageDef {
    pub fn parse(data: &[u8]) -> Result<Self> {
        PEFile::parse_minimal(data).map(Self::from_pe_file)
    }

    pub fn from_pe_file(pe_file: PEFile) -> Self {
        let file_bytes = pe_file.file_bytes();
        let PEFile {
            dos_header,
            coff_header,
            optional_header,
            sections,
            ..
        } = pe_file;

        let stub_end = (dos_header.e_lfanew as usize).min(file_bytes.len());
        let dos_stub = file_bytes
            .get(ImageDosHeader::SIZE..stub_end)
            .map(Vec::from)
            .unwrap_or_default();

        let Sections(Table(section_rows)) = sections;

        let first_raw_offset = section_rows
            .iter()
            .map(|s| s.row.pointer_to_raw_data as usize)
            .filter(|p| *p != 0)
            .min()
            .unwrap_or(0);

        let overlay_offset = section_rows
            .iter()
            .map(|s| s.row.pointer_to_raw_data as usize + s.row.size_of_raw_data as usize)
            .max()
            .unwrap_or(file_bytes.len())
            .min(file_bytes.len());

        let mut sections: Vec<SectionHeap> = section_rows
            .into_iter()
            .map(|s| SectionHeap {
                data: match s.row.virtual_size as usize {
                    0 => Vec::from(s.data),
                    vsize => Vec::from(&s.data[..vsize.min(s.data.len())]),
                },
                name: s.row.name_str().into(),
                characteristics: s.row.characteristics,
                virtual_address: s.row.virtual_address,
                virtual_size: s.row.virtual_size,
            })
            .collect();
        sections.sort_by_key(|s| s.virtual_address);

        Self {
            dos_header,
            dos_stub,
            coff_header,
            optional_header: optional_header.unwrap_or_default(),
            sections: SectionDefinitions(sections),
            overlay: Vec::from(&file_bytes[overlay_offset..]),
            overlay_offset,
            first_raw_offset,
        }
    }

    pub fn file_alignment(&self) -> usize {
        self.optional_header
            .windows_specific_fields
            .file_alignment() as usize
    }

    pub fn section_alignment(&self) -> usize {
        self.optional_header
            .windows_specific_fields
            .section_alignment() as usize
    }

    /// Adds a new empty section after the last one.
    pub fn new_section(
        &mut self,
        name: impl Into<String>,
        characteristics: SectionFlags,
    ) -> &mut SectionHeap {
        let section = SectionHeap {
            name: name.into(),
            virtual_address: self.sections.next_virtual_address(self.section_alignment()) as u32,
            data: Vec::new(),
            characteristics,
            virtual_size: 0,
        };
        self.sections.push(section);
        self.sections.last_mut().unwrap()
    }

    pub fn read_at_rva(&self, rva: u32, len: usize) -> Option<&[u8]> {
        let section = self.sections.find_rva(rva as usize)?;
        let start = (rva - section.virtual_address) as usize;
        section.data.get(start..start + len)
    }

    pub fn write_at_rva(&mut self, rva: u32, data: &[u8]) -> Result<()> {
        let section = self
            .sections
            .find_rva_mut(rva as usize)
            .ok_or_else(|| PewterError::invalid_image_format("RVA is not inside a section"))?;
        let start = (rva - section.virtual_address) as usize;
        let dest = section
            .data
            .get_mut(start..start + data.len())
            .ok_or_else(|| PewterError::not_enough_space(data.len()))?;
        dest.copy_from_slice(data);
        Ok(())
    }

    /// Removes the certificate table. Any edit to the image invalidates it anyway.
    pub fn strip_certificate(&mut self) {
        let cert = self.optional_header.data_directories.certificate_table;
        if !cert.is_null() {
            let start = (cert.virtual_address as usize).saturating_sub(self.overlay_offset);
            if start <= self.overlay.len() {
                self.overlay.truncate(start);
            }
            self.optional_header.data_directories.certificate_table = ImageDataDirectory::default();
        }
    }

    fn headers_size(&self) -> usize {
        self.dos_header.e_lfanew as usize
            + PEFile::SIGNATURE.len()
            + CoffFileHeader::SIZE
            + self.optional_header.size()
            + SectionTableRow::SIZE * self.sections.len()
    }

    pub fn fix_headers(&mut self) -> Result<()> {
        let file_alignment = self.file_alignment();
        let section_alignment = self.section_alignment();

        let last_used_dir = SectionName::iter()
            .filter(|dir| {
                !self
                    .optional_header
                    .data_directories
                    .get_directory(*dir)
                    .is_null()
            })
            .map(|dir| dir as u32 + 1)
            .max()
            .unwrap_or(0);
        let wsf = &mut self.optional_header.windows_specific_fields;
        wsf.set_number_of_rva_and_sizes(wsf.number_of_rva_and_sizes().max(last_used_dir));

        self.coff_header.number_of_sections = self.sections.len() as u16;
        self.coff_header.size_of_optional_header = self.optional_header.size() as u16;
        self.make_room_for_headers();

        let size_of_headers = align_up(self.headers_size(), file_alignment);
        if let Some(first) = self.sections.first() {
            if size_of_headers > first.virtual_address as usize {
                return Err(PewterError::invalid_image_format(
                    "Section table does not fit before the first section",
                ));
            }
        }

        let size_of_image = self
            .sections
            .last()
            .map(|s| s.virtual_address as usize + s.virtual_size())
            .unwrap_or(size_of_headers);

        let (mut code, mut init, mut uninit) = (0, 0, 0);
        for s in self.sections.iter() {
            let raw = align_up(s.data.len(), file_alignment) as u32;
            if s.characteristics.contains(SectionFlags::CNT_CODE) {
                code += raw;
            }
            if s.characteristics
                .contains(SectionFlags::CNT_INITIALIZED_DATA)
            {
                init += raw;
            }
            if s.characteristics
                .contains(SectionFlags::CNT_UNINITIALIZED_DATA)
            {
                uninit += align_up(s.virtual_size(), file_alignment) as u32;
            }
        }
        let std = &mut self.optional_header.standard_fields;
        std.size_of_code = code;
        std.size_of_initilized_data = init;
        std.size_of_unitilized_data = uninit;

        let wsf = &mut self.optional_header.windows_specific_fields;
        wsf.set_size_of_headers(size_of_headers as u32);
        wsf.set_size_of_image(align_up(size_of_image, section_alignment) as u32);

        if !self
            .optional_header
            .data_directories
            .certificate_table
            .is_null()
        {
            let new_overlay = self.raw_data_end();
            let cert = &mut self.optional_header.data_directories.certificate_table;
            cert.virtual_address =
                (cert.virtual_address as usize - self.overlay_offset + new_overlay) as u32;
            self.overlay_offset = new_overlay;
        }
        Ok(())
    }

    /// Images whose sections are mapped straight from the file (section alignment
    /// below the page size, as produced by crossgen) need file offsets congruent
    /// to their RVA modulo 64K.
    fn is_flat_layout(&self) -> bool {
        self.section_alignment() < 0x1000
    }

    /// File offset of each section's raw data.
    fn section_offsets(&self) -> Vec<usize> {
        let file_alignment = self.file_alignment();
        let mut cursor = align_up(self.headers_size(), file_alignment);
        self.sections
            .iter()
            .map(|s| {
                let mut offset = cursor;
                if self.is_flat_layout() {
                    const GRANULARITY: usize = 0x10000;
                    let target = s.virtual_address as usize % GRANULARITY;
                    offset = offset - offset % GRANULARITY + target;
                    if offset < cursor {
                        offset += GRANULARITY;
                    }
                }
                cursor = offset + align_up(s.data.len(), file_alignment);
                offset
            })
            .collect()
    }

    fn raw_data_end(&self) -> usize {
        let file_alignment = self.file_alignment();
        self.section_offsets()
            .iter()
            .zip(self.sections.iter())
            .map(|(offset, s)| offset + align_up(s.data.len(), file_alignment))
            .max()
            .unwrap_or_else(|| align_up(self.headers_size(), file_alignment))
    }

    /// Drops the DOS stub if the section table would otherwise push the first
    /// section's data to a later file offset.
    fn make_room_for_headers(&mut self) {
        let grows = align_up(self.headers_size(), self.file_alignment()) > self.first_raw_offset;
        if grows
            && self.first_raw_offset != 0
            && self.dos_header.e_lfanew as usize > ImageDosHeader::SIZE
        {
            self.dos_stub.clear();
            self.dos_header.e_lfanew = ImageDosHeader::SIZE as u32;
        }
    }

    pub fn write_file(&mut self) -> Result<Vec<u8>> {
        self.fix_headers()?;
        let mut buffer = self.write_no_fix()?;
        if self.optional_header.windows_specific_fields.check_sum() != 0 {
            let offset = self.checksum_offset();
            let checksum = pe_checksum(&buffer, offset);
            buffer[offset..offset + 4].copy_from_slice(&checksum.to_le_bytes());
            self.optional_header
                .windows_specific_fields
                .set_check_sum(checksum);
        }
        Ok(buffer)
    }

    fn checksum_offset(&self) -> usize {
        self.dos_header.e_lfanew as usize + PEFile::SIGNATURE.len() + CoffFileHeader::SIZE + 64
    }

    pub fn write_no_fix(&self) -> Result<Vec<u8>> {
        let file_alignment = self.file_alignment();
        let mut buffer = Vec::with_capacity(self.raw_data_end() + self.overlay.len());

        self.dos_header.write_to(&mut buffer)?;
        buffer.write_slice(&self.dos_stub)?;
        buffer.resize(self.dos_header.e_lfanew as usize, 0);

        PEFile::SIGNATURE.write_to(&mut buffer)?;
        self.coff_header.write_to(&mut buffer)?;
        self.optional_header.write_to(&mut buffer)?;

        let offsets = self.section_offsets();
        let rows: Vec<SectionTableRow> = self
            .sections
            .iter()
            .zip(offsets)
            .map(|(sec, data_offset)| {
                let mut name = [0u8; 8];
                for (b, n) in sec.name.bytes().take(8).zip(name.iter_mut()) {
                    *n = b;
                }
                let size_of_raw_data = align_up(sec.data.len(), file_alignment);

                SectionTableRow {
                    name,
                    virtual_size: sec.virtual_size.max(sec.data.len() as u32),
                    virtual_address: sec.virtual_address,
                    characteristics: sec.characteristics,
                    pointer_to_raw_data: if size_of_raw_data == 0 {
                        0
                    } else {
                        data_offset as u32
                    },
                    size_of_raw_data: size_of_raw_data as u32,
                    ..Default::default()
                }
            })
            .collect();

        for row in &rows {
            row.write_to(&mut buffer)?;
        }

        for (sec, row) in self.sections.iter().zip(rows.iter()) {
            if row.size_of_raw_data == 0 {
                continue;
            }
            buffer.resize(row.pointer_to_raw_data as usize, 0);
            buffer.write_slice(&sec.data)?;
        }
        buffer.resize(align_up(buffer.len(), file_alignment), 0);
        buffer.write_slice(&self.overlay)?;

        Ok(buffer)
    }
}

/// Standard PE checksum, skipping the 4 byte checksum field at `checksum_offset`.
pub fn pe_checksum(data: &[u8], checksum_offset: usize) -> u32 {
    let mut sum: u64 = 0;
    for (i, chunk) in data.chunks(2).enumerate() {
        let offset = i * 2;
        if offset == checksum_offset || offset == checksum_offset + 2 {
            continue;
        }
        let word = match chunk {
            [a, b] => u16::from_le_bytes([*a, *b]),
            [a] => *a as u16,
            _ => 0,
        };
        sum += word as u64;
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);
    (sum as u32).wrapping_add(data.len() as u32)
}

/// Sections ordered by virtual address.
#[derive(Debug, Clone, Default)]
pub struct SectionDefinitions(pub Vec<SectionHeap>);

impl SectionDefinitions {
    pub fn by_name(&self, name: &str) -> Option<&SectionHeap> {
        self.0.iter().find(|s| s.name == name)
    }

    pub fn by_name_mut(&mut self, name: &str) -> Option<&mut SectionHeap> {
        self.0.iter_mut().find(|s| s.name == name)
    }

    pub fn find_rva(&self, virtual_address: usize) -> Option<&SectionHeap> {
        self.0.iter().find(|s| s.contains_rva(virtual_address))
    }

    pub fn find_rva_mut(&mut self, virtual_address: usize) -> Option<&mut SectionHeap> {
        self.0.iter_mut().find(|s| s.contains_rva(virtual_address))
    }

    pub fn has_overlapping_sections(&self) -> bool {
        self.0.windows(2).any(|w| {
            w[0].virtual_address as usize + w[0].virtual_size() > w[1].virtual_address as usize
        })
    }

    /// Adds a section, assigning [`SectionDefinitions::next_virtual_address`] if
    /// `virtual_address` is zero. Returns the virtual address.
    pub fn add_section(&mut self, mut section: SectionHeap, section_alignment: usize) -> usize {
        if section.virtual_address == 0 {
            section.virtual_address = self.next_virtual_address(section_alignment) as u32;
        }
        let vaddr = section.virtual_address;
        self.0.push(section);
        self.0.sort_by_key(|s| s.virtual_address);
        vaddr as usize
    }

    pub fn next_virtual_address(&self, section_alignment: usize) -> usize {
        let end = self
            .0
            .iter()
            .map(|s| s.virtual_address as usize + s.virtual_size())
            .max()
            .unwrap_or(0);
        align_up(end, section_alignment)
    }
}

impl Deref for SectionDefinitions {
    type Target = Vec<SectionHeap>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SectionDefinitions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug, Clone, Default)]
pub struct SectionHeap {
    /// Names longer than 8 bytes are truncated.
    pub name: String,
    pub virtual_address: u32,
    /// Leave as zero to use the data length.
    pub virtual_size: u32,
    pub characteristics: SectionFlags,
    pub data: Vec<u8>,
}

impl SectionHeap {
    /// Appends data, returning its virtual address.
    pub fn add_data(&mut self, data: &[u8]) -> usize {
        let addr = self.virtual_address as usize + self.data.len();
        self.data.extend_from_slice(data);
        addr
    }

    /// Pads the data so the next [`SectionHeap::add_data`] is aligned.
    pub fn align_data(&mut self, alignment: usize) {
        self.data.resize(align_up(self.data.len(), alignment), 0);
    }

    pub fn virtual_size(&self) -> usize {
        (self.virtual_size as usize).max(self.data.len())
    }

    pub fn contains_rva(&self, virtual_address: usize) -> bool {
        virtual_address >= self.virtual_address as usize
            && virtual_address < self.virtual_address as usize + self.virtual_size()
    }
}
