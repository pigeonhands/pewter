use crate::{
    containers::Table,
    error::Result,
    io::{WriteData, Writer},
    pe::{
        coff::{CoffFileHeader, ImageFileCharacteristics, ImageFileMachine},
        dos::ImageDosHeader,
        optional_header::{self, data_directories::SectionName},
        sections::{SectionFlags, SectionTableRow, Sections},
    },
    string::String,
    vec::Vec,
    PEFile,
};

pub struct PEImageDef {
    pub dos_header: ImageDosHeader,
    pub file_characteristics: ImageFileCharacteristics,
    pub optional_header: optional_header::OptionalHeader,
    pub sections: SectionDefinitions,
}

impl PEImageDef {
    pub fn from_pe_file(pe_file: PEFile) -> Self {
        let PEFile {
            dos_header,
            coff_header,
            optional_header,
            sections,
            ..
        } = pe_file;

        let sections = {
            let Sections(Table(section_rows)) = sections;

            let mapped_sections = section_rows.into_iter().map(|s| SectionHeap {
                data: Vec::from(s.data),
                name: s.row.name_str().into(),
                characteristics: s.row.characteristics,
                virtual_address: s.row.virtual_address,
                virtual_size: s.row.virtual_size,
            });

            let mut sections = SectionDefinitions::default();
            for s in mapped_sections {
                match s.name.as_str() {
                    ".text" => sections.text = Some(s),
                    ".data" => sections.data = Some(s),
                    ".rdata" => sections.rdata = Some(s),
                    ".reloc" => sections.reloc = Some(s),
                    ".pdata" => sections.pdata = Some(s),
                    _ => sections.other.push(s),
                }
            }
            sections
        };

        Self {
            dos_header,
            optional_header: optional_header.unwrap_or_default(),
            sections,
            file_characteristics: coff_header.characteristics,
        }
    }

    pub fn new_section(
        &mut self,
        name: impl Into<String>,
        characteristics: SectionFlags,
    ) -> &mut SectionHeap {
        let section = SectionHeap {
            name: name.into(),
            virtual_address: self.sections.next_virtual_address() as u32,
            data: Vec::new(),
            characteristics,
            virtual_size: 0,
        };
        self.sections.other.push(section);
        self.sections.other.last_mut().unwrap()
    }

    pub fn fix_headers(&mut self) {
        let file_alignment = self.optional_header.windows_specific_fields.file_alignment() as usize;
        let allign_section = |addr: usize| {
            (addr + file_alignment) & (!(file_alignment - 1))
        };

        self.optional_header.windows_specific_fields.set_size_of_headers(
            allign_section(self.dos_header.e_lfanew as usize
            + PEFile::SIGNATURE.len()
            + CoffFileHeader::SIZE
            + self.optional_header.size()
            +  (SectionTableRow::SIZE * self.sections.count())) as u32
        );

        self.optional_header.windows_specific_fields.set_size_of_image(self.output_size() as u32);

        let number_of_data_directories =
            SectionName::ALL
                .iter()
                .enumerate()
                .fold(0, |acc, (i, dir)| {
                    if self
                        .optional_header
                        .data_directories
                        .get_directory(*dir)
                        .is_null()
                    {
                        (i+1) as u32
                    } else {
                        acc
                    }
                });

        self.optional_header
            .windows_specific_fields
            .set_number_of_rva_and_sizes(
                self.optional_header
                    .windows_specific_fields
                    .number_of_rva_and_sizes()
                    .max(number_of_data_directories),
            );
/*
        if let Some(init_data) = &self.sections.data {
            self.optional_header.standard_fields.size_of_initilized_data = self
                .optional_header
                .standard_fields
                .size_of_initilized_data
                .max(init_data.data.len() as u32);
        }

        if let Some(code) = &self.sections.text {
            self.optional_header.standard_fields.size_of_code = self
                .optional_header
                .standard_fields
                .size_of_code
                .max(code.data.len() as u32);
        } */
    }

    pub fn output_size(&self) -> usize {
        //self.sections.iter_sections().fold(0, |acc, sec| {
        //   let size = sec.
        //   acc
        //});
        let file_alignment = self.optional_header.windows_specific_fields.section_alignment() as usize;
        let allign_section = |addr: usize| {
            (addr + file_alignment) & (!(file_alignment - 1))
        };

            self.optional_header.windows_specific_fields.size_of_headers() as usize
            + self
                .sections
                .iter_sections()
                .map(|s| {
                    if (s.data.len() & (file_alignment-1)) != 0 {
                        allign_section( s.data.len())
                    }else {
                        s.data.len()
                    }
                })
                .sum::<usize>()
    }

    pub fn write_file(&mut self) -> Result<crate::vec::Vec<u8>> {
        self.fix_headers();
        self.write_no_fix()
    }

    pub fn write_no_fix(&self) -> Result<Vec<u8>> {
        let mut buffer = crate::vec::Vec::with_capacity(self.output_size());
        //ImageDosHeader {
        //e_magic: ImageDosHeader::MAGIC_CONSTANT,
//
        //    e_lfanew: 0xf0,
        //    ..Default::default()
        //}
        //.write_to(&mut buffer)?;
        self.dos_header.write_to(&mut buffer)?;

        // TODO: Write dos stub
        while buffer.len() < self.dos_header.e_lfanew as usize {
            buffer.write(0u8)?;
        }
       // buffer.write([0u8; self.dos_header.e_lfanew - ImageDosHeader::SIZE])?;
        PEFile::SIGNATURE.write_to(&mut buffer)?;

        CoffFileHeader {
            machine: ImageFileMachine::Amd64,
            characteristics: self.file_characteristics,
            size_of_optional_header: self.optional_header.size() as u16,
            number_of_sections: self.sections.count() as u16,
            ..Default::default()
        }
        .write_to(&mut buffer)?;

        self.optional_header.write_to(&mut buffer)?;

        let file_alignment = self.optional_header.windows_specific_fields.file_alignment() as usize;
        let allign_section = |addr: usize| {
            (addr + file_alignment) & (!(file_alignment - 1))
        };

        let mut data_offset = allign_section(buffer.len() + (SectionTableRow::SIZE * self.sections.count()));

        let sections: Vec<_> = self
            .sections
            .iter_sections()
            .map(|sec| {
                (&sec.data, {
                    let name = {
                        let mut name_buffer = [0u8; 8];
                        for (c, buff) in sec.name.chars().take(8).zip(name_buffer.iter_mut()) {
                            *buff = c as u8;
                        }
                        name_buffer
                    };
                    let pointer_to_raw_data = data_offset as u32;
                    data_offset  += sec.data.len();
                    
                    if (data_offset & (file_alignment-1)) != 0 {
                        data_offset =  allign_section( data_offset);
                    }

                    SectionTableRow {
                        name,
                        virtual_size: sec.virtual_size.max(sec.data.len() as u32),
                        virtual_address: sec.virtual_address,
                        characteristics: sec.characteristics,
                        pointer_to_raw_data,
                        size_of_raw_data: sec.data.len() as u32,
                        ..Default::default()
                    }
                })
            })
            .collect();

        for (_, sec) in &sections {
            sec.write_to(&mut buffer)?;
        }

        for (sec_data, sec) in sections {
            while buffer.len() < sec.pointer_to_raw_data as usize {
                buffer.write(0u8)?;
            }
            buffer.write_slice(sec_data)?;
        }

        Ok(buffer)
    }
}

/// If a section has a `virtual_address` of 0, it
/// is not included.
///
/// The named fields are well known section names just for convenience.
/// They are treated exactly the same as values in `other`.
#[derive(Debug, Clone, Default)]
pub struct SectionDefinitions {
    /// .text section
    ///
    /// Flash memory. Mainly constant variables
    /// and compiled code
    pub text: Option<SectionHeap>,
    /// .data section
    ///
    /// Uninitilized data.
    /// Inital values of dynamic variables.
    pub data: Option<SectionHeap>,
    /// Read-only initialized data
    pub rdata: Option<SectionHeap>,
    /// exception table
    pub pdata: Option<SectionHeap>,
    /// Relocation table.
    /// this will be written to if virtual addresses need to be moved.
    pub reloc: Option<SectionHeap>,
    /// Other sections
    pub other: Vec<SectionHeap>,
}

impl SectionDefinitions {
    pub const VIRTUAL_ADDRESS_ALIGNMENT: usize = 0x1000;

    pub fn allign_to_next_section(addr: usize) -> usize {
        (addr + Self::VIRTUAL_ADDRESS_ALIGNMENT) & (!(Self::VIRTUAL_ADDRESS_ALIGNMENT - 1))
    }

    /// Iters all sections that have a non-zero `virtual_address`.
    pub fn iter_sections(&self) -> impl Iterator<Item = &SectionHeap> {
        [&self.text, &self.rdata, &self.data,&self.pdata, &self.reloc]
            .into_iter()
            .flat_map(|f| f.as_ref())
            .chain(self.other.iter())
            .filter(|heap| heap.virtual_address != 0)
    }

    pub fn count(&self) -> usize {
        self.iter_sections().count()
    }

    /// Finds the section that contains the given virtual address
    #[inline(always)]
    pub fn find_rva(&self, virtual_address: usize) -> Option<&SectionHeap> {
        if virtual_address == 0 {
            return None;
        }
        self.iter_sections().find(|heap| {
            virtual_address >= (heap.virtual_address as usize)
                && virtual_address < (heap.virtual_address as usize + heap.data.len())
        })
    }

    #[inline]
    pub fn has_overlapping_sections(&self) -> bool {
        for section in self.iter_sections() {
            if let Some(overlapping_section) = self.find_rva(section.virtual_address as usize) {
                if !core::ptr::eq(section, overlapping_section) {
                    return true;
                }
            }
        }
        false
    }

    /// Add section and add base virtual address of section.
    /// If `virtual_address` is zero, [`SectionDefinitions::next_virtual_address`] will be used.
    pub fn add_section(&mut self, mut section: SectionHeap) -> usize {
        if section.virtual_address == 0 {
            section.virtual_address = self.next_virtual_address() as u32;
        }
        let vaddr = section.virtual_address;
        self.other.push(section);
        vaddr as usize
    }

    /// Finds the next availible virtual address
    pub fn next_virtual_address(&self) -> usize {
        let v_addr = self.iter_sections().fold(0, |accumulator, heap| {
            let heap_end_addr = heap.virtual_address as usize + heap.data.len();
            if heap_end_addr > accumulator {
                heap_end_addr
            } else {
                accumulator
            }
        });
        Self::allign_to_next_section(v_addr)
        //v_addr
    }
}

/// virtual addresses need to be set before adding data
/// use [PEImageDef::add_section] if possable.
#[derive(Debug, Clone, Default)]
pub struct SectionHeap {
    /// Name of section.
    /// Names longer than 8 bytes will be truncated.
    pub name: String,
    /// Where the section will be loaded into memory.
    pub virtual_address: u32,
    /// Leave as zero for new sections.
    pub virtual_size: u32,
    pub characteristics: SectionFlags,
    pub data: Vec<u8>,
}

impl SectionHeap {
    /// Add data to heap and return the virtual address of the data, extending the
    /// `virtual_size` if needed.
    /// If virtual address is zero, this will just be an offset into the heap.
    pub fn add_data(&mut self, data: &[u8]) -> usize {
        let addr: usize = self.virtual_address as usize + self.data.len();
        self.data.extend_from_slice(data);
        addr
    }

    pub fn virtual_size(&self) -> usize {
        SectionDefinitions::allign_to_next_section(self.data.len())
    }

    /// Returns the remaning space until a new section needs to be allocated.
    pub fn remaining_section_size(&self) -> usize {
        self.virtual_size() - self.data.len()
    }
}
