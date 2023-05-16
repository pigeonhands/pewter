use crate::{pe::sections::SectionFlags, string::String, vec::Vec};

pub struct PEFileDef {}

/// If a section has a `virtual_address` of 0, it 
/// is not included.
/// 
/// The named fields are well known section names just for convenience. 
/// They are treated exactly the same as values in `other`.
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
    /// Relocation table.
    /// this will be written to if virtual addresses need to be moved.
    pub reloc: Option<SectionHeap>,
    /// Other sections
    pub other: Vec<SectionHeap>,
}

impl SectionDefinitions {
    pub const VIRTUAL_ADDRESS_ALIGNMENT: usize = 0x1000;

    pub fn allign_to_next_section(addr: usize) -> usize {
        (addr + Self::VIRTUAL_ADDRESS_ALIGNMENT) & (!(Self::VIRTUAL_ADDRESS_ALIGNMENT-1))
    }

    /// Iters all sections that have a non-zero `virtual_address`.
    pub fn iter_sections<'a>(&'a self) -> impl Iterator<Item = &SectionHeap> + 'a {
        [&self.text, &self.data, &self.rdata, &self.reloc]
            .into_iter()
            .flat_map(|f| f.as_ref())
            .chain(self.other.iter())
            .filter(|heap| heap.virtual_address != 0)
    }

    /// Finds the section that contains the given virtual address
    #[inline(always)]
    pub fn find_rva(&self, virtual_address: usize) -> Option<&SectionHeap> {
        if virtual_address == 0 {
            return None;
        }
        self.iter_sections().find(|heap| {
            virtual_address >= (heap.virtual_address as usize)
                && virtual_address < (heap.virtual_address as usize + heap.data.len() as usize)
        })
    }

    #[inline]
    pub fn has_overlapping_sections(&self) -> bool {
        for section in self.iter_sections(){
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
        let v_addr = self.iter_sections()
                .fold(0, |accumulator, heap| {
            let heap_end_addr = heap.virtual_address as usize + heap.virtual_size();
            if heap_end_addr > accumulator {
                heap_end_addr
            }else{
                accumulator
            }
        });
        Self::allign_to_next_section(v_addr)
    }
}

/// virtual addresses need to be set before adding data
pub struct SectionHeap {
    /// Name of section.
    /// Names longer than 8 bytes will be truncated.
    pub name: String,
    /// If this is less than `data.len()`, it will be set to `data.len()`
    pub virtual_size: u32,
    /// Where the section will be loaded into memory.
    pub virtual_address: u32,
    pub characteristiics: SectionFlags,
    pub data: Vec<u8>,
}

impl SectionHeap {
    /// Add data to heap and return the virtual address of the data, extending the
    /// `virtual_size` if needed.
    /// If virtual address is zero, this will just be an offset into the heap.
    pub fn add_data(&mut self, data: &[u8]) -> usize {
        let addr: usize = self.virtual_address as usize + self.data.len();
        self.data.extend_from_slice(data);
        if data.len() > self.virtual_size as usize {
            self.virtual_address = SectionDefinitions::allign_to_next_section(self.virtual_address as usize) as u32;
        }
        addr
    }
    
    pub fn virtual_size(&self) -> usize {
        self.data.len().max(self.virtual_size as usize)
    }
}