use super::{ElfFile, ElfMachine, ElfReader, SectionType, Symbol};
use crate::{error::Result, vec::Vec};

impl ElfMachine {
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
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
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
            Some(if is_64 {
                r.u64()? as i64
            } else {
                r.u32()? as i32 as i64
            })
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

impl<'a> ElfFile<'a> {
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
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
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
