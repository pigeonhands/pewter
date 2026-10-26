use strum::FromRepr;

use super::{c_str, ElfFile, ElfReader, SectionType};
use crate::{error::Result, vec::Vec};

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum SymbolType {
    NoType = 0,
    Object = 1,
    Func = 2,
    Section = 3,
    File = 4,
    Common = 5,
    Tls = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, FromRepr)]
#[repr(u8)]
pub enum SymbolBinding {
    Local = 0,
    Global = 1,
    Weak = 2,
    /// `STB_GNU_UNIQUE`
    GnuUnique = 10,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol<'a> {
    pub name: &'a str,
    pub name_offset: u32,
    pub value: u64,
    pub size: u64,
    pub info: u8,
    pub other: u8,
    pub section_index: u16,
    /// From `.dynsym` rather than `.symtab`.
    pub dynamic: bool,
}

impl Symbol<'_> {
    pub(crate) fn read(r: &mut ElfReader, is_64: bool) -> Result<Self> {
        let name_offset = r.u32()?;
        let (value, size, info, other, section_index) = if is_64 {
            let info = r.u8()?;
            let other = r.u8()?;
            let section_index = r.u16()?;
            (r.u64()?, r.u64()?, info, other, section_index)
        } else {
            let value = r.u32()? as u64;
            let size = r.u32()? as u64;
            (value, size, r.u8()?, r.u8()?, r.u16()?)
        };
        Ok(Self {
            name: "",
            name_offset,
            value,
            size,
            info,
            other,
            section_index,
            dynamic: false,
        })
    }

    pub fn symbol_type(&self) -> Option<SymbolType> {
        SymbolType::from_repr(self.info & 0xF)
    }

    pub fn binding(&self) -> Option<SymbolBinding> {
        SymbolBinding::from_repr(self.info >> 4)
    }

    /// Defined in this file, rather than imported.
    pub fn is_defined(&self) -> bool {
        self.section_index != 0
    }
}

impl<'a> ElfFile<'a> {
    /// Symbols from `.symtab` and `.dynsym`.
    pub fn symbols(&self) -> Result<Vec<Symbol<'a>>> {
        let mut symbols = Vec::new();
        for section in &self.sections {
            if !matches!(
                section.header.section_type,
                SectionType::SymTab | SectionType::DynSym
            ) {
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
}
