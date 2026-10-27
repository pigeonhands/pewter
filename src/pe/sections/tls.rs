//! The .tls Section (Image Only)
//!
//! The TLS directory contains pointers to the TLS template data, the TLS index,
//! and the TLS callback array. All pointer-sized fields are 4 bytes in PE32 and
//! 8 bytes in PE32+.

use crate::containers::Table;
use crate::error::Result;
use crate::io::{ReadData, Reader};

use super::ParseSectionData;

#[derive(Default, Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "reflect", derive(facet::Facet))]
pub struct TlsDirectory {
    /// VA of the start of the TLS template.
    pub start_address_of_raw_data: u64,
    /// VA of the end of the TLS template.
    pub end_address_of_raw_data: u64,
    /// VA of the TLS index (assigned by the loader).
    pub address_of_index: u64,
    /// VA of a null-terminated array of TLS callback function pointers.
    pub address_of_callbacks: u64,
    /// Size in bytes of zero-fill beyond the template data.
    pub size_of_zero_fill: u32,
    /// Alignment info in the upper 4 bits, reserved flags in the lower 20.
    pub characteristics: u32,
}

impl TlsDirectory {
    pub fn read_pe32(data: &[u8]) -> Result<Self> {
        let reader = &mut data.as_ref();
        Ok(Self {
            start_address_of_raw_data: u32::read(reader)? as u64,
            end_address_of_raw_data: u32::read(reader)? as u64,
            address_of_index: u32::read(reader)? as u64,
            address_of_callbacks: u32::read(reader)? as u64,
            size_of_zero_fill: reader.read()?,
            characteristics: reader.read()?,
        })
    }

    pub fn read_pe32_plus(data: &[u8]) -> Result<Self> {
        let reader = &mut data.as_ref();
        Ok(Self {
            start_address_of_raw_data: reader.read()?,
            end_address_of_raw_data: reader.read()?,
            address_of_index: reader.read()?,
            address_of_callbacks: reader.read()?,
            size_of_zero_fill: reader.read()?,
            characteristics: reader.read()?,
        })
    }

    /// Returns the TLS callback array. Each entry is a VA; the array is
    /// terminated by a null pointer. `resolve_va` maps a VA to file data.
    pub fn callbacks(
        &self,
        resolve_va: impl Fn(u64) -> Option<u64>,
    ) -> Table<u64> {
        let mut out = Table::new();
        if self.address_of_callbacks == 0 {
            return out;
        }
        let Some(mut ptr) = resolve_va(self.address_of_callbacks) else {
            return out;
        };
        loop {
            let va = ptr;
            let Some(next) = resolve_va(va) else { break };
            if next == 0 {
                break;
            }
            out.push(next);
            ptr = va + 8;
        }
        out
    }
}

impl ParseSectionData for TlsDirectory {
    fn parse(
        section_data: &[u8],
        _sections: &super::Sections,
        optional_header: &crate::pe::optional_header::OptionalHeader,
        _coff_header: &crate::pe::coff::CoffFileHeader,
    ) -> Result<Self> {
        if optional_header.windows_specific_fields.is_pe32_plus() {
            Self::read_pe32_plus(section_data)
        } else {
            Self::read_pe32(section_data)
        }
    }
}
