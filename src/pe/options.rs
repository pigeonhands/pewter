use bitflags::bitflags;

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ParseSectionFlags : u32 {
        const NONE = 0;
        const EXPORT_TABLE = 1<<0;
        const IMPORT_TABLE = 1<<1;
        const RESOURCE_TABLE = 1<<2;
        const EXCEPTION_TABLE = 1<<3;
        const CERTIFICATE_TABLE = 1<<4;
        const BASE_RELOCATION_TABLE = 1<<5;
        const DEBUG = 1<<6;
        const ARCHITECTURE = 1<<7;
        const GLOBAL_PTR = 1<<8;
        const TLS_TABLE = 1<<8;
        const LOAD_CONFIG_TABLE = 1<<9;
        const BOUND_TABLE = 1<<10;
        const ITA = 1<<11;
        const DELAY_IMPORT_DESCRIPTOR = 1<<12;
        const CLR_RUNTIME_HEADER = 1<<13;
        const RESERVED = 1<<14;

        const ALL = Self::EXPORT_TABLE.bits() |
        Self::IMPORT_TABLE.bits() |
        Self::RESOURCE_TABLE.bits() |
            Self::EXCEPTION_TABLE.bits() |
            Self::CERTIFICATE_TABLE.bits() |
            Self::BASE_RELOCATION_TABLE.bits() |
            Self::DEBUG.bits() |
            Self::ARCHITECTURE.bits() |
            Self::GLOBAL_PTR.bits() |
            Self::TLS_TABLE.bits() |
            Self::LOAD_CONFIG_TABLE.bits() |
            Self::BOUND_TABLE.bits() |
            Self::ITA.bits() |
            Self::DELAY_IMPORT_DESCRIPTOR.bits() |
            Self::CLR_RUNTIME_HEADER.bits() |
            Self::RESERVED.bits();
    }
}

/// Parsing options.
#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Specifies what special sections to parse.
    /// default: [`ParseSectionFlags::ALL`]
    pub parse_special_sections: ParseSectionFlags,
}

impl Options {
    /// Does the least ammount of parsing.
    pub fn minimal() -> Self {
        Self {
            parse_special_sections: ParseSectionFlags::NONE,
        }
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            parse_special_sections: ParseSectionFlags::ALL,
        }
    }
}
