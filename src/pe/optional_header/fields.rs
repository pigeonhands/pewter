//! Every image file has an optional header that provides information to the loader. T
//! his header is optional in the sense that some files (specifically, object files) do not have it.
//! For image files, this header is required. An object file can have an optional header, but generally
//! this header has no function in an object file except to increase its size.
//!
//! Note that the size of the optional header is not fixed.
//! The SizeOfOptionalHeader field in the COFF header must be used to validate that a probe into the
//! file for a particular data directory does not go beyond SizeOfOptionalHeader. For more information,
//! see COFF File Header (Object and Image).
use crate::{
    error::{PewterError, Result},
    io::{ReadData, WriteData},
};
use bitflags::bitflags;
/// The optional header magic number determines whether an image is a PE32 or PE32+ executable.
///
/// The most common number is 0x10B, which identifies it as a normal executable file.
/// 0x107 identifies it as a ROM image, and 0x20B identifies it as a PE32+ executable.
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum OptionalHeaderMagic {
    #[default]
    PE32 = 0x10B,
    PE32Plus = 0x20B,
    // Other(u16),
}

impl OptionalHeaderMagic {
    pub const SIZE: usize = 2;

    pub fn from_u16(sig: u16) -> Result<Self> {
        match sig {
            0x10B => Ok(Self::PE32),
            0x20B => Ok(Self::PE32Plus),
            //n => Self::Other(n),
            _ => Err(PewterError::invalid_image_format(
                "Bad optional header magic number",
            )),
        }
    }

    pub fn to_u16(&self) -> u16 {
        match self {
            Self::PE32 => 0x10b,
            Self::PE32Plus => 0x20b,
            // Self::Other(n) => *n,
        }
    }
}

impl ReadData for OptionalHeaderMagic {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self::from_u16(reader.read()?)?)
    }
}

impl WriteData for OptionalHeaderMagic {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.to_u16())
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct OptionalHeaderStandardFields {
    /// The unsigned integer that identifies the state of the image file.
    pub magic: OptionalHeaderMagic,
    /// The linker major version number.
    pub major_linker_version: u8,
    /// The linker minor version number.
    pub minor_linker_version: u8,
    /// The size of the code (text) section, or the sum of all code sections
    /// if there are multiple sections.
    pub size_of_code: u32,
    /// The size of the initialized data section, or the sum of all such sections
    /// if there are multiple data sections.
    pub size_of_initilized_data: u32,
    /// The size of the uninitialized data section (BSS), or the sum of all such
    /// sections if there are multiple BSS sections.
    pub size_of_unitilized_data: u32,
    /// The address of the entry point relative to the image base when the
    /// executable file is loaded into memory. For program images, this is
    /// the starting address. For device drivers, this is the address of the
    /// initialization function. An entry point is optional for DLLs. When no
    /// entry point is present, this field must be zero.
    pub address_of_entry_point: u32,
    /// The address that is relative to the image base of the beginning-of-code
    /// section when it is loaded into memory.
    pub base_of_code: u32,
    /// PE32 contains this additional field, which is absent in PE32+, following BaseOfCode.
    ///
    /// The address that is relative to the image base of the beginning-of-data
    /// section when it is loaded into memory.
    pub base_of_data: Option<u32>,
}

impl OptionalHeaderStandardFields {
    pub const SIZE_PE: usize = 28;
    pub const SIZE_PE_PLUS: usize = 24;
}

impl ReadData for OptionalHeaderStandardFields {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        let magic = reader.read()?;
        Ok(Self {
            magic,
            major_linker_version: reader.read()?,
            minor_linker_version: reader.read()?,
            size_of_code: reader.read()?,
            size_of_initilized_data: reader.read()?,
            size_of_unitilized_data: reader.read()?,
            address_of_entry_point: reader.read()?,
            base_of_code: reader.read()?,
            base_of_data: (magic == OptionalHeaderMagic::PE32)
                .then(|| reader.read())
                .transpose()?,
        })
    }
}

impl WriteData for &OptionalHeaderStandardFields {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.magic)?;
        writer.write(self.major_linker_version)?;
        writer.write(self.minor_linker_version)?;
        writer.write(self.size_of_code)?;
        writer.write(self.size_of_initilized_data)?;
        writer.write(self.size_of_unitilized_data)?;
        writer.write(self.address_of_entry_point)?;
        writer.write(self.base_of_code)?;
        if self.magic == OptionalHeaderMagic::PE32 {
            writer.write(self.base_of_data.unwrap_or(0))?;
        }
        Ok(())
    }
}

/// The following values defined for the Subsystem field of the optional header
/// determine which Windows subsystem (if any) is required to run the image.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u16)]
pub enum ImageSubsystem {
    #[default]
    /// An unknown subsystem
    Unknown = 0,
    /// Device drivers and native Windows processes
    Native = 1,
    /// The Windows graphical user interface (GUI) subsystem
    WindowsGui = 2,
    /// The Windows character subsystem
    WindowsCui = 3,
    /// The OS/2 character subsystem
    Os2Cui = 5,
    /// The Posix character subsystem
    PosixCui = 7,
    /// Native Win9x driver
    NativeWindows = 8,
    /// Windows CE
    WindowsCeGui = 9,
    /// An Extensible Firmware Interface (EFI) application
    EfiApplication = 10,
    /// An EFI driver with boot services
    EbiBootServiceDriver = 11,
    /// An EFI driver with run-time services
    EfiRuntimeDriver = 12,
    /// An EFI ROM image
    EfiRom = 13,
    /// XBOX
    Xbox = 14,
    /// Windows boot application.
    WindowsBootApplication = 15,
    /// Other
    Other(u16),
}

impl ImageSubsystem {
    pub fn to_u16(&self) -> u16 {
        match self {
            Self::Unknown => 0,
            Self::Native => 1,
            Self::WindowsGui => 2,
            Self::WindowsCui => 3,
            Self::Os2Cui => 5,
            Self::PosixCui => 7,
            Self::NativeWindows => 8,
            Self::WindowsCeGui => 9,
            Self::EfiApplication => 10,
            Self::EbiBootServiceDriver => 11,
            Self::EfiRuntimeDriver => 12,
            Self::EfiRom => 13,
            Self::Xbox => 14,
            Self::WindowsBootApplication => 15,
            Self::Other(n) => *n,
        }
    }

    pub fn from_u16(subsystem: u16) -> Self {
        match subsystem {
            0 => Self::Unknown,
            1 => Self::Native,
            2 => Self::WindowsGui,
            3 => Self::WindowsCui,
            5 => Self::Os2Cui,
            7 => Self::PosixCui,
            8 => Self::NativeWindows,
            9 => Self::WindowsCeGui,
            10 => Self::EfiApplication,
            11 => Self::EbiBootServiceDriver,
            12 => Self::EfiRuntimeDriver,
            13 => Self::EfiRom,
            14 => Self::Xbox,
            15 => Self::WindowsBootApplication,
            n => Self::Other(n),
        }
    }
}

bitflags! {
    #[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct ImageDllCharacteristics: u16 {
        /// Reserved, must be zero.
        const RESERVED = 0x01 | 0x02 | 0x04 | 0x08;
        /// Image can handle a high entropy 64-bit virtual address space.
        const HIGH_ENTROPY_VA = 0x0020;
        /// DLL can be relocated at load time.
        const DYNAMIC_BASE = 0x0040;
        /// Code Integrity checks are enforced.
        const FORCE_INTEGRITY = 0x0080;
        /// Image is NX compatible.
        const NX_COMPAT  = 0x0100;
        /// Isolation aware, but do not isolate the image.
        const NO_ISOLATION = 0x0200;
        /// Does not use structured exception (SE) handling. No SE handler
        /// may be called in this image.
        const NO_SEH = 0x0400 ;
        /// Do not bind the image.
        const NO_BIND  = 0x0800 ;
        /// Image must execute in an AppContainer.
        const APPCONTAINER = 0x1000;
        /// A WDM driver.
        const WDM_DRIVER = 0x2000 ;
        /// Image supports Control Flow Guard.
        const GUARD_CF = 0x4000 ;
        /// Terminal Server aware.
        const TERMINAL_SERVER_AWARE  = 0x8000 ;
    }
}

/// Used to determine the field size in the
/// [`OptionalHeaderWindowsSpecificFields`] struct.
pub trait OptVariant {
    type Addr: ReadData + WriteData + Copy;
}

/// 32bit address size for Pe32.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Pe32;
impl OptVariant for Pe32 {
    type Addr = u32;
}

/// 64bit address size for Pe32.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Pe32Plus;
impl OptVariant for Pe32Plus {
    type Addr = u64;
}

pub(crate) trait CalulateOptVariantSize<A: OptVariant> {
    fn calculate_size() -> usize;
}

/// These 21 fields are an extension to the COFF optional header format.
/// They contain additional information that is required by the linker and loader in Windows.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct OptionalHeaderWindowsSpecificFields<A: OptVariant> {
    /// The preferred address of the first byte of image when loaded into memory;
    /// must be a multiple of 64 K. The default for DLLs is 0x10000000.
    /// The default for Windows CE EXEs is 0x00010000. The default for Windows NT,
    /// Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is 0x00400000.
    pub image_base: A::Addr,
    /// The alignment (in bytes) of sections when they are loaded into memory.
    /// It must be greater than or equal to FileAlignment. The default is the page
    /// size for the architecture.
    pub section_alignment: u32,
    /// The alignment factor (in bytes) that is used to align the raw data of sections
    /// in the image file. The value should be a power of 2 between 512 and 64 K, inclusive.
    /// The default is 512. If the SectionAlignment is less than the architecture's page size,
    /// then FileAlignment must match SectionAlignment.
    pub file_alignment: u32,
    /// The major version number of the required operating system.
    pub major_operating_system_version: u16,
    /// The minor version number of the required operating system.
    pub minor_operating_system_version: u16,
    /// The major version number of the image.
    pub major_image_version: u16,
    /// The minor version number of the image.
    pub minor_image_version: u16,
    /// The major version number of the subsystem.
    pub major_subsystem_version: u16,
    /// The minor version number of the subsystem.
    pub minor_subsystem_version: u16,
    /// Reserved, must be zero.
    pub win32_version_value: u32,
    /// The size (in bytes) of the image, including all headers,
    /// as the image is loaded in memory. It must be a multiple of SectionAlignment.
    pub size_of_image: u32,
    /// The combined size of an MS-DOS stub, PE header, and section headers rounded
    /// up to a multiple of FileAlignment.
    pub size_of_headers: u32,
    /// The image file checksum. The algorithm for computing the checksum is incorporated
    /// into IMAGHELP.DLL. The following are checked for validation at load time: all drivers,
    /// any DLL loaded at boot time, and any DLL that is loaded into a critical Windows process.
    pub check_sum: u32,
    /// The subsystem that is required to run this image. For more information, see Windows Subsystem.
    pub subsystem: ImageSubsystem,
    /// For more information, see [`ImageDllCharacteristics`].
    pub dll_characteristics: ImageDllCharacteristics,
    /// The size of the stack to reserve. Only SizeOfStackCommit is committed;
    /// the rest is made available one page at a time until the reserve size is reached.
    pub size_of_stack_reserve: A::Addr,
    /// The size of the stack to commit.
    pub size_of_stack_commit: A::Addr,
    /// The size of the local heap space to reserve. Only SizeOfHeapCommit is committed; the
    /// rest is made available one page at a time until the reserve size is reached.
    pub size_of_heap_reserve: A::Addr,
    /// The size of the local heap space to commit.
    pub size_of_heap_commit: A::Addr,
    /// Reserved, must be zero.
    pub loader_flags: u32,
    /// The number of data-directory entries in the remainder of the optional header.
    /// Each describes a location and size.
    pub number_of_rva_and_sizes: u32,
}

impl OptionalHeaderWindowsSpecificFields<Pe32> {
    pub const SIZE: usize = 68;
}

impl OptionalHeaderWindowsSpecificFields<Pe32Plus> {
    pub const SIZE: usize = 88;
}

impl CalulateOptVariantSize<Pe32> for OptionalHeaderWindowsSpecificFields<Pe32> {
    fn calculate_size() -> usize {
        Self::SIZE
    }
}

impl CalulateOptVariantSize<Pe32Plus> for OptionalHeaderWindowsSpecificFields<Pe32> {
    fn calculate_size() -> usize {
        Self::SIZE
    }
}

impl<T: OptVariant> ReadData for OptionalHeaderWindowsSpecificFields<T> {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            image_base: reader.read()?,
            section_alignment: reader.read()?,
            file_alignment: reader.read()?,
            major_operating_system_version: reader.read()?,
            minor_operating_system_version: reader.read()?,
            major_image_version: reader.read()?,
            minor_image_version: reader.read()?,
            major_subsystem_version: reader.read()?,
            minor_subsystem_version: reader.read()?,
            win32_version_value: reader.read()?,
            size_of_image: reader.read()?,
            size_of_headers: reader.read()?,
            check_sum: reader.read()?,
            subsystem: ImageSubsystem::from_u16(reader.read()?),
            dll_characteristics: ImageDllCharacteristics::from_bits_retain(reader.read()?),
            size_of_stack_reserve: reader.read()?,
            size_of_stack_commit: reader.read()?,
            size_of_heap_reserve: reader.read()?,
            size_of_heap_commit: reader.read()?,
            loader_flags: reader.read()?,
            number_of_rva_and_sizes: reader.read()?,
        })
    }
}

impl<T: OptVariant> WriteData for &OptionalHeaderWindowsSpecificFields<T> {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.image_base)?;
        writer.write(self.section_alignment)?;
        writer.write(self.file_alignment)?;
        writer.write(self.major_operating_system_version)?;
        writer.write(self.minor_operating_system_version)?;
        writer.write(self.major_image_version)?;
        writer.write(self.minor_image_version)?;
        writer.write(self.major_subsystem_version)?;
        writer.write(self.minor_subsystem_version)?;
        writer.write(self.win32_version_value)?;
        writer.write(self.size_of_image)?;
        writer.write(self.size_of_headers)?;
        writer.write(self.check_sum)?;
        writer.write(self.subsystem.to_u16())?;
        writer.write(self.dll_characteristics.bits())?;
        writer.write(self.size_of_stack_reserve)?;
        writer.write(self.size_of_stack_commit)?;
        writer.write(self.size_of_heap_reserve)?;
        writer.write(self.size_of_heap_commit)?;
        writer.write(self.loader_flags)?;
        writer.write(self.number_of_rva_and_sizes)?;
        Ok(())
    }
}

/// Holds the Optional Header Windows Specific fields
/// for either PE32 or PE32+.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OptionalHeaderWindowsSpecific {
    PE32(OptionalHeaderWindowsSpecificFields<Pe32>),
    PE32Plus(OptionalHeaderWindowsSpecificFields<Pe32Plus>),
}

impl Default for OptionalHeaderWindowsSpecific {
    fn default() -> Self {
        Self::PE32(Default::default())
    }
}

impl OptionalHeaderWindowsSpecific {
    /// Returns true if the enum variant is
    /// [PE32](OptionalHeaderWindowsSpecific::PE32)
    pub fn is_pe32(&self) -> bool {
        matches!(self, Self::PE32(_))
    }

    /// Returns true if the enum variant is
    /// [PEPlus](OptionalHeaderWindowsSpecific::PE32Plus)
    pub fn is_pe32_plus(&self) -> bool {
        matches!(self, Self::PE32Plus(_))
    }

    /// gets [image_base](OptionalHeaderWindowsSpecificFields::image_base)
    /// from the underlying variant.
    #[inline]
    pub fn image_base(&self) -> u64 {
        match self {
            Self::PE32(pe32) => pe32.image_base as u64,
            Self::PE32Plus(pe32) => pe32.image_base as u64,
        }
    }
    /// sets [image_base](OptionalHeaderWindowsSpecificFields::image_base)
    /// on the underlying variant.
    #[inline]
    pub fn set_image_base(&mut self, value: u64) {
        match self {
            Self::PE32(pe32) => pe32.image_base = value as u32,
            Self::PE32Plus(pe32) => pe32.image_base = value as u64,
        };
    }

    /// gets [section_alignment](OptionalHeaderWindowsSpecificFields::section_alignment)
    /// from the underlying variant.
    #[inline]
    pub fn section_alignment(&self) -> u32 {
        match self {
            Self::PE32(pe32) => pe32.section_alignment,
            Self::PE32Plus(pe32) => pe32.section_alignment,
        }
    }
    /// sets [section_alignment](OptionalHeaderWindowsSpecificFields::section_alignment)
    /// on the underlying variant.
    #[inline]
    pub fn set_section_alignment(&mut self, value: u32) {
        match self {
            Self::PE32(pe32) => pe32.section_alignment = value,
            Self::PE32Plus(pe32) => pe32.section_alignment = value,
        };
    }

    /// gets [file_alignment](OptionalHeaderWindowsSpecificFields::file_alignment)
    /// from the underlying variant.
    #[inline]
    pub fn file_alignment(&self) -> u64 {
        match self {
            Self::PE32(pe32) => pe32.file_alignment as u64,
            Self::PE32Plus(pe32) => pe32.file_alignment as u64,
        }
    }
    /// sets [file_alignment](OptionalHeaderWindowsSpecificFields::file_alignment)
    /// on the underlying variant.
    #[inline]
    pub fn set_file_alignment(&mut self, value: u32) {
        match self {
            Self::PE32(pe32) => pe32.file_alignment = value,
            Self::PE32Plus(pe32) => pe32.file_alignment = value,
        };
    }

    /// gets [major_operating_system_version](OptionalHeaderWindowsSpecificFields::major_operating_system_version)
    /// from the underlying variant.
    #[inline]
    pub fn major_operating_system_version(&self) -> u16 {
        match self {
            Self::PE32(pe32) => pe32.major_operating_system_version,
            Self::PE32Plus(pe32) => pe32.major_operating_system_version,
        }
    }
    /// sets [major_operating_system_version](OptionalHeaderWindowsSpecificFields::major_operating_system_version)
    /// on the underlying variant.
    #[inline]
    pub fn set_major_operating_system_version(&mut self, value: u16) {
        match self {
            Self::PE32(pe32) => pe32.major_operating_system_version = value,
            Self::PE32Plus(pe32) => pe32.major_operating_system_version = value,
        };
    }

    /// gets [minor_operating_system_version](OptionalHeaderWindowsSpecificFields::minor_operating_system_version)
    /// from the underlying variant.
    #[inline]
    pub fn minor_operating_system_version(&self) -> u16 {
        match self {
            Self::PE32(pe32) => pe32.minor_operating_system_version,
            Self::PE32Plus(pe32) => pe32.minor_operating_system_version,
        }
    }
    /// sets [minor_operating_system_version](OptionalHeaderWindowsSpecificFields::minor_operating_system_version)
    /// on the underlying variant.
    #[inline]
    pub fn set_minor_operating_system_version(&mut self, value: u16) {
        match self {
            Self::PE32(pe32) => pe32.minor_operating_system_version = value,
            Self::PE32Plus(pe32) => pe32.minor_operating_system_version = value,
        };
    }

    /// gets [major_image_version](OptionalHeaderWindowsSpecificFields::major_image_version)
    /// from the underlying variant.
    #[inline]
    pub fn major_image_version(&self) -> u16 {
        match self {
            Self::PE32(pe32) => pe32.major_image_version,
            Self::PE32Plus(pe32) => pe32.major_image_version,
        }
    }
    /// sets [major_image_version](OptionalHeaderWindowsSpecificFields::major_image_version)
    /// on the underlying variant.
    #[inline]
    pub fn set_major_image_version(&mut self, value: u16) {
        match self {
            Self::PE32(pe32) => pe32.major_image_version = value,
            Self::PE32Plus(pe32) => pe32.major_image_version = value,
        };
    }

    /// gets [minor_image_version](OptionalHeaderWindowsSpecificFields::minor_image_version)
    /// from the underlying variant.
    #[inline]
    pub fn minor_image_version(&self) -> u16 {
        match self {
            Self::PE32(pe32) => pe32.minor_image_version,
            Self::PE32Plus(pe32) => pe32.minor_image_version,
        }
    }
    /// sets [minor_image_version](OptionalHeaderWindowsSpecificFields::minor_image_version)
    /// on the underlying variant.
    #[inline]
    pub fn set_minor_image_version(&mut self, value: u16) {
        match self {
            Self::PE32(pe32) => pe32.minor_image_version = value,
            Self::PE32Plus(pe32) => pe32.minor_image_version = value,
        };
    }

    /// gets [major_subsystem_version](OptionalHeaderWindowsSpecificFields::major_subsystem_version)
    /// from the underlying variant.
    #[inline]
    pub fn major_subsystem_version(&self) -> u16 {
        match self {
            Self::PE32(pe32) => pe32.major_subsystem_version,
            Self::PE32Plus(pe32) => pe32.major_subsystem_version,
        }
    }
    /// sets [major_subsystem_version](OptionalHeaderWindowsSpecificFields::major_subsystem_version)
    /// on the underlying variant.
    #[inline]
    pub fn set_major_subsystem_version(&mut self, value: u16) {
        match self {
            Self::PE32(pe32) => pe32.major_subsystem_version = value,
            Self::PE32Plus(pe32) => pe32.major_subsystem_version = value,
        };
    }

    /// gets [minor_subsystem_version](OptionalHeaderWindowsSpecificFields::minor_subsystem_version)
    /// from the underlying variant.
    #[inline]
    pub fn minor_subsystem_version(&self) -> u16 {
        match self {
            Self::PE32(pe32) => pe32.minor_subsystem_version,
            Self::PE32Plus(pe32) => pe32.minor_subsystem_version,
        }
    }
    /// sets [minor_subsystem_version](OptionalHeaderWindowsSpecificFields::minor_subsystem_version)
    /// on the underlying variant.
    #[inline]
    pub fn set_minor_subsystem_version(&mut self, value: u16) {
        match self {
            Self::PE32(pe32) => pe32.minor_subsystem_version = value,
            Self::PE32Plus(pe32) => pe32.minor_subsystem_version = value,
        };
    }

    /// gets [win32_version_value](OptionalHeaderWindowsSpecificFields::win32_version_value)
    /// from the underlying variant.
    #[inline]
    pub fn win32_version_value(&self) -> u32 {
        match self {
            Self::PE32(pe32) => pe32.win32_version_value,
            Self::PE32Plus(pe32) => pe32.win32_version_value,
        }
    }
    /// sets [win32_version_value](OptionalHeaderWindowsSpecificFields::win32_version_value)
    /// on the underlying variant.
    #[inline]
    pub fn set_win32_version_value(&mut self, value: u32) {
        match self {
            Self::PE32(pe32) => pe32.win32_version_value = value,
            Self::PE32Plus(pe32) => pe32.win32_version_value = value,
        };
    }

    /// gets [size_of_image](OptionalHeaderWindowsSpecificFields::size_of_image)
    /// from the underlying variant.
    #[inline]
    pub fn size_of_image(&self) -> u32 {
        match self {
            Self::PE32(pe32) => pe32.size_of_image,
            Self::PE32Plus(pe32) => pe32.size_of_image,
        }
    }
    /// sets [size_of_image](OptionalHeaderWindowsSpecificFields::size_of_image)
    /// on the underlying variant.
    #[inline]
    pub fn set_size_of_image(&mut self, value: u32) {
        match self {
            Self::PE32(pe32) => pe32.size_of_image = value,
            Self::PE32Plus(pe32) => pe32.size_of_image = value,
        };
    }

    /// gets [size_of_headers](OptionalHeaderWindowsSpecificFields::size_of_headers)
    /// from the underlying variant.
    #[inline]
    pub fn size_of_headers(&self) -> u32 {
        match self {
            Self::PE32(pe32) => pe32.size_of_headers,
            Self::PE32Plus(pe32) => pe32.size_of_headers,
        }
    }
    /// sets [size_of_headers](OptionalHeaderWindowsSpecificFields::size_of_headers)
    /// on the underlying variant.
    #[inline]
    pub fn set_size_of_headers(&mut self, value: u32) {
        match self {
            Self::PE32(pe32) => pe32.size_of_headers = value,
            Self::PE32Plus(pe32) => pe32.size_of_headers = value,
        };
    }

    /// gets [check_sum](OptionalHeaderWindowsSpecificFields::check_sum)
    /// from the underlying variant.
    #[inline]
    pub fn check_sum(&self) -> u32 {
        match self {
            Self::PE32(pe32) => pe32.check_sum,
            Self::PE32Plus(pe32) => pe32.check_sum,
        }
    }
    /// sets [check_sum](OptionalHeaderWindowsSpecificFields::check_sum)
    /// on the underlying variant.
    #[inline]
    pub fn set_check_sum(&mut self, value: u32) {
        match self {
            Self::PE32(pe32) => pe32.check_sum = value,
            Self::PE32Plus(pe32) => pe32.check_sum = value,
        };
    }

    /// gets [subsystem](OptionalHeaderWindowsSpecificFields::subsystem)
    /// from the underlying variant.
    #[inline]
    pub fn subsystem(&self) -> ImageSubsystem {
        match self {
            Self::PE32(pe32) => pe32.subsystem,
            Self::PE32Plus(pe32) => pe32.subsystem,
        }
    }
    /// sets [subsystem](OptionalHeaderWindowsSpecificFields::subsystem)
    /// on the underlying variant.
    #[inline]
    pub fn set_subsystem(&mut self, value: ImageSubsystem) {
        match self {
            Self::PE32(pe32) => pe32.subsystem = value,
            Self::PE32Plus(pe32) => pe32.subsystem = value,
        };
    }

    /// gets [dll_characteristics](OptionalHeaderWindowsSpecificFields::dll_characteristics)
    /// from the underlying variant.
    #[inline]
    pub fn dll_characteristics(&self) -> ImageDllCharacteristics {
        match self {
            Self::PE32(pe32) => pe32.dll_characteristics,
            Self::PE32Plus(pe32) => pe32.dll_characteristics,
        }
    }
    /// sets [dll_characteristics](OptionalHeaderWindowsSpecificFields::dll_characteristics)
    /// on the underlying variant.
    #[inline]
    pub fn set_dll_characteristics(&mut self, value: ImageDllCharacteristics) {
        match self {
            Self::PE32(pe32) => pe32.dll_characteristics = value,
            Self::PE32Plus(pe32) => pe32.dll_characteristics = value,
        };
    }

    /// gets [size_of_stack_reserve](OptionalHeaderWindowsSpecificFields::size_of_stack_reserve)
    /// from the underlying variant.
    #[inline]
    pub fn size_of_stack_reserve(&self) -> u64 {
        match self {
            Self::PE32(pe32) => pe32.size_of_stack_reserve as u64,
            Self::PE32Plus(pe32) => pe32.size_of_stack_reserve,
        }
    }
    /// sets [size_of_stack_reserve](OptionalHeaderWindowsSpecificFields::size_of_stack_reserve)
    /// on the underlying variant.
    #[inline]
    pub fn set_size_of_stack_reserve(&mut self, value: u64) {
        match self {
            Self::PE32(pe32) => pe32.size_of_stack_reserve = value as u32,
            Self::PE32Plus(pe32) => pe32.size_of_stack_reserve = value,
        };
    }

    /// gets [size_of_stack_commit](OptionalHeaderWindowsSpecificFields::size_of_stack_commit)
    /// from the underlying variant.
    #[inline]
    pub fn size_of_stack_commit(&self) -> u64 {
        match self {
            Self::PE32(pe32) => pe32.size_of_stack_commit as u64,
            Self::PE32Plus(pe32) => pe32.size_of_stack_commit,
        }
    }
    /// sets [size_of_stack_commit](OptionalHeaderWindowsSpecificFields::size_of_stack_commit)
    /// on the underlying variant.
    #[inline]
    pub fn set_size_of_stack_commit(&mut self, value: u64) {
        match self {
            Self::PE32(pe32) => pe32.size_of_stack_commit = value as u32,
            Self::PE32Plus(pe32) => pe32.size_of_stack_commit = value,
        };
    }

    /// gets [size_of_heap_reserve](OptionalHeaderWindowsSpecificFields::size_of_heap_reserve)
    /// from the underlying variant.
    #[inline]
    pub fn size_of_heap_reserve(&self) -> u64 {
        match self {
            Self::PE32(pe32) => pe32.size_of_heap_reserve as u64,
            Self::PE32Plus(pe32) => pe32.size_of_heap_reserve,
        }
    }
    /// sets [size_of_heap_reserve](OptionalHeaderWindowsSpecificFields::size_of_heap_reserve)
    /// on the underlying variant.
    #[inline]
    pub fn set_size_of_heap_reserve(&mut self, value: u64) {
        match self {
            Self::PE32(pe32) => pe32.size_of_heap_reserve = value as u32,
            Self::PE32Plus(pe32) => pe32.size_of_heap_reserve = value,
        };
    }

    /// gets [size_of_heap_commit](OptionalHeaderWindowsSpecificFields::size_of_heap_commit)
    /// from the underlying variant.
    #[inline]
    pub fn size_of_heap_commit(&self) -> u64 {
        match self {
            Self::PE32(pe32) => pe32.size_of_heap_commit as u64,
            Self::PE32Plus(pe32) => pe32.size_of_heap_commit,
        }
    }
    /// sets [size_of_heap_commit](OptionalHeaderWindowsSpecificFields::size_of_heap_commit)
    /// on the underlying variant.
    #[inline]
    pub fn set_size_of_heap_commit(&mut self, value: u64) {
        match self {
            Self::PE32(pe32) => pe32.size_of_heap_commit = value as u32,
            Self::PE32Plus(pe32) => pe32.size_of_heap_commit = value,
        };
    }

    /// gets [loader_flags](OptionalHeaderWindowsSpecificFields::loader_flags)
    /// from the underlying variant.
    #[inline]
    pub fn loader_flags(&self) -> u32 {
        match self {
            Self::PE32(pe32) => pe32.loader_flags,
            Self::PE32Plus(pe32) => pe32.loader_flags,
        }
    }
    /// sets [loader_flags](OptionalHeaderWindowsSpecificFields::loader_flags)
    /// on the underlying variant.
    #[inline]
    pub fn set_loader_flags(&mut self, value: u32) {
        match self {
            Self::PE32(pe32) => pe32.loader_flags = value,
            Self::PE32Plus(pe32) => pe32.loader_flags = value,
        };
    }

    /// gets [number_of_rva_and_sizes](OptionalHeaderWindowsSpecificFields::number_of_rva_and_sizes)
    /// from the underlying variant.
    #[inline]
    pub fn number_of_rva_and_sizes(&self) -> u32 {
        match self {
            Self::PE32(pe32) => pe32.number_of_rva_and_sizes,
            Self::PE32Plus(pe32) => pe32.number_of_rva_and_sizes,
        }
    }

    /// sets [number_of_rva_and_sizes](OptionalHeaderWindowsSpecificFields::number_of_rva_and_sizes)
    /// on the underlying variant.
    #[inline]
    pub fn set_number_of_rva_and_sizes(&mut self, value: u32) {
        match self {
            Self::PE32(pe32) => pe32.number_of_rva_and_sizes = value,
            Self::PE32Plus(pe32) => pe32.number_of_rva_and_sizes = value,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opttional_header_magic_is_2_bytes() {
        let buffer: [u8; OptionalHeaderMagic::SIZE] = 0x10B_u16.to_le_bytes();
        let read_ptr = &mut buffer.as_slice();
        OptionalHeaderMagic::read(read_ptr).unwrap();
        assert!(read_ptr.is_empty());
    }

    #[test]
    fn read_optional_header_magic() {
        assert_eq!(
            OptionalHeaderMagic::read(&mut [0x0B, 0x1u8].as_slice()).unwrap(),
            OptionalHeaderMagic::PE32
        );
        assert_eq!(
            OptionalHeaderMagic::read(&mut [0x0B, 0x2u8].as_slice()).unwrap(),
            OptionalHeaderMagic::PE32Plus
        );
    }

    #[test]
    fn optional_header_stand_fields_pe_is_24() {
        let mut buffer = [0u8; OptionalHeaderStandardFields::SIZE_PE];
        buffer[..2].copy_from_slice(&OptionalHeaderMagic::PE32.to_u16().to_le_bytes());
        let read_ptr = &mut buffer.as_slice();
        OptionalHeaderStandardFields::read(read_ptr).unwrap();
        assert_eq!(read_ptr.len(), 0);
    }

    #[test]
    fn optional_header_standard_fields_pe32_plus_is_28_bytes() {
        let mut buffer = [0u8; OptionalHeaderStandardFields::SIZE_PE_PLUS];
        buffer[..2].copy_from_slice(&OptionalHeaderMagic::PE32Plus.to_u16().to_le_bytes());
        let read_ptr = &mut buffer.as_slice();
        OptionalHeaderStandardFields::read(read_ptr).unwrap();
        assert_eq!(read_ptr.len(), 0);
    }

    #[test]
    fn optional_header_win_specific_pe32_is_68() {
        let buffer = [0u8; OptionalHeaderWindowsSpecificFields::<Pe32>::SIZE];
        let read_ptr = &mut buffer.as_slice();
        OptionalHeaderWindowsSpecificFields::<Pe32>::read(read_ptr).unwrap();
        assert_eq!(read_ptr.len(), 0);
    }

    #[test]
    fn optional_header_win_specific_pe32_plus_is_88() {
        let buffer = [0u8; OptionalHeaderWindowsSpecificFields::<Pe32Plus>::SIZE];
        let read_ptr = &mut buffer.as_slice();
        OptionalHeaderWindowsSpecificFields::<Pe32Plus>::read(read_ptr).unwrap();
        assert_eq!(read_ptr.len(), 0);
    }
}
