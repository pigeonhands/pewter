//! Optional Header Data Directories (Image Only)
use crate::io::{ReadData, WriteData};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SectionName {
    ExportTable = 0,
    ImportTable = 1,
    ResourceTable = 2,
    ExceptionTable = 3,
    CertificateTable = 4,
    BaseRelocationTable = 5,
    Debug = 6,
    Architecture = 7,
    GlobalPtr = 8,
    TlsTable = 9,
    LoadConfigTable = 10,
    BoundImport = 11,
    Ita = 12,
    DelayImportDescriptor = 13,
    ClrRuntimeHeader = 14,
    Reserved = 15,
}

impl SectionName {
    pub const ALL: [SectionName; 16] = [
        SectionName::ExportTable,
        SectionName::ImportTable,
        SectionName::ResourceTable,
        SectionName::ExceptionTable,
        SectionName::CertificateTable,
        SectionName::BaseRelocationTable,
        SectionName::Debug,
        SectionName::Architecture,
        SectionName::GlobalPtr,
        SectionName::TlsTable,
        SectionName::LoadConfigTable,
        SectionName::BoundImport,
        SectionName::Ita,
        SectionName::DelayImportDescriptor,
        SectionName::ClrRuntimeHeader,
        SectionName::Reserved,
    ];
}

/// All the possable data directories.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct DataDirectories {
    /// The export table address and size.
    pub export_table: ImageDataDirectory,
    /// The import  table address and size.
    pub import_table: ImageDataDirectory,
    /// The resource table address and size.
    pub resource_table: ImageDataDirectory,
    /// The exception table address and size.
    pub exception_table: ImageDataDirectory,
    /// The attribute certificate table address and size.
    pub certificate_table: ImageDataDirectory,
    /// The base relocation certificate table address and size.
    pub base_relocation_table: ImageDataDirectory,
    /// The debug data starting address and size.
    pub debug: ImageDataDirectory,
    /// Reserved, must be 0.
    pub architecture: ImageDataDirectory,
    /// The RVA of the value to be stored in the global pointer register.
    /// The size member of this structure must be set to zero.
    pub global_ptr: ImageDataDirectory,
    /// The thread local storage (TLS) table address and size.
    pub tls_table: ImageDataDirectory,
    /// The load configuration table address and size.
    pub load_config_table: ImageDataDirectory,
    /// The bound import table address and size.
    pub bound_import: ImageDataDirectory,
    /// The import address table address and size.
    pub ita: ImageDataDirectory,
    /// The delay import descriptor address and size.
    pub delay_import_descriptor: ImageDataDirectory,
    /// The CLR runtime header address and sizeclr_runtime.
    pub clr_runtime_header: ImageDataDirectory,
    /// Reserved, must be zero.
    pub reserved: ImageDataDirectory,
}

impl DataDirectories {
    pub fn get_directory(&self, name: SectionName) -> ImageDataDirectory {
        match name {
            SectionName::ExportTable => self.export_table,
            SectionName::ImportTable => self.import_table,
            SectionName::ResourceTable => self.resource_table,
            SectionName::ExceptionTable => self.exception_table,
            SectionName::CertificateTable => self.certificate_table,
            SectionName::BaseRelocationTable => self.base_relocation_table,
            SectionName::Debug => self.debug,
            SectionName::Architecture => self.architecture,
            SectionName::GlobalPtr => self.global_ptr,
            SectionName::TlsTable => self.tls_table,
            SectionName::LoadConfigTable => self.load_config_table,
            SectionName::BoundImport => self.bound_import,
            SectionName::Ita => self.ita,
            SectionName::DelayImportDescriptor => self.delay_import_descriptor,
            SectionName::ClrRuntimeHeader => self.clr_runtime_header,
            SectionName::Reserved => self.reserved,
        }
    }

    pub fn set_directory(&mut self, name: SectionName, data: ImageDataDirectory) {
        match name {
            SectionName::ExportTable => self.export_table = data,
            SectionName::ImportTable => self.import_table = data,
            SectionName::ResourceTable => self.resource_table = data,
            SectionName::ExceptionTable => self.exception_table = data,
            SectionName::CertificateTable => self.certificate_table = data,
            SectionName::BaseRelocationTable => self.base_relocation_table = data,
            SectionName::Debug => self.debug = data,
            SectionName::Architecture => self.architecture = data,
            SectionName::GlobalPtr => self.global_ptr = data,
            SectionName::TlsTable => self.tls_table = data,
            SectionName::LoadConfigTable => self.load_config_table = data,
            SectionName::BoundImport => self.bound_import = data,
            SectionName::Ita => self.ita = data,
            SectionName::DelayImportDescriptor => self.delay_import_descriptor = data,
            SectionName::ClrRuntimeHeader => self.clr_runtime_header = data,
            SectionName::Reserved => self.reserved = data,
        }
    }
}

/// Each data directory gives the address and size of a table or string that Windows uses.
/// These data directory entries are all loaded into memory so that the system can use them at run time.
/// A data directory is an 8-byte field that has the following declaration:
#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub struct ImageDataDirectory {
    /// The RVA of the table.
    ///
    /// The RVA is the address of the table relative to the base address of the image when the table is loaded.
    pub virtual_address: u32,
    /// Size in bytes.
    pub size: u32,
}

impl ImageDataDirectory {
    pub const SIZE: usize = 8;
}

impl ReadData for ImageDataDirectory {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            virtual_address: reader.read()?,
            size: reader.read()?,
        })
    }
}

impl WriteData for ImageDataDirectory {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.virtual_address)?;
        writer.write(self.size)?;
        Ok(())
    }
}
