//! Optional Header Data Directories (Image Only)
use crate::io::{ReadData, WriteData};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DataDirectoryName {
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
    pub const ALL_DATA_DIRECTORIES: [DataDirectoryName; 16] = [
        DataDirectoryName::ExportTable,
        DataDirectoryName::ImportTable,
        DataDirectoryName::ResourceTable,
        DataDirectoryName::ExceptionTable,
        DataDirectoryName::CertificateTable,
        DataDirectoryName::BaseRelocationTable,
        DataDirectoryName::Debug,
        DataDirectoryName::Architecture,
        DataDirectoryName::GlobalPtr,
        DataDirectoryName::TlsTable,
        DataDirectoryName::LoadConfigTable,
        DataDirectoryName::BoundImport,
        DataDirectoryName::Ita,
        DataDirectoryName::DelayImportDescriptor,
        DataDirectoryName::ClrRuntimeHeader,
        DataDirectoryName::Reserved,
    ];

    pub fn get_directory(&self, name: DataDirectoryName) -> ImageDataDirectory {
        match name {
            DataDirectoryName::ExportTable => self.export_table,
            DataDirectoryName::ImportTable => self.import_table,
            DataDirectoryName::ResourceTable => self.resource_table,
            DataDirectoryName::ExceptionTable => self.exception_table,
            DataDirectoryName::CertificateTable => self.certificate_table,
            DataDirectoryName::BaseRelocationTable => self.base_relocation_table,
            DataDirectoryName::Debug => self.debug,
            DataDirectoryName::Architecture => self.architecture,
            DataDirectoryName::GlobalPtr => self.global_ptr,
            DataDirectoryName::TlsTable => self.tls_table,
            DataDirectoryName::LoadConfigTable => self.load_config_table,
            DataDirectoryName::BoundImport => self.bound_import,
            DataDirectoryName::Ita => self.ita,
            DataDirectoryName::DelayImportDescriptor => self.delay_import_descriptor,
            DataDirectoryName::ClrRuntimeHeader => self.clr_runtime_header,
            DataDirectoryName::Reserved => self.reserved,
        }
    }

    pub fn set_directory(&mut self, name: DataDirectoryName, data: ImageDataDirectory) {
        match name {
            DataDirectoryName::ExportTable => self.export_table = data,
            DataDirectoryName::ImportTable => self.import_table = data,
            DataDirectoryName::ResourceTable => self.resource_table = data,
            DataDirectoryName::ExceptionTable => self.exception_table = data,
            DataDirectoryName::CertificateTable => self.certificate_table = data,
            DataDirectoryName::BaseRelocationTable => self.base_relocation_table = data,
            DataDirectoryName::Debug => self.debug = data,
            DataDirectoryName::Architecture => self.architecture = data,
            DataDirectoryName::GlobalPtr => self.global_ptr = data,
            DataDirectoryName::TlsTable => self.tls_table = data,
            DataDirectoryName::LoadConfigTable => self.load_config_table = data,
            DataDirectoryName::BoundImport => self.bound_import = data,
            DataDirectoryName::Ita => self.ita = data,
            DataDirectoryName::DelayImportDescriptor => self.delay_import_descriptor = data,
            DataDirectoryName::ClrRuntimeHeader => self.clr_runtime_header = data,
            DataDirectoryName::Reserved => self.reserved = data,
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
