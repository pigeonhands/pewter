//! The .edata Section (Image Only)
//!
//! The export data section, named .edata, contains information about symbols
//! that other images can access through dynamic linking. Exported symbols are
//! generally found in DLLs, but DLLs can also import symbols.

use crate::{
    containers::Table,
    error::{PewterError, Result},
    image::Export,
    vec,
    io::{ReadData, WriteData, Writer},
    pe::{
        coff::CoffFileHeader,
        optional_header::{data_directories::ImageDataDirectory, OptionalHeader},
    },
};

use super::ParseSectionData;

use crate::{string::String, vec::Vec};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportTableDataDirectory {
    /// The export directory table contains address information that is used to resolve
    /// imports to the entry points within this image.
    pub export_directory_table: ExportDirectory,
    /// The export address table contains the address of exported entry points and exported data and absolutes.
    /// An ordinal number is used as an index into the export address table.
    pub export_address_table: Table<ExportAddress>,
    /// The export name pointer table is an array of addresses (RVAs) into the export name table.
    /// The pointers are 32 bits each and are relative to the image base. The pointers are ordered lexically
    /// to allow binary searches.
    pub name_pointer_table: Table<ExportNamePointer>,
    /// An array of the ordinals that correspond to members of the name pointer table.
    /// The correspondence is by position; therefore, the name pointer table and the ordinal
    /// table must have the same number of members. Each ordinal is an index into the export address table.
    pub export_ordinal_table: Table<ExportOrtinal>,
    // The export name table contains the actual string data that was pointed to by the export name pointer table.
    // The strings in this table are public names that other images can use to import the symbols.
    // These public export names are not necessarily the same as the private symbol names that the symbols have
    // in their own image file and source code, although they can be.
    pub export_name_table: Table<String>,
    /// The name of the DLL, from [`ExportDirectory::name_rva`].
    pub dll_name: String,
}

impl ParseSectionData for ExportTableDataDirectory {
    fn parse(
        section_data: &[u8],
        sections: &super::Sections,
        _: &OptionalHeader,
        _: &CoffFileHeader,
    ) -> Result<Self> {
        Self::read(section_data, |rva| sections.find_rva_data(rva as usize))
    }
}

impl ExportTableDataDirectory {
    /// Reads the export directory at the start of `directory_data`. `image_data` maps an
    /// RVA to the image bytes from there to the end of its section.
    pub fn read<'d>(
        directory_data: &[u8],
        image_data: impl Fn(u32) -> Option<&'d [u8]>,
    ) -> Result<Self> {
        let export_directory_table = ExportDirectory::read(&mut directory_data.as_ref())?;

        let rva_data = |rva: u32, what: &'static str| {
            image_data(rva).ok_or_else(|| PewterError::invalid_image_format(what))
        };

        let export_address_table = Table::new_linear(
            &mut rva_data(
                export_directory_table.export_address_table,
                "Failed to map export_address_table inside image",
            )?,
            export_directory_table.address_table_entries as usize,
        )?;

        let name_count = export_directory_table.number_of_name_pointers as usize;
        let (name_pointer_table, export_ordinal_table) = if name_count == 0 {
            (Table::new(), Table::new())
        } else {
            (
                Table::<ExportNamePointer>::new_linear(
                    &mut rva_data(
                        export_directory_table.name_pointer_rva,
                        "Failed to map name_pointer_table inside image",
                    )?,
                    name_count,
                )?,
                Table::new_linear(
                    &mut rva_data(
                        export_directory_table.ordinal_table_rva,
                        "Failed to map export_ordinal_table inside image",
                    )?,
                    name_count,
                )?,
            )
        };

        let export_name_table = Table(
            name_pointer_table
                .iter()
                .map(|ptr| {
                    rva_data(ptr.0, "Failed to map export name inside image").map(c_string)
                })
                .collect::<Result<Vec<_>>>()?,
        );

        let dll_name = match export_directory_table.name_rva {
            0 => String::new(),
            rva => c_string(rva_data(rva, "Failed to map export dll name inside image")?),
        };

        Ok(Self {
            export_address_table,
            name_pointer_table,
            export_ordinal_table,
            export_name_table,
            dll_name,
            export_directory_table,
        })
    }
}

/// What an exported symbol resolves to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportTarget {
    /// The RVA of code or data in this image. Zero marks an unused ordinal.
    Rva(u32),
    /// A symbol in another DLL, as `"OtherDll.Name"` or `"OtherDll.#27"`.
    Forwarder(String),
}

/// One entry of the export address table. Its ordinal is its position plus the ordinal base.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExportDef {
    /// Leave as `None` to export by ordinal only.
    pub name: Option<String>,
    pub target: ExportTarget,
}

impl ExportDef {
    pub fn rva(name: impl Into<String>, rva: u32) -> Self {
        Self {
            name: Some(name.into()),
            target: ExportTarget::Rva(rva),
        }
    }

    pub fn forwarder(name: impl Into<String>, forwarder: impl Into<String>) -> Self {
        Self {
            name: Some(name.into()),
            target: ExportTarget::Forwarder(forwarder.into()),
        }
    }
}

/// Serializes an export directory, with its tables and strings, for placement at `rva`.
///
/// Forwarder strings are placed inside the returned data, so the export table data
/// directory must cover all of it for loaders to recognise them.
pub fn build_export_data(
    rva: u32,
    dll_name: &str,
    ordinal_base: u32,
    exports: &[ExportDef],
) -> Result<Vec<u8>> {
    const DIRECTORY_SIZE: usize = 40;

    if dll_name.is_empty() || dll_name.contains('\0') {
        return Err(PewterError::invalid_image_format("Invalid export dll name"));
    }
    if exports.len() > u16::MAX as usize + 1 {
        return Err(PewterError::invalid_image_format(
            "Too many exports for the ordinal table",
        ));
    }
    for export in exports {
        if let ExportTarget::Forwarder(forwarder) = &export.target {
            let valid = forwarder
                .split_once('.')
                .is_some_and(|(dll, name)| !dll.is_empty() && !name.is_empty())
                && !forwarder.contains('\0');
            if !valid {
                return Err(PewterError::invalid_image_format(
                    "Export forwarder must look like OtherDll.Name",
                ));
            }
        }
    }

    // The name pointer table is sorted lexically so loaders can binary search it.
    let mut named: Vec<(&str, u16)> = exports
        .iter()
        .enumerate()
        .filter_map(|(i, e)| Some((e.name.as_deref()?, i as u16)))
        .collect();
    named.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if named
        .iter()
        .any(|(name, _)| name.is_empty() || name.contains('\0'))
    {
        return Err(PewterError::invalid_image_format("Invalid export name"));
    }
    if named.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err(PewterError::invalid_image_format("Duplicate export name"));
    }

    let address_table = DIRECTORY_SIZE;
    let name_pointers = address_table + 4 * exports.len();
    let ordinals = name_pointers + 4 * named.len();
    let strings = ordinals + 2 * named.len();

    let mut string_data = Vec::new();
    let mut add_string = |s: &str| -> Result<u32> {
        let offset = strings + string_data.len();
        string_data.extend_from_slice(s.as_bytes());
        string_data.push(0);
        u32::try_from(offset)
            .ok()
            .and_then(|offset| rva.checked_add(offset))
            .ok_or_else(|| {
                PewterError::invalid_image_format("Export table does not fit in the image")
            })
    };

    let name_rva = add_string(dll_name)?;
    let name_rvas = named
        .iter()
        .map(|(name, _)| add_string(name))
        .collect::<Result<Vec<_>>>()?;
    let addresses = exports
        .iter()
        .map(|e| match &e.target {
            ExportTarget::Rva(rva) => Ok(*rva),
            ExportTarget::Forwarder(forwarder) => add_string(forwarder),
        })
        .collect::<Result<Vec<_>>>()?;

    let mut data = Vec::with_capacity(strings + string_data.len());
    data.write(ExportDirectory {
        name_rva,
        ordinal_base,
        address_table_entries: exports.len() as u32,
        number_of_name_pointers: named.len() as u32,
        export_address_table: rva + address_table as u32,
        name_pointer_rva: rva + name_pointers as u32,
        ordinal_table_rva: rva + ordinals as u32,
        ..Default::default()
    })?;
    for address in addresses {
        data.write(ExportAddress(address))?;
    }
    for name_rva in name_rvas {
        data.write(ExportNamePointer(name_rva))?;
    }
    for (_, ordinal) in &named {
        data.write(ExportOrtinal(*ordinal))?;
    }
    data.write_slice(&string_data)?;
    Ok(data)
}

/// Export definitions for `exports`, with `target` choosing what each resolves to in
/// the new table, or `None` to leave it out. Returns the ordinal base to build them with.
///
/// Return [`ExportTarget::Forwarder`] to forward an export to another module (see
/// [`Export::forwarder_in`]), or [`ExportTarget::Rva`] to point it at a method written
/// into this image instead, such as a hook. The source `exports` may come from a PE or
/// an ELF, via [`AnyImage::exports`](crate::image::LoadedImage::exports).
///
/// Exports with an ordinal keep it; a name sharing an ordinal with an earlier one, and
/// exports without an ordinal (such as ELF symbols), get new ordinals after the rest.
/// Exports with neither a name nor an ordinal are skipped.
pub fn forward_exports(
    exports: &[Export],
    mut target: impl FnMut(&Export) -> Option<ExportTarget>,
) -> (u32, Vec<ExportDef>) {
    let ordinal_base = exports.iter().filter_map(|e| e.ordinal).min().unwrap_or(1);
    let slots = exports
        .iter()
        .filter_map(|e| Some(e.ordinal? - ordinal_base + 1))
        .max()
        .unwrap_or(0) as usize;
    let mut defs: Vec<ExportDef> = (0..slots)
        .map(|_| ExportDef {
            name: None,
            target: ExportTarget::Rva(0),
        })
        .collect();
    let mut filled = vec![false; slots];

    let mut extra = Vec::new();
    for export in exports {
        if export.name.is_none() && export.ordinal.is_none() {
            continue;
        }
        let Some(target) = target(export) else {
            continue;
        };
        let def = ExportDef {
            name: export.name.clone(),
            target,
        };
        match export.ordinal.map(|o| (o - ordinal_base) as usize) {
            Some(slot) if !filled[slot] => {
                defs[slot] = def;
                filled[slot] = true;
            }
            _ => extra.push(def),
        }
    }
    defs.append(&mut extra);
    (ordinal_base, defs)
}

/// [`forward_exports`] with every export forwarded to the same symbol in `module`, a
/// module name without its `.dll` extension. See [`Export::forwarder_in`].
pub fn forward_all_exports(exports: &[Export], module: &str) -> (u32, Vec<ExportDef>) {
    forward_exports(exports, |export| {
        export.forwarder_in(module).map(ExportTarget::Forwarder)
    })
}

/// A null-terminated ASCII string at the start of `data`.
fn c_string(data: &[u8]) -> String {
    let end = data.iter().position(|c| *c == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into()
}

/// The export symbol information begins with the export directory table,
/// which describes the remainder of the export symbol information.
/// The export directory table contains address information that is used to
/// resolve imports to the entry points within this image.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportDirectory {
    /// Reserved, must be 0.
    pub export_flags: u32,
    /// The time and date that the export data was created.
    pub time_date_stamp: u32,
    /// The major version number. The major and minor version numbers can be set by the user.
    pub major_version: u16,
    /// The minor version number.
    pub minor_version: u16,
    /// The address of the ASCII string that contains the name of the DLL.
    /// This address is relative to the image base.
    pub name_rva: u32,
    /// The starting ordinal number for exports in this image. This field specifies the starting
    /// ordinal number for the export address table. It is usually set to 1.
    pub ordinal_base: u32,
    /// The number of entries in the export address table.
    pub address_table_entries: u32,
    /// The number of entries in the name pointer table.
    /// This is also the number of entries in the ordinal table.
    pub number_of_name_pointers: u32,
    /// The address of the export address table, relative to the image base.
    pub export_address_table: u32,
    /// The address of the export name pointer table, relative to the image base.
    /// The table size is given by the Number of Name Pointers field.
    pub name_pointer_rva: u32,
    /// The address of the ordinal table, relative to the image base.
    pub ordinal_table_rva: u32,
}

impl ReadData for ExportDirectory {
    fn read(reader: &mut impl crate::io::Reader) -> Result<Self> {
        Ok(Self {
            export_flags: reader.read()?,
            time_date_stamp: reader.read()?,
            major_version: reader.read()?,
            minor_version: reader.read()?,
            name_rva: reader.read()?,
            ordinal_base: reader.read()?,
            address_table_entries: reader.read()?,
            number_of_name_pointers: reader.read()?,
            export_address_table: reader.read()?,
            name_pointer_rva: reader.read()?,
            ordinal_table_rva: reader.read()?,
        })
    }
}

impl WriteData for ExportDirectory {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> Result<()> {
        writer.write(self.export_flags)?;
        writer.write(self.time_date_stamp)?;
        writer.write(self.major_version)?;
        writer.write(self.minor_version)?;
        writer.write(self.name_rva)?;
        writer.write(self.ordinal_base)?;
        writer.write(self.address_table_entries)?;
        writer.write(self.number_of_name_pointers)?;
        writer.write(self.export_address_table)?;
        writer.write(self.name_pointer_rva)?;
        writer.write(self.ordinal_table_rva)?;
        Ok(())
    }
}

/// Each entry in the export address table is a field that uses one of two formats in the following table.
/// If the address specified is not within the export section (as defined by the address and length that are
/// indicated in the optional header), the field is an export RVA, which is an actual address in code or data.
/// Otherwise, the field is a forwarder RVA, which names a symbol in another DLL.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportAddress(pub u32);

impl ExportAddress {
    /// A forwarder RVA points inside the export table data directory, at a null-terminated
    /// ASCII string in the export section. This string gives the DLL name and the name of the
    /// export (for example, "MYDLL.expfunc") or the DLL name and the ordinal number of the
    /// export (for example, "MYDLL.#27").
    ///
    /// See [DataDirectories::export_table](crate::pe::optional_header::data_directories::DataDirectories::export_table)
    pub fn is_forwarder(&self, export_table: &ImageDataDirectory) -> bool {
        self.0 >= export_table.virtual_address
            && self.0 - export_table.virtual_address < export_table.size
    }
}

impl ReadData for ExportAddress {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self(reader.read()?))
    }
}

impl WriteData for ExportAddress {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.0)?;
        Ok(())
    }
}

/// Pointer into the export name table.
/// An export name is defined only if the export name pointer table contains a pointer to it.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportNamePointer(pub u32);

impl ReadData for ExportNamePointer {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self(reader.read()?))
    }
}

impl WriteData for ExportNamePointer {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.0)?;
        Ok(())
    }
}

/// Index into the export address table. Ordinals are biased by the Ordinal Base field of the export directory table.
/// In other words, the ordinal base must be subtracted from the ordinals to obtain true indexes into the export address table.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportOrtinal(pub u16);

impl ReadData for ExportOrtinal {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self(reader.read()?))
    }
}

impl WriteData for ExportOrtinal {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.0)?;
        Ok(())
    }
}

/// Every exported symbol has an ordinal value, which is just the index into the export address table.
/// Use of export names, however, is optional. Some, all, or none of the exported symbols can have export names.
/// For exported symbols that do have export names, corresponding entries in the export name pointer table and
/// export ordinal table work together to associate each name with an ordinal.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ExportName(pub u16);

impl ReadData for ExportName {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self(reader.read()?))
    }
}

impl WriteData for ExportName {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.0)?;
        Ok(())
    }
}
