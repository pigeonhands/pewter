use pewter::PEFile;

/// A DLL with both regular and forwarded exports, from a Wine install.
fn sample() -> Option<Vec<u8>> {
    let path = std::env::var_os("PEWTER_TEST_EXPORTS_PE")
        .map(Into::into)
        .unwrap_or_else(|| std::path::PathBuf::from("/usr/lib/wine/x86_64-windows/kernel32.dll"));
    let data = std::fs::read(&path).ok();
    if data.is_none() {
        eprintln!("skipping: set PEWTER_TEST_EXPORTS_PE or install Wine to provide a test image");
    }
    data
}

#[test]
fn export_table_is_read() {
    let Some(data) = sample() else { return };
    let pe = PEFile::parse(&data).unwrap();
    let export_dir = pe.optional_header.as_ref().unwrap().data_directories.export_table;
    let exports = pe.read_export_table().unwrap().unwrap();
    let dir = &exports.export_directory_table;

    assert!(exports.dll_name.eq_ignore_ascii_case("kernel32.dll"));
    assert_eq!(exports.export_address_table.len(), dir.address_table_entries as usize);
    assert_eq!(exports.export_name_table.len(), dir.number_of_name_pointers as usize);
    assert_eq!(exports.export_ordinal_table.len(), exports.export_name_table.len());
    assert!(exports.export_name_table.windows(2).all(|w| w[0] < w[1]));

    let lookup = |name: &str| {
        let i = exports.export_name_table.iter().position(|n| n == name)?;
        let ordinal = exports.export_ordinal_table[i].0 as usize;
        Some(&exports.export_address_table[ordinal])
    };

    let forwarded = lookup("AcquireSRWLockExclusive").unwrap();
    assert!(forwarded.is_forwarder(&export_dir));
    let target = pe.sections.find_rva_data(forwarded.0 as usize).unwrap();
    assert!(target.starts_with(b"NTDLL.RtlAcquireSRWLockExclusive\0"));

    let local = lookup("CreateFileA").unwrap();
    assert!(!local.is_forwarder(&export_dir));
    assert!(pe.sections.find_rva(local.0 as usize).is_some());
}
