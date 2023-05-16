use std::env;

use pewter::pe::PEFile;

fn main() {
    let current_exec = env::args().next().unwrap();
    //let current_exec = r#""C:\re\dnspy\bin\dnlib.dll"#;

    let data = std::fs::read(&current_exec).unwrap();

    let _pe = PEFile::parse(&data).unwrap();

    // if let Some(optional_header) = &pe.optional_header {
    //     let section = pe
    //         .section_table
    //         .find_rva(optional_header.data_directories.import_table.virtual_address as usize)
    //         .unwrap();
    //     println!("Import table is in {} section", section.name_str());
    // }

    println!("Loaded {}", current_exec);
}
