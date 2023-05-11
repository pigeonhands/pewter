use std::{env, path::PathBuf};

use pewter::pe::{PEFile};

fn main() {
    let current_exec = PathBuf::from(env::args().next().unwrap());

    let mut data = std::fs::read(&current_exec).unwrap();

    let mut pe_file = PEFile::parse_minimal(&data).unwrap();

    if let Some(optional_header) = &mut pe_file.optional_header {
        optional_header.data_directories.debug = Default::default();
    }

    pe_file.patch(&mut data).unwrap();
    let patched_pe_file = PEFile::parse_minimal(&data).unwrap();

    assert_eq!(
        patched_pe_file,
        pe_file
    );

    //current_exec.set_extension("patched.exe");
    //std::fs::write(&current_exec, &data).unwrap();

    // println!("Patched! saved to {}", current_exec.display());
}
