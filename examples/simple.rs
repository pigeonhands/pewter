use std::env;

use pewter::pe::PEFile;

fn main() {
    let current_exec = env::args().next().unwrap();

    let data = std::fs::read(&current_exec).unwrap();
    let pe: PEFile = PEFile::from_bytes(&data).unwrap();

    println!("{:#?}", pe);
    println!("Loaded {}", current_exec);

}
