use std::env;

use pewter::pe::{PEFile};

fn main() {
    let current_exec = env::args().next().unwrap();
    //let current_exec = r#""C:\re\dnspy\bin\dnlib.dll"#;

    let data = std::fs::read(&current_exec).unwrap();


    let pe = PEFile::parse_minimal(&data).unwrap();

    println!("{:#?}", pe);
    println!("Loaded {}", current_exec);
}
