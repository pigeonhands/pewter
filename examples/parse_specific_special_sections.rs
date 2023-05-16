use std::env;

use pewter::{
    pe::{options::ParseSectionFlags, PEFile},
    Options,
};

fn main() {
    let current_exec = env::args().next().unwrap();
    let data = std::fs::read(&current_exec).unwrap();

    let opt = Options {
        parse_special_sections: ParseSectionFlags::NONE,
    };

    let pe = PEFile::parse_with_options(&data, opt).unwrap();

    println!("{:#?}", pe);
    println!("Loaded {}", current_exec);
}
