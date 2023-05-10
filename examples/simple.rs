use perw::pe::PEFile;
fn main() {
    env_logger::init();

    let data = std::fs::read(r#"C:\re\dnspy\bin\dnlib.dll"#).unwrap();
    let pe: PEFile = PEFile::from_bytes(&data).unwrap();
    //let pe = PE::parse(&data).unwrap();

    println!("{:#?}", pe);
}
