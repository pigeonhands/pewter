use std::{env, path::{PathBuf}};

use pewter::pe::{PEFile, definition::PEImageDef, sections::{SectionFlags}, optional_header::data_directories::ImageDataDirectory};

fn main() {
    let mut args = env::args();

    let mut current_exec = PathBuf::from(args.next().unwrap());
    current_exec.set_file_name("simple.exe");
    let arg = args.next().unwrap_or_default();

    let data = std::fs::read(&current_exec).unwrap();

    let pe = PEFile::parse(&data).unwrap();

    if &arg == "patch" {
        let mut def = PEImageDef::from_pe_file(pe);
       
        let dotnet_vaddr = {
            let new_section = def.new_section(".net", SectionFlags::MEM_READ | SectionFlags::CNT_INITIALIZED_DATA);
            new_section.virtual_size = 0x1000;
            new_section.add_data(&[1,2,3,4,5])
        };
         
        def.optional_header.data_directories.clr_runtime_header = ImageDataDirectory {
            virtual_address: dotnet_vaddr as u32,
            size: 6,
        };  
        
        let pacthed_data = def.write_file().unwrap();

        let pe = PEFile::parse(&pacthed_data).unwrap();
       println!("{:#?}", pe);

       current_exec.set_extension("patched-no-section.exe");
       //std::fs::write(&current_exec, &pacthed_data).unwrap();
       println!("Patched self {}", current_exec.display());


    }else{
        println!("{:#?}", pe);
        println!("Loaded self (did not patch)")
    }

    // if let Some(optional_header) = &pe.optional_header {
    //     let section = pe
    //         .section_table
    //         .find_rva(optional_header.data_directories.import_table.virtual_address as usize)
    //         .unwrap();
    //     println!("Import table is in {} section", section.name_str());
    // }

}
