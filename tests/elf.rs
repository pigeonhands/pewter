//! ELF tests against files installed on the machine, cross checked with `readelf` when available.

use std::process::Command;

use pewter::elf::{ElfClass, ElfFile, ElfMachine, ElfType, SectionType, SegmentType};

fn readelf(args: &[&str], path: &str) -> Option<String> {
    let output = Command::new("readelf").args(args).arg(path).output().ok()?;
    output.status.success().then(|| String::from_utf8_lossy(&output.stdout).into_owned())
}

fn check_against_readelf(path: &str) {
    let data = std::fs::read(path).unwrap();
    let elf = ElfFile::parse(&data).unwrap();

    let Some(sections) = readelf(&["-SW"], path) else {
        eprintln!("skipping readelf comparison: readelf not installed");
        return;
    };
    for section in elf.sections.iter().filter(|s| !s.name.is_empty()) {
        assert!(sections.contains(&format!(" {} ", section.name)), "{} not in readelf output", section.name);
    }

    let relocations = readelf(&["-rW"], path).unwrap();
    let relative_name = match elf.header.machine {
        ElfMachine::X86_64 => "R_X86_64_RELATIVE",
        ElfMachine::X86 => "R_386_RELATIVE",
        ElfMachine::AArch64 => "R_AARCH64_RELATIVE",
        _ => return,
    };
    let expected = relocations.lines().filter(|l| l.contains(relative_name)).count();
    let relative = elf.header.machine.relative_relocation_type().unwrap();
    let actual = elf.relocations().unwrap().iter().filter(|r| r.relocation_type == relative).count();
    assert_eq!(actual, expected, "relative relocation count for {}", path);

    let symbols = readelf(&["--dyn-syms", "-W"], path).unwrap();
    let dynamic: Vec<_> = elf.symbols().unwrap().into_iter().filter(|s| s.dynamic).collect();
    let mut checked = 0;
    for line in symbols.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(index) = fields.first().and_then(|f| f.strip_suffix(':')).and_then(|n| n.parse::<usize>().ok()) else {
            continue;
        };
        let symbol = &dynamic[index];
        assert_eq!(symbol.value, u64::from_str_radix(fields[1], 16).unwrap(), "value of {}", symbol.name);
        if !symbol.name.is_empty() {
            assert!(line.contains(&format!(" {}", symbol.name)), "{} not on line {}", symbol.name, line);
        }
        checked += 1;
    }
    assert_eq!(checked, dynamic.len());
}

#[test]
fn parses_own_test_binary() {
    let exe = std::env::current_exe().unwrap();
    let data = std::fs::read(&exe).unwrap();
    if !ElfFile::is_elf(&data) {
        eprintln!("skipping: not running on an ELF platform");
        return;
    }
    let elf = ElfFile::parse(&data).unwrap();
    assert!(elf.section_by_name(".text").is_some());
    assert!(elf.program_headers.iter().any(|p| p.segment_type == SegmentType::Load));
    let text = elf.section_by_name(".text").unwrap();
    assert_eq!(elf.vaddr_to_offset(text.header.addr), Some(text.header.offset as usize));
    assert_eq!(elf.offset_to_vaddr(text.header.offset as usize), Some(text.header.addr));
}

#[test]
fn libc_matches_readelf() {
    let path = "/usr/lib/libc.so.6";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {} not found", path);
        return;
    }
    let data = std::fs::read(path).unwrap();
    let elf = ElfFile::parse(&data).unwrap();
    assert_eq!(elf.header.file_type, ElfType::Dyn);
    assert!(elf.sections.iter().any(|s| s.header.section_type == SectionType::DynSym));
    let malloc = elf.find_symbol("malloc").unwrap().unwrap();
    assert!(malloc.is_defined() && malloc.size > 0);
    check_against_readelf(path);
}

#[test]
fn libc_32_bit() {
    let path = "/usr/lib32/libc.so.6";
    if !std::path::Path::new(path).exists() {
        eprintln!("skipping: {} not found", path);
        return;
    }
    let data = std::fs::read(path).unwrap();
    let elf = ElfFile::parse(&data).unwrap();
    assert_eq!(elf.header.class, ElfClass::Elf32);
    assert_eq!(elf.header.machine, ElfMachine::X86);
    assert!(elf.find_symbol("malloc").unwrap().is_some());
    check_against_readelf(path);
}

/// Il2Cpp game binaries rely on relocations for the pointers in their metadata tables.
#[test]
fn il2cpp_game_assembly() {
    let path = std::env::var("PEWTER_TEST_ELF")
        .unwrap_or_else(|_| "/games/SteamLibrary/steamapps/common/Megabonk/GameAssembly.so".into());
    if !std::path::Path::new(&path).exists() {
        eprintln!("skipping: set PEWTER_TEST_ELF to a GameAssembly.so");
        return;
    }
    let data = std::fs::read(&path).unwrap();
    let elf = ElfFile::parse(&data).unwrap();
    let init = elf.find_symbol("il2cpp_init").unwrap().expect("il2cpp_init export");
    assert!(init.is_defined());
    let pointers = elf.relocated_pointers().unwrap();
    assert!(!pointers.is_empty());
    let (vaddr, value) = pointers.0[pointers.len() / 2];
    assert_eq!(elf.read_pointer(vaddr, &pointers), Some(value));
    check_against_readelf(&path);
}
