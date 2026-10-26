pewter
=======

<!-- [![Actions][actions-badge]][actions-url] -->

[![github-badge]][github-link]
[![crates-pewter-badge]][crates-pewter]
[![docs][docs-pewter-badge]][docs-pewter]
![License][license-badge]

[license-badge]:https://img.shields.io/crates/l/pewter.svg?style=for-the-badge
[github-badge]: https://img.shields.io/badge/github-pigeonhands/pewter-8da0cb?style=for-the-badge&labelColor=555555&logo=github
[github-link]: https://github.com/pigeonhands/pewter
[actions-badge]: https://img.shields.io/github/actions/workflow/status/pigeonhands/pewter/ci.yml?branch=master&style=for-the-badge
[actions-url]: https://github.com/pigeonhands/pewter/actions
[crates-pewter-badge]: https://img.shields.io/crates/v/pewter.svg?style=for-the-badge&color=fc8d62&logo=rust
[crates-pewter]: https://crates.io/crates/pewter
[docs-pewter-badge]: https://img.shields.io/badge/docs.rs-pewter-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
[docs-pewter]: https://docs.rs/pewter


-----
A library for reading and writing PE files, and reading ELF files.

The documentation for this code is directly from [Microsofts pe-format documentation](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
## Writing

`PEImageDef` is an owned, editable copy of an image. Writing an unmodified image produces the
original bytes. The DOS stub, COFF fields, section order and overlay data are kept.

```rust
use pewter::pe::{definition::PEImageDef, sections::SectionFlags};

let data = std::fs::read("app.exe")?;
let mut image = PEImageDef::parse(&data)?;

let rva = image
    .new_section(".extra", SectionFlags::CNT_INITIALIZED_DATA | SectionFlags::MEM_READ)
    .add_data(b"hello");
image.write_at_rva(rva as u32, b"HELLO")?;

std::fs::write("app.patched.exe", image.write_file()?)?;
```

`write_file` recalculates the header sizes, section offsets and checksum. Images with a section
alignment below the page size (e.g. crossgen output) keep their file offsets congruent to their
RVAs so they can still be mapped directly.

## ELF

`pewter::elf` reads 32 and 64 bit ELF files of either byte order: the header, program headers
(segments), sections, symbols from `.symtab` and `.dynsym`, and relocations.

```rust
use pewter::elf::ElfFile;

let data = std::fs::read("libfoo.so")?;
let elf = ElfFile::parse(&data)?;

let init = elf.find_symbol("foo_init")?.expect("exported");
let code = elf.data_at_vaddr(init.value);

// Pointers in position independent code are filled in by relocations at load time.
let pointers = elf.relocated_pointers()?;
let target = elf.read_pointer(0x1234, &pointers);
```

Virtual addresses are mapped to file offsets through the `PT_LOAD` segments
(`vaddr_to_offset` / `offset_to_vaddr`). Writing ELF files isn't supported.

## Tests

The tests use files already on the machine and skip what isn't there: the installed .NET
framework DLLs for PE (or `PEWTER_TEST_PE`), the system `libc` for ELF, and `PEWTER_TEST_ELF`
for an Il2Cpp `GameAssembly.so`.
