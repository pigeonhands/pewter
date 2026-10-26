#![cfg(feature = "reflect")]
//! Confirms the `reflect` feature derives `facet::Facet` across every category
//! of public type, and that the bitflags escape hatch yields flag names.

use bitflags::Flags;
use facet::Facet;
use pewter::{
    containers::Table,
    elf::{ElfFile, Symbol},
    image::AnyImage,
    pe::{
        coff::{CoffFileHeader, ImageFileMachine},
        optional_header::{OptionalHeaderWindowsSpecificFields, Pe32Plus},
        sections::{edata::ExportDirectory, SectionFlags},
        PEFile,
    },
};

fn assert_facet<'a, T: Facet<'a>>() {}

#[test]
fn every_category_is_reflected() {
    // Plain data structs.
    assert_facet::<CoffFileHeader>();
    assert_facet::<ExportDirectory>();
    // Open enum with an `Other(u16)` fallback.
    assert_facet::<ImageFileMachine>();
    // Generic newtype.
    assert_facet::<Table<u32>>();
    // Bitflags (registered opaque).
    assert_facet::<SectionFlags>();
    // Borrowing types (facet handles the lifetime; bevy_reflect could not).
    assert_facet::<PEFile<'static>>();
    assert_facet::<ElfFile<'static>>();
    assert_facet::<Symbol<'static>>();
    assert_facet::<AnyImage<'static>>();
    // The associated-type generic, also opaque.
    assert_facet::<OptionalHeaderWindowsSpecificFields<Pe32Plus>>();
}

#[test]
fn roots_are_exposed() {
    let roots = pewter::reflect::roots();
    assert_eq!(roots.len(), 4);
    let names: Vec<&str> = roots.iter().map(|s| s.type_identifier).collect();
    assert!(names.contains(&"PEFile"));
    assert!(names.contains(&"PEImageDef"));
}

#[test]
fn bitflags_names_reachable_via_flags_trait() {
    // Opaque in facet, but names come from bitflags' own Flags trait.
    let names: Vec<&str> = SectionFlags::FLAGS.iter().map(|f| f.name()).collect();
    assert!(names.contains(&"CNT_CODE"));
    assert!(names.contains(&"MEM_EXECUTE"));
}
