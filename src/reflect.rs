//! Compile-time reflection, via [`facet`], for registering pewter's types with
//! an external consumer such as a scripting runtime. Enabled by the `reflect`
//! feature.
//!
//! Every public type derives [`facet::Facet`], so a consumer never registers
//! them one by one: it starts from the shapes in [`roots`] and walks each
//! shape's fields and variants (which reference other shapes) to reach every
//! reflected type transitively.
//!
//! Two kinds of type are deliberately [opaque](facet::Type::User) — they appear
//! in the graph as sized black boxes rather than exposing their contents:
//!
//! - **bitflags** sets ([`SectionFlags`](crate::pe::sections::SectionFlags),
//!   etc.): their flag names are `const`s, which no derive can surface. Read
//!   them through [`bitflags::Flags::FLAGS`], which gives each flag's name and
//!   value.
//! - [`OptionalHeaderWindowsSpecificFields`](crate::pe::optional_header::fields::OptionalHeaderWindowsSpecificFields),
//!   whose fields are an associated type of a generic parameter.

use facet::{Facet, Shape};

use crate::{
    elf::ElfFile,
    image::AnyImage,
    pe::{file::definition::PEImageDef, PEFile},
};

/// The shapes of pewter's entry-point types. Walk each shape's fields and
/// variants to reach every reflected type in the crate.
pub fn roots() -> &'static [&'static Shape] {
    &[
        <PEFile<'static> as Facet>::SHAPE,
        <PEImageDef as Facet>::SHAPE,
        <ElfFile<'static> as Facet>::SHAPE,
        <AnyImage<'static> as Facet>::SHAPE,
    ]
}
