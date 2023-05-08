#![no_std]

pub mod io;
pub mod error;
pub mod pe;

#[cfg(feature="alloc")]
extern crate alloc;

pub struct PEFile {
    /// Magic number
    pub e_magic: [u8;2],
    /// Bytes on last page of file
    pub e_cblp: u16,
    /// Pages in file
    pub e_cp: u16,
    /// Relocations
    pub e_crlc: u16,
}