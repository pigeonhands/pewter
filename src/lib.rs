#![no_std]

#[cfg(feature="std")]
mod alloc_containers {
    pub extern crate std;
    pub use std::{vec, string, error};
}
#[cfg(not(feature="std"))]
mod alloc_containers {
    extern crate alloc;
    pub use alloc::{vec, string};
}

pub (crate) use alloc_containers::*;



pub mod containers;
pub mod error;
pub mod io;
pub mod pe;

pub use pe::{options::Options, PEFile, PEImage};
