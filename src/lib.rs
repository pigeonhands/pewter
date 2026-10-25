#![no_std]
#![allow(clippy::useless_asref)]

#[cfg(feature = "std")]
mod alloc_containers {
    pub extern crate std;
    pub use std::{error, string, vec};
}
#[cfg(not(feature = "std"))]
mod alloc_containers {
    extern crate alloc;
    pub use alloc::{borrow, string, vec};
}

pub(crate) use alloc_containers::*;

/// The discriminant of a `#[repr($ty)]` enum with an `Other($ty)` fallback variant.
#[macro_export]
#[doc(hidden)]
macro_rules! open_enum_value {
    ($value:expr, $ty:ty) => {
        match *$value {
            Self::Other(v) => v,
            // SAFETY: primitive representation enums start with their discriminant.
            ref known => unsafe { *(known as *const Self).cast::<$ty>() },
        }
    };
}

pub mod containers;
pub mod error;
pub mod io;
pub mod pe;

pub use pe::{options::Options, PEFile};
