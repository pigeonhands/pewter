#[cfg(feature="std")]
use crate::alloc_containers::{error::Error};


pub type Result<T> = core::result::Result<T, PerwError>;

#[derive(Debug)]
pub enum PerwError {
    NotEnoughDataLeft { attempted_read: usize },
    NotEnoughSpaceLeft { attempted_write: usize },
    InvalidImageFormat { message: &'static str },
}


impl PerwError {
    #[cold]
    pub const fn not_enough_data(size: usize) -> Self {
        Self::NotEnoughDataLeft {
            attempted_read: size,
        }
    }
    #[cold]
    pub const fn not_enough_space(size: usize) -> Self {
        Self::NotEnoughSpaceLeft {
            attempted_write: size,
        }
    }
    #[cold]
    pub const fn invalid_image_format(message: &'static str) -> Self {
        Self::InvalidImageFormat { message }
    }
}

impl core::fmt::Display for PerwError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidImageFormat { message } => write!(f, "Invalid image format: {}", message),
            Self::NotEnoughDataLeft { attempted_read } => write!(f, "Attempted to read {} bytes but there was not enough data.", attempted_read),
            Self::NotEnoughSpaceLeft { attempted_write } => write!(f, "Attempted to write {} bytes but there was not enough space.", attempted_write),
        }
    }
}

#[cfg(feature="std")]
impl Error for PerwError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }

    fn cause(&self) -> Option<&dyn Error> {
        self.source()
    }
}