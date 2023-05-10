use snafu::Snafu;

pub type Result<T> = core::result::Result<T, PerwError>;

#[derive(Snafu, Debug)]
pub enum PerwError {
    #[snafu(display("Not enough data to complete read of {attempted_read} bytes"))]
    NotEnoughDataLeft { attempted_read: usize },
    #[snafu(display("Not enough space to complete write of {attempted_write} bytes"))]
    NotEnoughSpaceLeft { attempted_write: usize },
    #[snafu(display("Invalid image format. {message}"))]
    InvalidImageFormat { message: &'static str },
    #[snafu(display("unknown error"))]
    Unknown,
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
