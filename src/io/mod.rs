pub mod stream;
use core::mem::MaybeUninit;

use crate::error::{PewterError, Result};

pub trait Reader: Sized {
    fn read_slice(&mut self, size: usize) -> Result<&[u8]>;
    #[inline(always)]
    fn read<T: ReadData>(&mut self) -> Result<T> {
        T::read(self)
    }
}

pub trait Writer: Sized {
    fn write_slice(&mut self, data: &[u8]) -> Result<()>;
    #[inline(always)]
    fn write<T: WriteData>(&mut self, value: T) -> Result<()> {
        T::write_to(value, self)
    }
}

impl<'a> Reader for &'a [u8] {
    #[inline(always)]
    fn read_slice(&mut self, size: usize) -> Result<&'a [u8]> {
        if self.len() < size {
            return Err(PewterError::not_enough_data(size));
        }
        let (data, remaining) = self.split_at(size);
        *self = remaining;
        Ok(data)
    }
}

impl<'a> Writer for &'a mut [u8] {
    #[inline(always)]
    fn write_slice(&mut self, data: &[u8]) -> Result<()> {
        if self.len() < data.len() {
            return Err(PewterError::not_enough_space(data.len()));
        }
        let this = core::mem::take(self);
        let (write_buffer, remaining) = this.split_at_mut(data.len());
        *self = remaining;
        write_buffer.copy_from_slice(data);
        Ok(())
    }
}

impl<'a> Writer for crate::vec::Vec<u8> {
    #[inline(always)]
    fn write_slice(&mut self, data: &[u8]) -> Result<()> {
        self.extend_from_slice(data);
        Ok(())
    }
}

pub trait ReadData: Sized {
    fn read(reader: &mut impl Reader) -> Result<Self>;
}

pub trait WriteData {
    fn write_to(self, writer: &mut impl Writer) -> Result<()>;
}

impl<const N: usize> ReadData for [u8; N] {
    #[cfg_attr(feature = "fast-rw", inline(always))]
    fn read(reader: &mut impl Reader) -> Result<Self> {
        if cfg!(feature = "fast-rw") {
            let slice = reader.read_slice(N)?;
            unsafe { Ok(*slice.as_ptr().cast()) }
        } else {
            reader
                .read_slice(N)?
                .try_into()
                .map_err(|_| PewterError::not_enough_data(N))
        }
    }
}

impl<const N: usize> WriteData for [u8; N] {
    fn write_to(self, writer: &mut impl Writer) -> Result<()> {
        writer.write_slice(&self)
    }
}

impl<const N: usize> ReadData for [u16; N] {
    #[cfg_attr(all(target_endian = "little", feature = "fast-rw"), inline(always))]
    fn read(reader: &mut impl Reader) -> Result<Self> {
        let mut read_buffer = reader.read_slice(core::mem::size_of::<u16>() * N)?;

        if cfg!(all(target_endian = "little", feature = "fast-rw")) {
            Ok(unsafe { *read_buffer.as_ptr().cast() })
        } else {
            let mut write_buffer: [MaybeUninit<u16>; N] =
                unsafe { MaybeUninit::uninit().assume_init() };
            let read_ptr = &mut read_buffer;

            for elem in write_buffer.iter_mut() {
                elem.write(u16::read(read_ptr)?);
            }

            Ok(unsafe { *write_buffer.as_ptr().cast() })
        }
    }
}
impl<const N: usize> WriteData for [u16; N] {
    #[cfg_attr(all(target_endian = "little", feature = "fast-rw"), inline(always))]
    fn write_to(self, writer: &mut impl Writer) -> Result<()> {
        if cfg!(all(target_endian = "little", feature = "fast-rw")) {
            let data_ptr: *const u8 = self.as_ptr().cast();
            let data_slice = unsafe { core::slice::from_raw_parts(data_ptr, N * 2) };
            writer.write_slice(data_slice)?;
        } else {
            for v in self.iter() {
                writer.write(*v)?;
            }
        }

        Ok(())
    }
}

/*


impl<const N: usize, T> ReadData for [T;N]
where T: ReadData + Copy {
    fn read_from(reader: &mut impl Reader) -> Result<Self> {
        let mut buffer : [MaybeUninit<T>;N] = unsafe { MaybeUninit::uninit().assume_init() };

        for elem in buffer.iter_mut() {
            elem.write(reader.read()?);
        }
        Ok(unsafe { *buffer.as_ptr().cast() })
    }
}

impl<const N: usize, T> WriteData for [T;N]
where
T: WriteData + Copy {
    #[inline]
    fn write_to(&self, writer: &mut impl Writer) -> Result<()> {
        for v in self.iter() {
            writer.write(*v)?;
        }
        Ok(())
    }
} */

impl ReadData for u8 {
    fn read(reader: &mut impl Reader) -> Result<Self> {
        reader.read_slice(1).map(|m| m[0])
    }
}

impl WriteData for u8 {
    fn write_to(self, writer: &mut impl Writer) -> Result<()> {
        writer.write_slice(&[self])
    }
}

macro_rules! impl_read_write_data {
    ($($t:ty),+) => {
        $(
            impl ReadData for $t {
                #[inline(always)]
                fn read(reader: &mut impl Reader) -> Result<$t> {
                    if cfg!(all(target_endian = "little", feature = "fast-rw")) {
                        let read_buffer = reader.read_slice(core::mem::size_of::<$t>())?;
                        Ok(unsafe { *read_buffer.as_ptr().cast() })
                    }else {
                        let data = reader.read();
                        data.map(<$t>::from_le_bytes)
                    }
                }
            }

            impl WriteData for $t {
                #[inline(always)]
                fn write_to(self, writer: &mut impl Writer) -> Result<()> {
                    let data = self.to_le_bytes();
                    writer.write(data)
                }
            }
         )*
    };
}

impl_read_write_data! {
    u16,
    u32,
    u64
}
