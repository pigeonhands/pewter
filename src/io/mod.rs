pub mod stream;
use core::{mem::MaybeUninit};

use crate::error::{Result, PerwError};


pub trait Reader: Sized {
    fn read_slice(&mut self, size: usize) -> Result<&[u8]>;
    #[inline(always)]
    fn read<T: ReadData>(&mut self) -> Result<T>{
        T::read_from(self)
    }
}

pub trait Writer: Sized {
    fn write_slice(&mut self, data: &[u8]) -> Result<()>;
    #[inline(always)]
    fn write<T: WriteData>(&mut self, value: T) -> Result<()> {
        T::write_to(&value, self)
    }
}

impl<'a> Reader for &'a [u8] {
    #[inline(always)]
    fn read_slice(&mut self, size: usize) -> Result<&'a [u8]> {
        let (data, remaining) = self.split_at(size);
        *self = remaining;
        Ok(data)
    }
}

impl<'a> Writer for &'a mut [u8] {
    #[inline(always)]
    fn write_slice(&mut self, data: &[u8]) -> Result<()> {
        let this = core::mem::take(self);
        let (write_buffer, remaining) = this.split_at_mut(data.len());
        *self = remaining;
        write_buffer.copy_from_slice(data);
        Ok(())
    }
} 

pub trait ReadData: Sized {
    fn read_from(reader: &mut impl Reader) -> Result<Self>;
}

pub trait WriteData {
    fn write_to(&self, writer: &mut impl Writer) -> Result<()>;
}

impl ReadData for () {
    fn read_from(_: &mut impl Reader) -> Result<Self> {
        Ok(())
    }
}

impl WriteData for () {
    fn write_to(&self, _: &mut impl Writer) -> Result<()> {
        Ok(())
    }
}

impl<const N: usize> ReadData for [u8;N] {
    fn read_from(reader: &mut impl Reader) -> Result<Self> {
        reader.read_slice(N)?
            .try_into()
            .map_err(|_| PerwError::not_enough_data(N))
    }
}
impl<const N: usize> WriteData for [u8;N] {
    fn write_to(&self, writer: &mut impl Writer) -> Result<()> {
        writer.write_slice(self)
    }
}

impl<const N: usize> ReadData for [u16;N] {
    fn read_from(reader: &mut impl Reader) -> Result<Self> {
        let mut buffer : [MaybeUninit<u16>;N] = unsafe { MaybeUninit::uninit().assume_init() };

        for elem in buffer.iter_mut() {
            elem.write(reader.read()?);
        }
        Ok(unsafe { *buffer.as_ptr().cast() })
    }
}
impl<const N: usize> WriteData for [u16;N] {
    fn write_to(&self, writer: &mut impl Writer) -> Result<()> {
        for v in self.iter() {
            writer.write(*v)?;
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
    fn read_from(reader: &mut impl Reader) -> Result<Self> {
        reader.read_slice(1).map(|m| m[0])
    }
}

impl WriteData for u8 {
    fn write_to(&self, writer: &mut impl Writer) -> Result<()> {
        writer.write_slice(&[*self])
    }
}

macro_rules! impl_read_write_data {
    ($($t:ty),+) => {
        $(
            impl ReadData for $t {
                #[inline(always)]
                fn read_from(reader: &mut impl Reader) -> Result<$t> {
                    let data = reader.read();
                    data.map(<$t>::from_le_bytes)
                }
            }

            impl WriteData for $t {
                #[inline(always)]
                fn write_to(&self, writer: &mut impl Writer) -> Result<()> {
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
