use core::mem::MaybeUninit;

use crate::{
    error::{PewterError, Result},
    io::{Reader, Writer},
};

use crate::vec::Vec;

pub struct PEStream<T> {
    buffer: T,
    position: usize,
}

impl<T> PEStream<T> {
    pub fn new(buffer: T) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }
    pub fn set_position(&mut self, position: usize) {
        self.position = position;
    }

    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]>> Reader for PEStream<T> {
    fn read_slice(&mut self, size: usize) -> Result<&[u8]> {
        let data = self.buffer.as_ref();
        if data.len() < self.position + size {
            return Err(PewterError::not_enough_data(size));
        }
        let data_pos = self.position;
        self.position += size;
        Ok(&data[data_pos..data_pos + size])
    }
}

impl Writer for PEStream<&mut [u8]> {
    fn write_slice(&mut self, data: &[u8]) -> Result<()> {
        if self.position + data.len() > self.buffer.len() {
            return Err(PewterError::not_enough_space(data.len()));
        }
        self.buffer[self.position..self.position + data.len()].copy_from_slice(data);
        self.position += data.len();
        Ok(())
    }
}

impl Writer for PEStream<Vec<u8>> {
    fn write_slice(&mut self, data: &[u8]) -> Result<()> {


        let end_pos = self.position + data.len();
        if self.buffer.len() < end_pos {
            let mut buffer : Vec<MaybeUninit<u8>> = {
                let buffer = core::mem::take(&mut self.buffer);
                unsafe { core::mem::transmute(buffer) }
            };
            buffer.reserve(data.len() - self.buffer.capacity());
            unsafe { 
                self.buffer.set_len(end_pos);
                let buffer : Vec<u8> = core::mem::transmute(buffer);
                let _ = core::mem::replace(&mut self.buffer, buffer);
            };
        }
        self.buffer[self.position..self.position + data.len()].copy_from_slice(data);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_too_much_writing() {
        let test_data = [0u8; 10];
        let mut out_buffer = [0u8; 9];

        let mut writer = PEStream::new(out_buffer.as_mut_slice());
        assert!(writer.write(test_data).is_err());
    }

    #[test]
    fn test_too_much_reading() {
        let test_data = [0u8; 10];
        let mut reader = PEStream::new(&test_data);
        let read_resp: Result<[u8; 11]> = reader.read();
        assert!(read_resp.is_err());
    }

    #[test]
    fn test_read_write_u8() {
        let test_data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut out_buffer = [0u8; 13];

        let mut writer = PEStream::new(out_buffer.as_mut_slice());
        writer.write(test_data).unwrap();

        assert_eq!(writer.into_inner(), test_data);
    }

    #[test]
    fn test_read_write_u16() {
        let test_data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut out_buffer = [0u8; 13 * 2];

        {
            let mut writer = PEStream::new(out_buffer.as_mut_slice());
            writer.write(test_data).unwrap();
        }

        let mut reader = PEStream::new(&out_buffer);
        assert_eq!(reader.read::<[u8; 13]>().unwrap(), test_data);
    }

    #[test]
    fn test_read_write_u32() {
        let test_data = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut out_buffer = [0u8; 13 * 4];

        {
            let mut writer = PEStream::new(out_buffer.as_mut_slice());
            writer.write(test_data).unwrap();
        }

        let mut reader = PEStream::new(&out_buffer);
        assert_eq!(reader.read::<[u8; 13]>().unwrap(), test_data);
    }
}
