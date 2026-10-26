use crate::error::{PewterError, Result};

/// Reads fields with the file's byte order and word size.
#[derive(Clone)]
pub(crate) struct ElfReader<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) position: usize,
    pub(crate) little_endian: bool,
    pub(crate) is_64: bool,
}

impl<'a> ElfReader<'a> {
    pub(crate) fn at(&self, position: usize) -> Self {
        Self {
            position,
            ..self.clone()
        }
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self
            .data
            .get(self.position..self.position + N)
            .ok_or_else(|| PewterError::not_enough_data(N))?;
        self.position += N;
        Ok(slice.try_into().unwrap())
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.bytes::<1>().map(|b| b[0])
    }

    pub fn u16(&mut self) -> Result<u16> {
        let b = self.bytes()?;
        Ok(if self.little_endian {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.bytes()?;
        Ok(if self.little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.bytes()?;
        Ok(if self.little_endian {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }

    /// An address or offset sized for the file's class.
    pub fn word(&mut self) -> Result<u64> {
        if self.is_64 {
            self.u64()
        } else {
            self.u32().map(u64::from)
        }
    }
}
