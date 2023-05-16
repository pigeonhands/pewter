use core::ops::Deref;
use core::ops::DerefMut;

use crate::vec::Vec;

use crate::error::Result;
use crate::io::ReadData;
use crate::io::Reader;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table<T>(pub Vec<T>);

impl<T> Table<T> {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }
}

impl<T: ReadData> Table<T> {
    pub fn new_linear(data_ptr: &mut &[u8], items_count: usize) -> Result<Self> {
        let mut items = Self::with_capacity(items_count);
        for _ in 0..items.capacity() {
            items.push(data_ptr.read()?);
        }
        Ok(items)
    }
}

impl<T> Table<T> {
    pub fn new_with_reader(
        data_ptr: &mut &[u8],
        items_count: usize,
        mut read_item: impl FnMut(&mut &[u8]) -> Result<T>,
    ) -> Result<Self> {
        let mut items = Self::with_capacity(items_count);
        for _ in 0..items.capacity() {
            items.push(read_item(data_ptr)?);
        }
        Ok(items)
    }
}

impl<T> Deref for Table<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> DerefMut for Table<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
