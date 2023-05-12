//! The .reloc Section (Image Only)
//! The base relocation table contains entries for all base relocations in the image. 
//! The Base Relocation Table field in the optional header data directories gives the number of bytes in the base relocation table. 
//! For more information, see Optional Header Data Directories (Image Only). 
//! The base relocation table is divided into blocks. Each block represents the base relocations for a 4K page. 
//! Each block must start on a 32-bit boundary.

use crate::{io::{ReadData, WriteData}, containers::Table, error::{Result, PewterError}};

//#[derive(Default, Clone, Debug, PartialEq, Eq)]
//pub struct BaseRelocationDataDitectory {
//}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct BaseRelocationBlockHeader {
    /// The image base plus the page RVA is added to each offset to create the VA where the base relocation must be applied. 
    pub base_rva: u32,
    /// The total number of bytes in the base relocation block, including the Page RVA and Block Size fields and the Type/Offset fields that follow. 
    pub block_size: u32,
    /// The Block Size field is then followed by any number of Type or Offset field entries. 
    /// Each entry is a WORD (2 bytes) and has the following structure:
    pub table: Table<BaseRelocationBlockOffsets>
}

impl ReadData for BaseRelocationBlockHeader {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            base_rva: reader.read()?,
            block_size: reader.read()?,
            table: Table::new()
        })
    }
}

impl WriteData for BaseRelocationBlockHeader {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.base_rva)?;
        writer.write(self.block_size)?;
        Ok(())
    }
}

#[derive(Default, Copy, Clone, Debug, PartialEq, Eq)]
pub enum BaseRelocationType {
    /// The base relocation is skipped. This type can be used to pad a block. 
    #[default]
    Absolute = 0,
    /// The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. 
    /// The 16-bit field represents the high value of a 32-bit word. 
    High = 1,
    /// The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. 
    /// The 16-bit field represents the low half of a 32-bit word. 
    Low = 2,
    /// The base relocation applies all 32 bits of the difference to the 32-bit field at offset. 
    HighLow = 3,
    /// The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. 
    /// The 16-bit field represents the high value of a 32-bit word. The low 16 bits of the 32-bit value are stored 
    /// in the 16-bit word that follows this base relocation. This means that this base relocation occupies two slots. 
    HighAdj = 4,
    /// The relocation interpretation is dependent on the machine type. 
    /// 
    ///  When the machine type is MIPS, the base relocation applies to a MIPS jump instruction. 
    /// 
    /// When the machine is ARM or Thumb. 
    /// The base relocation applies the 32-bit address of a symbol across a consecutive MOVW/MOVT instruction pair. 
    /// 
    /// When the machine type is RISC-V. The base relocation applies to the high 20 bits of a 32-bit absolute address. 
    MipsJmpAddrOrArmMove32OrRscvHigh20 = 5,
    /// Reserved, must be zero. 
    Reserved = 6,
    /// When the machine type is Thumb, Tye base relocation applies the 32-bit address of a symbol to a consecutive MOVW/MOVT instruction pair.
    /// 
    ///  When the machine type is RISC-V, the base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V I-type instruction format. 
    ThumbMov32OrRiscVLow121 = 7,
    /// When the machine type is RISC-V, the base relocation applies to the low 12 bits of a 32-bit absolute address formed in RISC-V S-type instruction format. 
    /// 
    /// When the machine type is LoongArch 32-bit, the base relocation applies to a 32-bit absolute address formed in two consecutive instructions. 
    RiscVLow125OtLoongArch32or64MarkLa = 8,
    /// The relocation is only meaningful when the machine type is MIPS. The base relocation applies to a MIPS16 jump instruction. 
    MipsJmpAddr16 = 9,
    /// The base relocation applies the difference to the 64-bit field at offset. 
    Dir64 = 10,
}

impl BaseRelocationType {
    pub fn from_u8(value: u8) -> Result<Self> {
        let reloc_type = match value {
            0 => Self::Absolute,
            1 => Self::High,
            2 => Self::Low,
            3 => Self::HighLow,
            4 => Self::HighAdj,
            5 => Self::MipsJmpAddrOrArmMove32OrRscvHigh20,
            6 => Self::Reserved,
            7 => Self::ThumbMov32OrRiscVLow121,
            8 => Self::RiscVLow125OtLoongArch32or64MarkLa,
            9 => Self::MipsJmpAddr16,
            10 => Self::Dir64,
            _ => return Err(PewterError::invalid_image_format("Invalid base relcation type.."))
        };
        Ok(reloc_type)
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct BaseRelocationBlockOffsets {
    /// Stored in the high 4 bits of the WORD, a value that indicates the type of base relocation to be applied. 
    pub relocation_type: BaseRelocationType
}