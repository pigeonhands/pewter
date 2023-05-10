//! The .pdata section contains an array of function table entries that are used for exception handling.
//! It is pointed to by the exception table entry in the image data directory.
//! The entries must be sorted according to the function addresses (the first field in each structure) before being emitted into the final image.
//! The target platform determines which of the three function table entry format variations described below is used.

use crate::{
    error::Result,
    io::{ReadData, WriteData},
    pe::coff::ImageFileMachine,
};

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub enum ExceptionHandlerDataDirectory {
    #[default]
    Unsupported,
    Mips32(Mips32ExceptionHandlerTable),
    ArmPowerPCSH4WindowsCE(ArmPowerPCSH4WindowsCEExceptionHandlerTable),
    X64(X64ExceptionHandlerTable),
}

impl ExceptionHandlerDataDirectory {
    pub fn parse(section_data: &[u8], machine: ImageFileMachine) -> Result<Self> {
        // I am unsure about these matches
        let val = match machine {
            ImageFileMachine::MipsFPU | ImageFileMachine::R4000 => Self::Mips32(
                Mips32ExceptionHandlerTable::read(&mut section_data.as_ref())?,
            ),
            ImageFileMachine::Arm 
            |  ImageFileMachine::PowerPC |ImageFileMachine::PowerPCFP  => Self::ArmPowerPCSH4WindowsCE(
                ArmPowerPCSH4WindowsCEExceptionHandlerTable::read(&mut section_data.as_ref())?,
            ),
            ImageFileMachine::Arm64 | ImageFileMachine::RiscV64 | ImageFileMachine::Amd64 => Self::X64(
                X64ExceptionHandlerTable::read(&mut section_data.as_ref())?
            ),
            _ => Self::Unsupported
        };
        Ok(val)
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Mips32ExceptionHandlerTable {
    /// The VA of the corresponding function.
    pub begin_address: u32,
    /// The VA of the end of the function.
    pub end_address: u32,
    /// The pointer to the exception handler to be executed.
    pub exception_hander: u32,
    /// The pointer to additional information to be passed to the handler.
    pub data_hander: u32,
    /// The VA of the end of the function's prolog.
    pub prolog_end_address: u32,
}

impl ReadData for Mips32ExceptionHandlerTable {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            begin_address: reader.read()?,
            end_address: reader.read()?,
            exception_hander: reader.read()?,
            data_hander: reader.read()?,
            prolog_end_address: reader.read()?,
        })
    }
}

impl WriteData for Mips32ExceptionHandlerTable {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.begin_address)?;
        writer.write(self.end_address)?;
        writer.write(self.exception_hander)?;
        writer.write(self.data_hander)?;
        writer.write(self.prolog_end_address)?;
        Ok(())
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub enum ExceptionHandlerInstructionLength {
    #[default]
    Is16Bit,
    Is32Bit,
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct ArmPowerPCSH4WindowsCEExceptionHandlerTable {
    /// The VA of the corresponding function.
    pub begin_address: u32,
    /// The number of instructions in the function's prolog.
    pub prolog_length: u8,
    /// The number of instructions in the function.
    pub function_length: u32,
    /// If set, the function consists of 32-bit instructions.
    /// If clear, the function consists of 16-bit instructions.
    pub instruction_length: ExceptionHandlerInstructionLength,
    /// If set, an exception handler exists for the function.
    /// Otherwise, no exception handler exists.
    pub exception_hander_exists: bool,
}

impl ReadData for ArmPowerPCSH4WindowsCEExceptionHandlerTable {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        let begin_address: u32 = reader.read()?;
        let other_fields: u32 = reader.read()?;

        // 8 bits
        let prolog_length = ((other_fields >> 24) & 0xFF) as u8;

        // 22 bits
        let function_length = (other_fields >> 2) & 0xc34ff;

        let instruction_length = match ((other_fields >> 1) & 1) == 1 {
            true => ExceptionHandlerInstructionLength::Is32Bit,
            false => ExceptionHandlerInstructionLength::Is16Bit,
        };

        let exception_hander_exists = (other_fields & 1) == 1;

        Ok(Self {
            begin_address,
            prolog_length,
            function_length,
            instruction_length,
            exception_hander_exists,
        })
    }
}

impl WriteData for ArmPowerPCSH4WindowsCEExceptionHandlerTable {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.prolog_length)?;

        let mut other_fields = 0;
        other_fields |= (self.prolog_length as u32) << 24;
        other_fields |= (self.function_length as u32) << 2;
        other_fields |= match self.instruction_length {
            ExceptionHandlerInstructionLength::Is16Bit => 0,
            ExceptionHandlerInstructionLength::Is32Bit => 1u32 << 1,
        };
        other_fields |= self.exception_hander_exists as u32;

        writer.write(other_fields)?;
        Ok(())
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct X64ExceptionHandlerTable {
    /// The VA of the corresponding function.
    pub begin_address: u32,
    /// The RVA of the end of the function.
    pub end_address: u32,
    /// The RVA of the unwind information.
    pub unwind_infomation: u32,
}

impl ReadData for X64ExceptionHandlerTable {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        Ok(Self {
            begin_address: reader.read()?,
            end_address: reader.read()?,
            unwind_infomation: reader.read()?,
        })
    }
}

impl WriteData for X64ExceptionHandlerTable {
    fn write_to(self, writer: &mut impl crate::io::Writer) -> crate::error::Result<()> {
        writer.write(self.begin_address)?;
        writer.write(self.end_address)?;
        writer.write(self.unwind_infomation)?;
        Ok(())
    }
}
