//! The Attribute Certificate Table (Image Only)
use crate::containers::Table;
use crate::error::Result;
use crate::io::ReadData;
use crate::{vec::Vec};

/// Attribute certificates can be associated with an image by adding an attribute certificate table.
/// The attribute certificate table is composed of a set of contiguous, quadword-aligned attribute
/// certificate entries. Zero padding is inserted between the original end of the file and the beginning
/// of the attribute certificate table to achieve this alignment.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct CertificateDataDirectory {
    pub certificates: Table<Certificate>,
}

impl CertificateDataDirectory {
    pub fn parse(section_data: &[u8]) -> Result<Self> {
        let mut offset = 0;
        let mut certificates = Table::new();
        loop {
            let cert = Certificate::read(&mut section_data[offset..].as_ref())?;
            offset += cert.length as usize;
            offset = (offset + 7) & !7;
            certificates.push(cert);
            if offset == section_data.len() {
                break;
            }
        }
        Ok(Self { certificates })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CertificateType {
    X509 = 0x0001,
    PkcsSignedData = 0x0002,
    Reserved1 = 0x0003,
    TsStackSigned = 0x0004,
    Other(u16),
}

impl CertificateType {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0001 => Self::X509,
            0x0002 => Self::PkcsSignedData,
            0x0003 => Self::Reserved1,
            0x0004 => Self::TsStackSigned,
            other => Self::Other(other)
        }
    }
}

impl Default for CertificateType {
    fn default() -> Self {
        Self::Other(0)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum CertificateRevision {
    Revision1_0 = 0x0100,
    Revision2_0 = 0x0200,
    Other(u16)
}

impl CertificateRevision {
    pub fn from_u16(val: u16) -> Self {
        match val {
            0x0001 => Self::Revision1_0,
            0x0002 => Self::Revision2_0,
            other => Self::Other(other)
        }
    }
}

impl Default for CertificateRevision {
    fn default() -> Self {
        Self::Other(0)
    }
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    /// Specifies the length of the attribute certificate entry.
    pub length: u32,
    /// Contains the certificate version number.
    pub revision: CertificateRevision,
    /// Specifies the type of content in `certificate`.
    pub certificate_type: CertificateType,
    /// Contains a certificate, such as an Authenticode signature.
    /// For details, see the following text.
    pub certificate: Vec<u8>,
}

impl ReadData for Certificate {
    fn read(reader: &mut impl crate::io::Reader) -> crate::error::Result<Self> {
        let length: u32 = reader.read()?;
        let cert_data_len = length.saturating_sub(core::mem::size_of_val(&length) as u32) as usize;

        let mut cert_data = reader.read_slice(cert_data_len)?;
        Ok(Self {
            length,
            revision: CertificateRevision::from_u16(u16::read(&mut cert_data)?),
            certificate_type: CertificateType::from_u16(u16::read(&mut cert_data)?),
            certificate: Vec::from(cert_data),
        })
    }
}
