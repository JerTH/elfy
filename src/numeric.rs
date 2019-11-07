//! Types describing various simple value types that may be found in an ELF file

use std::io::{ Read, Seek };
use std::convert::TryInto;

use crate::{ Parslet, ParseElfResult, Descriptor, DataClass, DataFormat };

/// Represents a 16 bit half word in an ELF file
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Short(pub u16);

impl Short {
    /// Returns the contained `u16` as a `usize`, zero extending it
    pub fn as_usize(self) -> usize {
        self.0 as usize
    }
}

impl Parslet for Short {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        Ok(Short(read_u16!(reader, descriptor)))
    }
}

impl std::fmt::Debug for Short {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a 32 bit word in an ELF file
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Word(pub u32);

impl Parslet for Word {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        Ok(Word(read_u32!(reader, descriptor)))
    }
}

impl std::fmt::Debug for Word {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}


/// Used to represent both 32 and 64 bit sizes and offsets within an ELF file
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Size {
    /// The `Size` type for ELF32
    Elf32Size(u32),

    /// The `Size` type for ELF64
    Elf64Size(u64)
}

impl Size {
    /// Returns the contained value as `usize`
    /// 
    /// # Panics
    /// 
    /// This method panics if the contained value would not fit into a `usize` without truncation
    pub fn as_usize(&self) -> usize {
        match self {
            Size::Elf32Size(v) => (*v).try_into().expect("Unable to convert `Elf32Size` to `usize` without truncating"),
            Size::Elf64Size(v) => (*v).try_into().expect("Unable to convert `Elf64Size` to `usize` without truncating")
        }
    }

    /// Returns the contained value as a `u64`, zero extending it if necessary
    pub fn as_u64(&self) -> u64 {
        self.as_usize() as u64
    }
}

impl Parslet for Size {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        match descriptor.data_class()? {
            DataClass::Elf32 => Ok(Size::Elf32Size(read_u32!(reader, descriptor))),
            DataClass::Elf64 => Ok(Size::Elf64Size(read_u64!(reader, descriptor))),
        }
    }
}

impl std::fmt::Debug for Size {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Size::Elf32Size(v) => {
                write!(f, "{}", v)
            },
            Size::Elf64Size(v) => {
                write!(f, "{}", v)
            }
        }
    }
}


/// This struct is used to represent both 32 and 64 bit virtual or physical addresses in ELF files and process images
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Address {
    /// The `Address` type for ELF32
    Elf32Addr(u32),
    /// The `Address` type for ELF64
    Elf64Addr(u64)
}
impl Address {
    /// Returns the contained value as `usize`
    /// 
    /// # Panics
    /// 
    /// This method panics if the contained value would not fit into a `usize` without truncation
    pub fn as_usize(&self) -> usize {
        match self {
            Address::Elf32Addr(v) => (*v).try_into().expect("Unable to convert `Elf32Addr` to `usize` without truncating"),
            Address::Elf64Addr(v) => (*v).try_into().expect("Unable to convert `Elf64Addr` to `usize` without truncating")
        }
    }
}

impl Parslet for Address {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        match descriptor.data_class()? {
            DataClass::Elf32 => Ok(Address::Elf32Addr(read_u32!(reader, descriptor))),
            DataClass::Elf64 => Ok(Address::Elf64Addr(read_u64!(reader, descriptor))),
        }
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Elf32Addr(v) => {
                write!(f, "{:#X}", v)
            },
            Address::Elf64Addr(v) => {
                write!(f, "{:#X}", v)
            }
        }
    }
}
