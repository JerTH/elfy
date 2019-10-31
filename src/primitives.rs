use std::convert::TryInto;
use std::io::{ Read, Seek };


/**
 * Returned by ELFParslets
 */
pub type LoaderResult<T> = std::io::Result<T>;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DataFormat {
    LE,
    BE,
    Unknown
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DataClass {
    Elf32,
    Elf64,
    Unknown
}

pub struct Descriptor {
    pub format: DataFormat,
    pub class: DataClass,
}

impl Descriptor {
    pub fn new() -> Descriptor {
        Descriptor {
            format: DataFormat::Unknown,
            class: DataClass::Unknown
        }
    }

    pub fn data_format(&self) -> DataFormat {
        self.format
    }

    pub fn data_class(&self) -> DataClass {
        self.class
    }

    pub fn is_elf32(&self) -> bool {
        self.class == DataClass::Elf32
    }

    pub fn is_elf64(&self) -> bool {
        self.class == DataClass::Elf64
    }
}

/**
 * Trait used to define how individual parts of the ELF binary structure should be parsed
 */
pub trait Parslet {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> where Self: Sized;
}

/**
 * Short
 * 
 * Represents a 16 bit half word in an ELF file
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Short(pub u16);

impl Parslet for Short {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        Ok(Short(read_u16!(reader, descriptor)))
    }
}

impl std::fmt::Debug for Short {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/**
 * Word
 * 
 * Represents a 32 bit word in an ELF file
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct Word(pub u32);

impl Parslet for Word {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        Ok(Word(read_u32!(reader, descriptor)))
    }
}

impl std::fmt::Debug for Word {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}


/**
 * Used to represent both 32 and 64 bit sizes and offsets within an ELF file
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Size {
    Elf32Size(u32),
    Elf64Size(u64)
}

impl Size {
    pub fn as_usize(&self) -> usize {
        match self {
            Size::Elf32Size(v) => (*v).try_into().unwrap(),
            Size::Elf64Size(v) => (*v).try_into().unwrap()
        }
    }
}

impl Parslet for Size {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match descriptor.data_class() {
            DataClass::Elf32 => {
                Ok(Size::Elf32Size(read_u32!(reader, descriptor)))
            },
            DataClass::Elf64 => {
                Ok(Size::Elf64Size(read_u64!(reader, descriptor)))
            },
            DataClass::Unknown => {
                panic!("Attempted to parse ELF size with an unknown ELF class: {:?}");
            }
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


/**
 * Address
 * 
 * This struct is used to represent both 32 and 64 bit virtual or physical addresses in ELF files and process images
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Address {
    Elf32Addr(u32),
    Elf64Addr(u64)
}

impl Address {
    pub fn as_usize(&self) -> usize {
        match self {
            Address::Elf32Addr(v) => (*v).try_into().unwrap(),
            Address::Elf64Addr(v) => (*v).try_into().unwrap()
        }
    }
}

impl Parslet for Address {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match descriptor.data_class() {
            DataClass::Elf32 => {
                Ok(Address::Elf32Addr(read_u32!(reader, descriptor)))
            },
            DataClass::Elf64 => {
                Ok(Address::Elf64Addr(read_u64!(reader, descriptor)))
            },
            DataClass::Unknown => {
                panic!("Attempted to parse ELF address with an unknown ELF class: {:?}");
            }
        }
    }
}

impl std::fmt::Debug for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::Elf32Addr(v) => {
                write!(f, "{:#010X}", v)
            },
            Address::Elf64Addr(v) => {
                write!(f, "{:#010X}", v)
            }
        }
    }
}
