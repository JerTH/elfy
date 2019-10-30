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
pub trait ELFParslet {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> where Self: Sized;
}

/**
 * ELFShort
 * 
 * Represents a 16 bit half word in an ELF file
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ELFShort(pub u16);

impl ELFParslet for ELFShort {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        Ok(ELFShort(read_u16!(reader, descriptor)))
    }
}

impl std::fmt::Debug for ELFShort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/**
 * ELFWord
 * 
 * Represents a 32 bit word in an ELF file
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub struct ELFWord(pub u32);

impl ELFParslet for ELFWord {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        Ok(ELFWord(read_u32!(reader, descriptor)))
    }
}

impl std::fmt::Debug for ELFWord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}


/**
 * ELFSize
 * 
 * Used to represent both 32 and 64 bit sizes and offsets within an ELF file
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum ELFSize {
    Elf32Size(u32),
    Elf64Size(u64)
}

impl ELFSize {
    pub fn as_usize(&self) -> usize {
        match self {
            ELFSize::Elf32Size(v) => (*v).try_into().unwrap(),
            ELFSize::Elf64Size(v) => (*v).try_into().unwrap()
        }
    }
}

impl ELFParslet for ELFSize {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match descriptor.data_class() {
            DataClass::Elf32 => {
                Ok(ELFSize::Elf32Size(read_u32!(reader, descriptor)))
            },
            DataClass::Elf64 => {
                Ok(ELFSize::Elf64Size(read_u64!(reader, descriptor)))
            },
            DataClass::Unknown => {
                panic!("Attempted to parse ELF size with an unknown ELF class: {:?}");
            }
        }
    }
}

impl std::fmt::Debug for ELFSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ELFSize::Elf32Size(v) => {
                write!(f, "{}", v)
            },
            ELFSize::Elf64Size(v) => {
                write!(f, "{}", v)
            }
        }
    }
}


/**
 * ELFAddress
 * 
 * This struct is used to represent both 32 and 64 bit virtual or physical addresses in ELF files and process images
 */
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum ELFAddress {
    Elf32Addr(u32),
    Elf64Addr(u64)
}

impl ELFAddress {
    pub fn as_usize(&self) -> usize {
        match self {
            ELFAddress::Elf32Addr(v) => (*v).try_into().unwrap(),
            ELFAddress::Elf64Addr(v) => (*v).try_into().unwrap()
        }
    }
}

impl ELFParslet for ELFAddress {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match descriptor.data_class() {
            DataClass::Elf32 => {
                Ok(ELFAddress::Elf32Addr(read_u32!(reader, descriptor)))
            },
            DataClass::Elf64 => {
                Ok(ELFAddress::Elf64Addr(read_u64!(reader, descriptor)))
            },
            DataClass::Unknown => {
                panic!("Attempted to parse ELF address with an unknown ELF class: {:?}");
            }
        }
    }
}

impl std::fmt::Debug for ELFAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ELFAddress::Elf32Addr(v) => {
                write!(f, "{:#010X}", v)
            },
            ELFAddress::Elf64Addr(v) => {
                write!(f, "{:#010X}", v)
            }
        }
    }
}
