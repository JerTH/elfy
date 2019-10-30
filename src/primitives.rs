
/**
 * Returned by ELFParslets
 */
type LoaderResult<T> = std::io::Result<T>;


struct Descriptor {
    
}


/**
 * Trait used to define how individual parts of the ELF binary structure should be parsed
 */
trait ELFParslet {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self> where Self: Sized;
}


/**
 * ELFWord
 * 
 * Represents a 32 bit word in an ELF file
 */
#[derive(PartialEq, Eq, Clone, Copy)]
struct ELFWord(u32);

impl ELFParslet for ELFWord {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self> {
        Ok(ELFWord(read_u32!(reader, format)))
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
enum ELFSize {
    ELF32Size(u32),
    ELF64Size(u64)
}

impl ELFSize {
    pub fn as_usize(&self) -> usize {
        match self {
            ELFSize::ELF32Size(v) => (*v).try_into().unwrap(),
            ELFSize::ELF64Size(v) => (*v).try_into().unwrap()
        }
    }
}

impl ELFParslet for ELFSize {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self> {
        match class {
            ELFClass::ELF32 => {
                Ok(ELFSize::ELF32Size(read_u32!(reader, format)))
            },
            ELFClass::ELF64 => {
                Ok(ELFSize::ELF64Size(read_u64!(reader, format)))
            },
            ELFClass::Unknown => {
                panic!("Attempted to parse ELF size with an unknown ELF class: {:?}");
            }
            ELFClass::Invalid(e) => {
                panic!("Attempted to parse ELF size with an invalid ELF class: {:?}", e);
            }
        }
    }
}

impl std::fmt::Debug for ELFSize {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ELFSize::ELF32Size(v) => {
                write!(f, "{}", v)
            },
            ELFSize::ELF64Size(v) => {
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
    ELF32Addr(u32),
    ELF64Addr(u64)
}

impl ELFAddress {
    pub fn as_usize(&self) -> usize {
        match self {
            ELFAddress::ELF32Addr(v) => (*v).try_into().unwrap(),
            ELFAddress::ELF64Addr(v) => (*v).try_into().unwrap()
        }
    }
}

impl ELFParslet for ELFAddress {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self> {
        match class {
            ELFClass::ELF32 => {
                Ok(ELFAddress::ELF32Addr(read_u32!(reader, format)))
            },
            ELFClass::ELF64 => {
                Ok(ELFAddress::ELF64Addr(read_u64!(reader, format)))
            },
            ELFClass::Unknown => {
                panic!("Attempted to parse ELF address with an unknown ELF class: {:?}");
            }
            ELFClass::Invalid(e) => {
                panic!("Attempted to parse ELF address with an invalid ELF class: {:?}", e);
            }
        }
    }
}

impl std::fmt::Debug for ELFAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ELFAddress::ELF32Addr(v) => {
                write!(f, "{:#010X}", v)
            },
            ELFAddress::ELF64Addr(v) => {
                write!(f, "{:#010X}", v)
            }
        }
    }
}
