#[macro_use]
mod macros;

mod constants;
use crate::constants::*;

mod primitives;
use crate::primitives::*;

type LoaderResult<T> = std::io::Result<T>;

trait ELFParslet {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self> where Self: Sized;
}

/* SECTIONS */

/**
 * Represents one section in a loaded ELF binary
 * 
 * This structure contains both a sections header along with the bytes it is responsible for
 */
#[derive(Debug)]
struct ELFSection {
    header: ELFSectionHeader,
    data: ELFSectionBytes,
}

impl ELFParslet for ELFSection {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self>
    {
        let header = ELFSectionHeader::parse(reader, format, class)?;
        let cursor = reader.seek(SeekFrom::Current(0)).unwrap(); // Save the cursor to return to
        
        let section_size = header.section_size.as_usize();
        let section_offs = header.offset.as_usize() as u64;

        let mut data = Vec::new();

        if header.ty != ELFSectionHeaderType::NoBits {
            let _ = reader.seek(SeekFrom::Start(section_offs));
            data.append(&mut read_n_bytes!(reader, section_size));
            let _ = reader.seek(SeekFrom::Start(cursor));
        }

        let section = ELFSection {
            header: header,
            data: ELFSectionBytes{ bytes: data },
        };

        Ok(section)
    }
}



/**
 * A section header describes the location as well as the contents of an ELF section
 * 
 * ELF sections are parsed and represented by the ELFSection structure 
 */
#[derive(Debug)]
struct ELFSectionHeader {
    name: ELFAddress,
    ty: ELFSectionHeaderType,
    flags: ELFSectionFlags,
    virtual_address: ELFAddress,
    offset: ELFAddress,
    section_size: ELFSize,
    link: ELFWord,
    info: ELFWord,
    align: ELFSize,
    entry_size: ELFSize,
}

impl ELFParslet for ELFSectionHeader {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self> {
        let section_header = ELFSectionHeader {
            name: ELFAddress::parse(reader, format, class)?,
            ty: ELFSectionHeaderType::parse(reader, format, class)?,
            flags: ELFSectionFlags::parse(reader, format, class)?,
            virtual_address: ELFAddress::parse(reader, format, class)?,
            offset: ELFAddress::parse(reader, format, class)?,
            section_size: ELFSize::parse(reader, format, class)?,
            link: ELFWord::parse(reader, format, class)?,
            info: ELFWord::parse(reader, format, class)?,
            align: ELFSize::parse(reader, format, class)?,
            entry_size: ELFSize::parse(reader, format, class)?,
        };

        Ok(section_header)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ELFSectionHeaderType {
    Null,
    ProgramData,
    SymbolTable,
    StringTable,
    RelocationWithAddends,
    SymbolHashTable,
    DynamicInfo,
    Note,
    NoBits,
    Relocation,
    ShLib,
    DynamicSymbolTable,
    InitArray,
    FiniArray,
    PreInitArray,
    Group,
    ExtendedSectionIndices,
    OSSpecific(u32),
    Invalid(u32)
}

/**
 * This struct describes the contents of an individual section and is used to determine how a section should be processed
 */
impl ELFParslet for ELFSectionHeaderType {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self> {

        use ELFSectionHeaderType::*;
        match read_u32!(reader, format) {
            0x00 => Ok(Null),
            0x01 => Ok(ProgramData),
            0x02 => Ok(SymbolTable),
            0x03 => Ok(StringTable),
            0x04 => Ok(RelocationWithAddends),
            0x05 => Ok(SymbolHashTable),
            0x06 => Ok(DynamicInfo),
            0x07 => Ok(Note),
            0x08 => Ok(NoBits),
            0x09 => Ok(Relocation),
            0x0A => Ok(ShLib),
            0x0B => Ok(DynamicSymbolTable),
            0x0E => Ok(InitArray),
            0x0F => Ok(FiniArray),
            0x10 => Ok(PreInitArray),
            0x11 => Ok(Group),
            0x12 => Ok(ExtendedSectionIndices),

            v @ 0x60000000 ..= 0xFFFFFFFF => Ok(ELFSectionHeaderType::OSSpecific(v)),
            v => Ok(ELFSectionHeaderType::Invalid(v))
        }
    }
}



/**
 * Section flags describe the allowable access patterns of an ELF section
 */
enum ELFSectionFlags {
    ELF32SectionFlags(u32),
    ELF64SectionFlags(u64)
}

impl ELFParslet for ELFSectionFlags {
    fn parse(reader: &mut BufReader<File>, format: ELFData, class: ELFClass) -> LoaderResult<Self> {
        match class {
            ELFClass::ELF32 => Ok(ELFSectionFlags::ELF32SectionFlags(read_u32!(reader, format))),
            ELFClass::ELF64 => Ok(ELFSectionFlags::ELF64SectionFlags(read_u64!(reader, format))),
            ELFClass::Unknown => panic!("Attempted to parse ELF section flags with an unknown ELF class: {:?}"),
            ELFClass::Invalid(e) => panic!("Attempted to parse ELF section flags with an invalid ELF class: {:?}", e)
        }
    }
}

impl std::fmt::Debug for ELFSectionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ELFSectionFlags::ELF32SectionFlags(v) => write!(f, "{:#b}", v),
            ELFSectionFlags::ELF64SectionFlags(v) => write!(f, "{:#b}", v),
        }
    }
}

/**
 * Represents the raw binary data contained in one section
 */
struct ELFSectionBytes {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for ELFSectionBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let _ = write!(f, "[\n\t");
        for (i, byte) in self.bytes.iter().enumerate() {

            if (i > 0) && (i % 16 == 0) {
                let _ = write!(f, "\n\t");
            }

            let _ = write!(f, "{:02x} ", byte);
            
        }
        write!(f, "\n]")
    }
}





/* LIB INTERFACE */

/**
 * ELF
 * 
 * Represents an ELF (Executable and Linkable Format) file.
 * 
 * The Executable and Linkable Format is a common standard file format for executable files, object code,
 * shared libraries, and core dumps.
 * 
 * This type is responsible for loading, parsing, and modifying ELF files, and is used by the ARM
 * program loader to construct an executable image.
 *  
 */
#[derive(Debug)]
pub struct ELF {
    header: ELFHeader,
    sections: Vec<ELFSection>,
    program_headers: Vec<ELFProgramHeader>,
}

impl ELF {
    pub fn parse(reader: &mut BufReader<File>) -> LoaderResult<ELF> {
        let header = ELFHeader::parse(reader, ELFData::Unknown, ELFClass::Unknown)?;

        assert!(header.ident.class != ELFClass::Unknown);

        let format = header.ident.data;
        let class = header.ident.class;

        reader.seek(SeekFrom::Start(header.shoff.as_usize() as u64))?;
        let mut sections = Vec::new();
        for _ in 0..header.shnum.0 {
            sections.push(ELFSection::parse(reader, format, class)?)
        }

        reader.seek(SeekFrom::Start(header.phoff.as_usize() as u64))?;
        let mut program_headers = Vec::new();
        for _ in 0..header.phnum.0 {
            program_headers.push(ELFProgramHeader::parse(reader, format, class)?)
        }

        let parsed = ELF {
            header: header,
            sections: sections,
            program_headers: program_headers,
        };

        Ok(parsed)
    }
}
