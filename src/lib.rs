use std::io::{ Read, Seek, SeekFrom };

#[macro_use]
mod macros;

mod constants;
use crate::constants::*;

mod primitives;
use crate::primitives::*;

/* ELF FILE HEADER */

/**
 * Represents an ELF file header
 * 
 * This header is used to identify and process the rest of an ELF file, it includes offsets to the program
 * header table and the section header table
 */
#[derive(Debug)]
struct ELFHeader {
    ident: ELFIdent,
    ty: ELFType,
    machine: ELFMachine,
    version: ELFVersion,
    entry: ELFAddress,
    phoff: ELFAddress,
    shoff: ELFAddress,
    flags: ELFFlags,
    ehsize: ELFShort,
    phentsize: ELFShort,
    phnum: ELFShort,
    shentsize: ELFShort,
    shnum: ELFShort,
    shstrndx: ELFShort,
}

impl ELFParslet for ELFHeader {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        let ident = ELFIdent::parse(reader, descriptor)?;

        let header = ELFHeader {
            ident: ident,
            ty: ELFType::parse(reader, descriptor)?,
            machine: ELFMachine::parse(reader, descriptor)?,
            version: ELFVersion::parse(reader, descriptor)?,
            entry: ELFAddress::parse(reader, descriptor)?,
            phoff: ELFAddress::parse(reader, descriptor)?,
            shoff: ELFAddress::parse(reader, descriptor)?,
            flags: ELFFlags::parse(reader, descriptor)?,
            ehsize: ELFShort::parse(reader, descriptor)?,
            phentsize: ELFShort::parse(reader, descriptor)?,
            phnum: ELFShort::parse(reader, descriptor)?,
            shentsize: ELFShort::parse(reader, descriptor)?,
            shnum: ELFShort::parse(reader, descriptor)?,
            shstrndx: ELFShort::parse(reader, descriptor)?,
        };

        Ok(header)
    } 
}

/**
 * ELFIdent
 * 
 * Used to validate an ELF file, and identify the format of its contents
 */
#[derive(Debug)]
struct ELFIdent {
    magic: ELFMagic,
    class: ELFClass,
    data: ELFData,
    version: ELFIdentVersion,
    os_abi: ELFOsAbi,
    abi_ver: ELFAbiVersion,
}

impl ELFParslet for ELFIdent {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        let parsed = ELFIdent {
            magic: ELFMagic::parse(reader, descriptor)?,
            class: ELFClass::parse(reader, descriptor)?,
            data: ELFData::parse(reader, descriptor)?,
            version: ELFIdentVersion::parse(reader, descriptor)?,
            os_abi: ELFOsAbi::parse(reader, descriptor)?,
            abi_ver: ELFAbiVersion::parse(reader, descriptor)?,
        };

        descriptor.class = match parsed.class {
            ELFClass::ELF32 => DataClass::Elf32,
            ELFClass::ELF64 => DataClass::Elf64,
            ELFClass::Invalid(_) => DataClass::Unknown,
        };

        descriptor.format = match parsed.data {
            ELFData::LittleEndian => DataFormat::LE,
            ELFData::BigEndian => DataFormat::BE,
            ELFData::Invalid(_) => DataFormat::Unknown,
        };

        // The end of the ident is composed of empty padding bytes, skip over them
        read_n_bytes!(reader, 7);

        Ok(parsed)
    } 
}

/**
 * ELF magic. Identifies a file as ELF
 */
#[derive(Debug)]
enum ELFMagic {
    Valid,
    Invalid,
}

impl ELFParslet for ELFMagic {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        let bytes = read_n_bytes!(reader, 4);
        if bytes.as_slice() == &ELF_MAGIC_BYTES[..] {
            Ok(ELFMagic::Valid)
        } else {
            Ok(ELFMagic::Invalid)
        }
    }
}

/**
 * ELFClass
 * 
 * Identifies an ELF binary as being either 32 or 64 bit
 */
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ELFClass {
    ELF32,
    ELF64,
    Invalid(u8)
}

impl ELFParslet for ELFClass {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x01 => Ok(ELFClass::ELF32),
            0x02 => Ok(ELFClass::ELF64),
            b => Ok(ELFClass::Invalid(b))
        }
    }
}

/**
 * Identifies the format of an ELF file, 2's Complement Little Endian or Big Endian
 */
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ELFData {
    LittleEndian,
    BigEndian,
    Invalid(u8)
}

impl ELFParslet for ELFData {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x01 => Ok(ELFData::LittleEndian),
            0x02 => Ok(ELFData::BigEndian),
            b => Ok(ELFData::Invalid(b))
        }
    }
}

#[derive(Debug)]
enum ELFIdentVersion {
    Current,
    Invalid(u8)
}

impl ELFParslet for ELFIdentVersion {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x01 => Ok(ELFIdentVersion::Current), // ELF only has one version, version one. Nonetheless we parse it as "current"
            b => Ok(ELFIdentVersion::Invalid(b))
        }
    }
}

/**
 * ELFOsAbi
 */
#[derive(Debug)]
enum ELFOsAbi {
    UNIXSystemV,
    Invalid(u8)
}

impl ELFParslet for ELFOsAbi {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x00 => Ok(ELFOsAbi::UNIXSystemV),
            b => Ok(ELFOsAbi::Invalid(b))
        }
    }
}

/**
 * ELFAbiVersion
 */
#[derive(Debug)]
enum ELFAbiVersion {
    Unspecified,
    Version(u8),
}

impl ELFParslet for ELFAbiVersion {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x00 => Ok(ELFAbiVersion::Unspecified),
            b => Ok(ELFAbiVersion::Version(b))
        }
    }
}

/**
 * ELFType
 */
#[derive(Debug)]
enum ELFType {
    None,
    Relocatable,
    Executable,
    Shared,
    Core,
    LoProc,
    HiProc,
    Invalid(u16),
}

impl ELFParslet for ELFType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match read_u16!(reader, descriptor) {
            0x0000 => Ok(ELFType::None),
            0x0001 => Ok(ELFType::Relocatable),
            0x0002 => Ok(ELFType::Executable),
            0x0003 => Ok(ELFType::Shared),
            0x0004 => Ok(ELFType::Core),
            0xFF00 => Ok(ELFType::LoProc),
            0xFFFF => Ok(ELFType::HiProc),
            b => Ok(ELFType::Invalid(b))
        }
    }
}

/**
 * ELFMachine
 * 
 * Identifies which machine architecture an ELF file targets
 */
#[derive(Debug)]
enum ELFMachine {
    None,
    AtmelAVR,
    AMD64,
    ARM,
    ST200,
    RISCV,
    Invalid(u16),
}

impl ELFParslet for ELFMachine {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match read_u16!(reader, descriptor) {
            0x0000 => Ok(ELFMachine::None),
            0x0028 => Ok(ELFMachine::ARM),
            0x0053 => Ok(ELFMachine::AtmelAVR),
            0x003E => Ok(ELFMachine::AMD64),
            0x0064 => Ok(ELFMachine::ST200),
            0x00F3 => Ok(ELFMachine::RISCV),
            b => Ok(ELFMachine::Invalid(b))
        }
    }
}

/**
 * ELF file version. There is only one version, version one
 */
#[derive(Debug)]
enum ELFVersion {
    Current,
    Invalid(u32)
}

impl ELFParslet for ELFVersion {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match read_u32!(reader, descriptor) {
            0x01 => Ok(ELFVersion::Current),
            b => Ok(ELFVersion::Invalid(b))
        }
    }
}

/**
 * ELFFlags
 */
struct ELFFlags(u32);

impl ELFParslet for ELFFlags {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match read_u32!(reader, descriptor) {
            v => Ok(ELFFlags(v)),
        }
    }
}

impl std::fmt::Debug for ELFFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#b}", self.0)
    }
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self>
    {
        let header = ELFSectionHeader::parse(reader, descriptor)?;
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        let section_header = ELFSectionHeader {
            name: ELFAddress::parse(reader, descriptor)?,
            ty: ELFSectionHeaderType::parse(reader, descriptor)?,
            flags: ELFSectionFlags::parse(reader, descriptor)?,
            virtual_address: ELFAddress::parse(reader, descriptor)?,
            offset: ELFAddress::parse(reader, descriptor)?,
            section_size: ELFSize::parse(reader, descriptor)?,
            link: ELFWord::parse(reader, descriptor)?,
            info: ELFWord::parse(reader, descriptor)?,
            align: ELFSize::parse(reader, descriptor)?,
            entry_size: ELFSize::parse(reader, descriptor)?,
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {

        use ELFSectionHeaderType::*;
        match read_u32!(reader, descriptor) {
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match descriptor.data_class() {
            DataClass::Elf32 => Ok(ELFSectionFlags::ELF32SectionFlags(read_u32!(reader, descriptor))),
            DataClass::Elf64 => Ok(ELFSectionFlags::ELF64SectionFlags(read_u64!(reader, descriptor))),
            DataClass::Unknown => panic!("Attempted to parse ELF section flags with an unknown ELF class: {:?}"),
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



/* PROGRAM HEADER */

/**
 * ELFProgramHeader
 * 
 * Program headers are used to describe how sections are to be loaded into memory in order to construct an executable process
 */
#[derive(Debug)]
struct ELFProgramHeader {
    ty: ELFProgramHeaderType,
    flags: ELFProgramFlags,
    offset: ELFAddress,
    virtual_address: ELFAddress,
    physical_address: ELFAddress,
    file_size: ELFSize,
    mem_size: ELFSize,
    align: ELFSize
}

impl ELFParslet for ELFProgramHeader {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {

        
        let ty = ELFProgramHeaderType::parse(reader, descriptor)?;
        
        // If this is an ELF64 file, the program flags appear before the 'offset' value
        let mut flags = ELFProgramFlags::Invalid(0);
        if descriptor.is_elf64() {
            flags = ELFProgramFlags::parse(reader, descriptor)?;
        }
        
        let offset = ELFAddress::parse(reader, descriptor)?;
        let virtual_address = ELFAddress::parse(reader, descriptor)?;
        let physical_address = ELFAddress::parse(reader, descriptor)?;
        let file_size = ELFSize::parse(reader, descriptor)?;
        let mem_size = ELFSize::parse(reader, descriptor)?;

        // If this is an ELF32 file, the program flags actually appear after the 'mem_size' value
        if descriptor.is_elf32() {
            flags = ELFProgramFlags::parse(reader, descriptor)?;
        }

        let align = ELFSize::parse(reader, descriptor)?;

        let program_header = ELFProgramHeader {
            ty,
            flags,
            offset,
            virtual_address,
            physical_address,
            file_size,
            mem_size,
            align,
        };

        Ok(program_header)
    }
}

/**
 * ELFProgramHeaderType
 * 
 * Describes the way in which the section pointed to by a program header is to be processed
 */
#[derive(Debug)]
enum ELFProgramHeaderType {
    Null,
    Loadable,
    DynamicInfo,
    InterpreterInfo,
    AuxiliaryInfo,
    ShLib,
    PHDR,
    OSSpecific(u32),
    ProcessorSpecific(u32),
    Invalid(u32),
}

impl ELFParslet for ELFProgramHeaderType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        
        use ELFProgramHeaderType::*;
        match read_u32!(reader, descriptor) {
            0x00 => Ok(Null),
            0x01 => Ok(Loadable),
            0x02 => Ok(DynamicInfo),
            0x03 => Ok(InterpreterInfo),
            0x04 => Ok(AuxiliaryInfo),
            0x05 => Ok(ShLib),
            0x06 => Ok(PHDR),

            v @ 0x60000000 ..= 0x6FFFFFFF => Ok(ELFProgramHeaderType::OSSpecific(v)),
            v @ 0x70000000 ..= 0x7FFFFFFF => Ok(ELFProgramHeaderType::ProcessorSpecific(v)),
            v => Ok(ELFProgramHeaderType::Invalid(v))
        }
    }
}

/**
 * Program flags describe the allowable access patterns of an ELF section
 */
#[derive(Debug)]
enum ELFProgramFlags {
    Read,
    Write,
    Execute,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
    Invalid(u32),
}

impl ELFParslet for ELFProgramFlags {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        
        use ELFProgramFlags::*;
        match read_u32!(reader, descriptor) {
            0b100 => Ok(Read),
            0b010 => Ok(Write),
            0b001 => Ok(Execute),
            0b110 => Ok(ReadWrite),
            0b101 => Ok(ReadExecute),
            0b111 => Ok(ReadWriteExecute),
            v => Ok(Invalid(v))
        }
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
    pub fn parse<R: Read + Seek>(reader: &mut R) -> LoaderResult<ELF> {
        let mut descriptor = Descriptor::new();

        let header = ELFHeader::parse(reader, &mut descriptor)?;

        reader.seek(SeekFrom::Start(header.shoff.as_usize() as u64))?;
        let mut sections = Vec::new();
        for _ in 0..header.shnum.0 {
            sections.push(ELFSection::parse(reader, &mut descriptor)?)
        }

        reader.seek(SeekFrom::Start(header.phoff.as_usize() as u64))?;
        let mut program_headers = Vec::new();
        for _ in 0..header.phnum.0 {
            program_headers.push(ELFProgramHeader::parse(reader, &mut descriptor)?)
        }

        let parsed = ELF {
            header: header,
            sections: sections,
            program_headers: program_headers,
        };

        Ok(parsed)
    }
}
