use std::io::{ Read, Seek, SeekFrom };

#[macro_use]
mod macros;

mod constants;
use crate::constants::*;

mod primitives;
use crate::primitives::*;

/* Elf FILE HEADER */

/**
 * Represents an Elf file header
 * 
 * This header is used to identify and process the rest of an Elf file, it includes offsets to the program
 * header table and the section header table
 */
#[derive(Debug)]
struct Header {
    ident: Identifier,
    ty: ElfType,
    machine: Machine,
    version: Version,
    entry: Address,
    phoff: Size,
    shoff: Size,
    flags: Flags,
    ehsize: Short,
    phentsize: Short,
    phnum: Short,
    shentsize: Short,
    shnum: Short,
    shstrndx: Short,
}

impl Parslet for Header {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        let ident = Identifier::parse(reader, descriptor)?;

        let header = Header {
            ident: ident,
            ty: ElfType::parse(reader, descriptor)?,
            machine: Machine::parse(reader, descriptor)?,
            version: Version::parse(reader, descriptor)?,
            entry: Address::parse(reader, descriptor)?,
            phoff: Size::parse(reader, descriptor)?,
            shoff: Size::parse(reader, descriptor)?,
            flags: Flags::parse(reader, descriptor)?,
            ehsize: Short::parse(reader, descriptor)?,
            phentsize: Short::parse(reader, descriptor)?,
            phnum: Short::parse(reader, descriptor)?,
            shentsize: Short::parse(reader, descriptor)?,
            shnum: Short::parse(reader, descriptor)?,
            shstrndx: Short::parse(reader, descriptor)?,
        };

        Ok(header)
    } 
}

/**
 * Identifier
 * 
 * Used to validate an Elf file, and identify the format of its contents
 */
#[derive(Debug)]
struct Identifier {
    magic: Magic,
    class: Class,
    data: ELFData,
    version: ELFIdentVersion,
    os_abi: OsAbi,
    abi_ver: AbiVersion,
}

impl Parslet for Identifier {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        let parsed = Identifier {
            magic: Magic::parse(reader, descriptor)?,
            class: Class::parse(reader, descriptor)?,
            data: ELFData::parse(reader, descriptor)?,
            version: ELFIdentVersion::parse(reader, descriptor)?,
            os_abi: OsAbi::parse(reader, descriptor)?,
            abi_ver: AbiVersion::parse(reader, descriptor)?,
        };

        descriptor.class = match parsed.class {
            Class::ELF32 => DataClass::Elf32,
            Class::ELF64 => DataClass::Elf64,
            Class::Invalid(_) => DataClass::Unknown,
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
 * Elf magic. Identifies a file as Elf
 */
#[derive(Debug)]
enum Magic {
    Valid,
    Invalid,
}

impl Parslet for Magic {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        let bytes = read_n_bytes!(reader, 4);
        if bytes.as_slice() == &ELF_MAGIC_BYTES[..] {
            Ok(Magic::Valid)
        } else {
            Ok(Magic::Invalid)
        }
    }
}

/**
 * Identifies an Elf binary as being either 32 or 64 bit
 */
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Class {
    ELF32,
    ELF64,
    Invalid(u8)
}

impl Parslet for Class {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x01 => Ok(Class::ELF32),
            0x02 => Ok(Class::ELF64),
            b => Ok(Class::Invalid(b))
        }
    }
}

/**
 * Identifies the format of an Elf file, 2's Complement Little Endian or Big Endian
 */
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum ELFData {
    LittleEndian,
    BigEndian,
    Invalid(u8)
}

impl Parslet for ELFData {
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

impl Parslet for ELFIdentVersion {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x01 => Ok(ELFIdentVersion::Current), // Elf only has one version, version one. Nonetheless we parse it as "current"
            b => Ok(ELFIdentVersion::Invalid(b))
        }
    }
}

/**
 * OsAbi
 */
#[derive(Debug)]
enum OsAbi {
    UNIXSystemV,
    Invalid(u8)
}

impl Parslet for OsAbi {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x00 => Ok(OsAbi::UNIXSystemV),
            b => Ok(OsAbi::Invalid(b))
        }
    }
}

/**
 * AbiVersion
 */
#[derive(Debug)]
enum AbiVersion {
    Unspecified,
    Version(u8),
}

impl Parslet for AbiVersion {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> LoaderResult<Self> {
        match read_byte!(reader) {
            0x00 => Ok(AbiVersion::Unspecified),
            b => Ok(AbiVersion::Version(b))
        }
    }
}

/**
 * ElfType
 */
#[derive(Debug)]
enum ElfType {
    None,
    Relocatable,
    Executable,
    Shared,
    Core,
    LoProc,
    HiProc,
    Invalid(u16),
}

impl Parslet for ElfType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match read_u16!(reader, descriptor) {
            0x0000 => Ok(ElfType::None),
            0x0001 => Ok(ElfType::Relocatable),
            0x0002 => Ok(ElfType::Executable),
            0x0003 => Ok(ElfType::Shared),
            0x0004 => Ok(ElfType::Core),
            0xFF00 => Ok(ElfType::LoProc),
            0xFFFF => Ok(ElfType::HiProc),
            b => Ok(ElfType::Invalid(b))
        }
    }
}

/**
 * Machine
 * 
 * Identifies which machine architecture an Elf file targets
 */
#[derive(Debug)]
enum Machine {
    None,
    AtmelAVR,
    AMD64,
    ARM,
    ST200,
    RISCV,
    Invalid(u16),
}

impl Parslet for Machine {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match read_u16!(reader, descriptor) {
            0x0000 => Ok(Machine::None),
            0x0028 => Ok(Machine::ARM),
            0x0053 => Ok(Machine::AtmelAVR),
            0x003E => Ok(Machine::AMD64),
            0x0064 => Ok(Machine::ST200),
            0x00F3 => Ok(Machine::RISCV),
            b => Ok(Machine::Invalid(b))
        }
    }
}

/**
 * Elf file version. There is only one version, version one
 */
#[derive(Debug)]
enum Version {
    Current,
    Invalid(u32)
}

impl Parslet for Version {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match read_u32!(reader, descriptor) {
            0x01 => Ok(Version::Current),
            b => Ok(Version::Invalid(b))
        }
    }
}

/**
 * Flags
 */
struct Flags(u32);

impl Parslet for Flags {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match read_u32!(reader, descriptor) {
            v => Ok(Flags(v)),
        }
    }
}

impl std::fmt::Debug for Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#b}", self.0)
    }
}






/* SECTIONS */

/**
 * Represents one section in a loaded Elf binary
 * 
 * This structure contains both a sections header along with the bytes it is responsible for
 */
#[derive(Debug)]
struct Section {
    header: SectionHeader,
    data: SectionData,
}

impl Parslet for Section {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self>
    {
        let header = SectionHeader::parse(reader, descriptor)?;
        let cursor = reader.seek(SeekFrom::Current(0)).unwrap(); // Save the cursor to return to
        
        let section_size = header.section_size.as_usize();
        let section_offs = header.offset.as_usize() as u64;

        let mut data = Vec::new();

        if header.ty != SectionHeaderType::NoBits {
            let _ = reader.seek(SeekFrom::Start(section_offs));
            data.append(&mut read_n_bytes!(reader, section_size));
            let _ = reader.seek(SeekFrom::Start(cursor));
        }

        let section = Section {
            header: header,
            data: SectionData{ bytes: data },
        };

        Ok(section)
    }
}

/**
 * A section header describes the location as well as the contents of an Elf section
 * 
 * Elf sections are parsed and represented by the Section structure 
 */
#[derive(Debug)]
struct SectionHeader {
    name: Address,
    ty: SectionHeaderType,
    flags: SectionFlags,
    virtual_address: Address,
    offset: Address,
    section_size: Size,
    link: Word,
    info: Word,
    align: Size,
    entry_size: Size,
}

impl Parslet for SectionHeader {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        let section_header = SectionHeader {
            name: Address::parse(reader, descriptor)?,
            ty: SectionHeaderType::parse(reader, descriptor)?,
            flags: SectionFlags::parse(reader, descriptor)?,
            virtual_address: Address::parse(reader, descriptor)?,
            offset: Address::parse(reader, descriptor)?,
            section_size: Size::parse(reader, descriptor)?,
            link: Word::parse(reader, descriptor)?,
            info: Word::parse(reader, descriptor)?,
            align: Size::parse(reader, descriptor)?,
            entry_size: Size::parse(reader, descriptor)?,
        };

        Ok(section_header)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum SectionHeaderType {
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
impl Parslet for SectionHeaderType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {

        use SectionHeaderType::*;
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

            v @ 0x60000000 ..= 0xFFFFFFFF => Ok(SectionHeaderType::OSSpecific(v)),
            v => Ok(SectionHeaderType::Invalid(v))
        }
    }
}

/**
 * Section flags describe the allowable access patterns of an Elf section
 */
enum SectionFlags {
    ELF32SectionFlags(u32),
    ELF64SectionFlags(u64)
}

impl Parslet for SectionFlags {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        match descriptor.data_class() {
            DataClass::Elf32 => Ok(SectionFlags::ELF32SectionFlags(read_u32!(reader, descriptor))),
            DataClass::Elf64 => Ok(SectionFlags::ELF64SectionFlags(read_u64!(reader, descriptor))),
            DataClass::Unknown => panic!("Attempted to parse Elf section flags with an unknown Elf class: {:?}"),
        }
    }
}

impl std::fmt::Debug for SectionFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SectionFlags::ELF32SectionFlags(v) => write!(f, "{:#b}", v),
            SectionFlags::ELF64SectionFlags(v) => write!(f, "{:#b}", v),
        }
    }
}

/**
 * Represents the raw binary data contained in one section
 */
struct SectionData {
    bytes: Vec<u8>,
}

impl std::fmt::Debug for SectionData {
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
 * Program headers are used to describe how sections are to be loaded into memory in order to construct an executable process
 */
#[derive(Debug)]
struct ProgramHeader {
    ty: ProgramHeaderType,
    flags: ProgramHeaderFlags,
    offset: Address,
    virtual_address: Address,
    physical_address: Address,
    file_size: Size,
    mem_size: Size,
    align: Size
}

impl Parslet for ProgramHeader {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {

        
        let ty = ProgramHeaderType::parse(reader, descriptor)?;
        
        // If this is an ELF64 file, the program flags appear before the 'offset' value
        let mut flags = ProgramHeaderFlags::Invalid(0);
        if descriptor.is_elf64() {
            flags = ProgramHeaderFlags::parse(reader, descriptor)?;
        }
        
        let offset = Address::parse(reader, descriptor)?;
        let virtual_address = Address::parse(reader, descriptor)?;
        let physical_address = Address::parse(reader, descriptor)?;
        let file_size = Size::parse(reader, descriptor)?;
        let mem_size = Size::parse(reader, descriptor)?;

        // If this is an ELF32 file, the program flags actually appear after the 'mem_size' value
        if descriptor.is_elf32() {
            flags = ProgramHeaderFlags::parse(reader, descriptor)?;
        }

        let align = Size::parse(reader, descriptor)?;

        let program_header = ProgramHeader {
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
 * ProgramHeaderType
 * 
 * Describes the way in which the section pointed to by a program header is to be processed
 */
#[derive(Debug)]
enum ProgramHeaderType {
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

impl Parslet for ProgramHeaderType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        
        use ProgramHeaderType::*;
        match read_u32!(reader, descriptor) {
            0x00 => Ok(Null),
            0x01 => Ok(Loadable),
            0x02 => Ok(DynamicInfo),
            0x03 => Ok(InterpreterInfo),
            0x04 => Ok(AuxiliaryInfo),
            0x05 => Ok(ShLib),
            0x06 => Ok(PHDR),

            v @ 0x60000000 ..= 0x6FFFFFFF => Ok(ProgramHeaderType::OSSpecific(v)),
            v @ 0x70000000 ..= 0x7FFFFFFF => Ok(ProgramHeaderType::ProcessorSpecific(v)),
            v => Ok(ProgramHeaderType::Invalid(v))
        }
    }
}

/**
 * Describe the allowable access patterns of an Elf section
 */
#[derive(Debug)]
enum ProgramHeaderFlags {
    Read,
    Write,
    Execute,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
    Invalid(u32),
}

impl Parslet for ProgramHeaderFlags {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> LoaderResult<Self> {
        
        use ProgramHeaderFlags::*;
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
 * Elf
 * 
 * Represents an Elf (Executable and Linkable Format) file.
 * 
 * The Executable and Linkable Format is a common standard file format for executable files, object code,
 * shared libraries, and core dumps.
 * 
 * This type is responsible for loading, parsing, and modifying Elf files, and is used by the ARM
 * program loader to construct an executable image.
 *  
 */
#[derive(Debug)]
pub struct Elf {
    header: Header,
    sections: Vec<Section>,
    program_headers: Vec<ProgramHeader>,
}

impl Elf {
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> LoaderResult<Elf> {
        let file = std::fs::File::open(path).unwrap();
        let mut buf = std::io::BufReader::new(file);
        let elf = Elf::parse(&mut buf).unwrap();
        Ok(elf)
    }

    pub fn parse<R: Read + Seek>(reader: &mut R) -> LoaderResult<Elf> {
        let mut descriptor = Descriptor::new();

        let header = Header::parse(reader, &mut descriptor)?;

        reader.seek(SeekFrom::Start(header.shoff.as_usize() as u64))?;
        let mut sections = Vec::new();
        for _ in 0..header.shnum.0 {
            sections.push(Section::parse(reader, &mut descriptor)?)
        }

        reader.seek(SeekFrom::Start(header.phoff.as_usize() as u64))?;
        let mut program_headers = Vec::new();
        for _ in 0..header.phnum.0 {
            program_headers.push(ProgramHeader::parse(reader, &mut descriptor)?)
        }

        let parsed = Elf {
            header: header,
            sections: sections,
            program_headers: program_headers,
        };

        Ok(parsed)
    }
}
