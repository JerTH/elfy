use std::io::{ Read, Seek, SeekFrom };
use std::collections::HashMap;
use std::fmt::Display;

mod error;

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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        let ident = Identifier::parse(reader, descriptor)?;

        let header = Header {
            ident,
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
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
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        let bytes = read_n_bytes!(reader, 4);
        if bytes.as_slice() == &MAGIC_BYTES[..] {
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
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
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
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
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
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
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
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
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
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        match read_u16!(reader, descriptor) {
            MACHINE_NONE => Ok(Machine::None),
            MACHINE_ARM => Ok(Machine::ARM),
            MACHINE_ATMELAVR => Ok(Machine::AtmelAVR),
            MACHINE_AMD64 => Ok(Machine::AMD64),
            MACHINE_ST200 => Ok(Machine::ST200),
            MACHINE_RISCV => Ok(Machine::RISCV),
            v => Ok(Machine::Invalid(v))
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
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
pub struct Section {
    header: SectionHeader,
    data: SectionData,
}

impl Section {
}

impl Parslet for Section {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        let header = SectionHeader::parse(reader, descriptor)?;
        let data = SectionData::parse_as(reader, &descriptor, &header)?;

        let section = Section {
            header,
            data
        };

        Ok(section)
    }
}

impl Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.header)?;
        write!(f, "{:?}", self.data)
    }
}

/**
 * A section header describes the location as well as the contents of an Elf section
 * 
 * Elf sections are parsed and represented by the Section structure 
 */
#[derive(Debug)]
struct SectionHeader {
    name_index: Size,
    ty: SectionType,
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        let section_header = SectionHeader {
            name_index: Size::parse(reader, descriptor)?,
            ty: SectionType::parse(reader, descriptor)?,
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
enum SectionType {
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
impl Parslet for SectionType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {

        use SectionType::*;
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

            v @ 0x6000_0000 ..= 0xFFFF_FFFF => Ok(SectionType::OSSpecific(v)),
            v => Ok(SectionType::Invalid(v))
        }
    }
}

/**
 * Section flags describe the allowable access patterns of an Elf section
 */
#[derive(Debug, PartialEq, Eq)]
enum SectionFlags {
    None,
    Write,
    Alloc,
    Execute,
    WriteAlloc,
    WriteExecute,
    AllocExecute,
    WriteAllocExecute,
    ProcessorSpecific(Size),
}

impl Parslet for SectionFlags {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        let flags = Size::parse(reader, descriptor)?;
        
        use SectionFlags::*;
        let section_flags = match flags.as_usize() {
            0b000 => None,
            0b001 => Write,
            0b010 => Alloc,
            0b100 => Execute,
            0b011 => WriteAlloc,
            0b101 => WriteExecute,
            0b110 => AllocExecute,
            0b111 => WriteAllocExecute,
            _ => ProcessorSpecific(flags)
        };
        Ok(section_flags)
    }
}

/**
 * Represents the parsed data contained in one section
 */
#[derive(Debug)]
enum SectionData {
    Null,
    Bytes(Vec<u8>),
    Strings(Vec<String>),
}

impl SectionData {
    fn parse_as<R: Read + Seek>(reader: &mut R, _descriptor: &Descriptor, header: &SectionHeader) -> ParseElfResult<SectionData> {
        let position = reader.seek(SeekFrom::Current(0)).unwrap(); // Save our position as it may change to read a section
        
        let section_offs = header.offset.as_usize() as u64;
        let _ = reader.seek(SeekFrom::Start(section_offs))?; // Move the readers position to the beginning of the section
        
        // Read the raw bytes of the section
        let bytes = read_n_bytes!(reader, header.section_size.as_usize());
        
        let data = match header.ty {
            SectionType::Null => {
                SectionData::Null
            },

            // Program data is preserved as raw binary data, its meaning is defined by the consuming system
            SectionType::ProgramData => {
                SectionData::Bytes(bytes)
            },
        
            // Parse string tables as actual vectors of String
            SectionType::StringTable => {
                let splits = bytes.split(|c| *c == (b'\0') ); 
                
                let mut strings: Vec<String> = Vec::new();
                for slice in splits {
                    let result = String::from_utf8(slice.to_vec());
                    strings.push(result.unwrap());
                }
                SectionData::Strings(strings)
            },

            _ => {
                SectionData::Bytes(bytes)
            },
        };

        let _ = reader.seek(SeekFrom::Start(position))?; // Reset the readers position
        Ok(data)
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {

        
        let ty = ProgramHeaderType::parse(reader, descriptor)?;
        
        // If this is an ELF64 file, the program flags appear before the 'offset' value
        let mut flags = if descriptor.is_elf64() {
            ProgramHeaderFlags::parse(reader, descriptor)?
        } else {
            ProgramHeaderFlags::Invalid(0)
        };
        
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        
        use ProgramHeaderType::*;
        match read_u32!(reader, descriptor) {
            0x00 => Ok(Null),
            0x01 => Ok(Loadable),
            0x02 => Ok(DynamicInfo),
            0x03 => Ok(InterpreterInfo),
            0x04 => Ok(AuxiliaryInfo),
            0x05 => Ok(ShLib),
            0x06 => Ok(PHDR),

            v @ 0x6000_0000 ..= 0x6FFF_FFFF => Ok(ProgramHeaderType::OSSpecific(v)),
            v @ 0x7000_0000 ..= 0x7FFF_FFFF => Ok(ProgramHeaderType::ProcessorSpecific(v)),
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
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        
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
 * Represents a parsed ELF (Executable and Linkable Format) file.
 * 
 * The ELF format is a common standard file format for executable files, object code,
 * shared libraries, and core dumps.
 */
#[derive(Debug)]
pub struct Elf {
    header: Header,
    sections: Vec<Section>,
    program_headers: Vec<ProgramHeader>,
    section_map: HashMap<String, usize>,
}

impl Elf {
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> ParseElfResult<Elf> {
        let file = std::fs::File::open(path)?;
        let mut buf = std::io::BufReader::new(file);
        let elf = Elf::parse(&mut buf)?;
        Ok(elf)
    }

    pub fn parse<R: Read + Seek>(reader: &mut R) -> ParseElfResult<Elf> {
        let mut descriptor = Descriptor::new();

        let header = Header::parse(reader, &mut descriptor)?;
        let sections = parse_sections(reader, &mut descriptor, &header)?;
        let program_headers = parse_program_headers(reader, &mut descriptor, &header)?;
        let mut section_map = HashMap::new();

        associate_string_table(&mut section_map, &sections, &header);

        let parsed = Elf { header, sections, program_headers, section_map };

        Ok(parsed)
    }

    pub fn try_get_section(&self, section_name: &str) -> Option<&Section> {
        self.sections.get(*self.section_map.get(section_name)?)
    }    
}


fn parse_sections<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor, header: &Header) -> ParseElfResult<Vec<Section>> {
    reader.seek(SeekFrom::Start(header.shoff.as_u64()))?;
    let mut sections = Vec::new();
    for _ in 0..header.shnum.0 {
        sections.push(Section::parse(reader, descriptor)?)
    }
    Ok(sections)
}


fn parse_program_headers<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor, header: &Header) -> ParseElfResult<Vec<ProgramHeader>> {
    reader.seek(SeekFrom::Start(header.phoff.as_u64()))?;
    let mut program_headers = Vec::new();
    for _ in 0..header.phnum.0 {
        program_headers.push(ProgramHeader::parse(reader, descriptor)?)
    }
    Ok(program_headers)
}


fn associate_string_table(section_map: &mut HashMap<String, usize>, sections: &[Section], header: &Header) {
    if header.shstrndx != SHN_UNDEF {
        if let SectionData::Strings(table) = &sections[header.shstrndx.as_usize()].data {
            for (i, _section) in sections.iter().enumerate() {
                let name = table[i].clone();
                section_map.insert(name, i);
            }
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_try_get_section() {
        let elf = Elf::load("examples/thumbv7m-binary-0").unwrap();
        let text = elf.try_get_section(".text").unwrap();

        assert_eq!(SectionFlags::AllocExecute, text.header.flags);

        println!("{:#?}", elf);
    }
}
