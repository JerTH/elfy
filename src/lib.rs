#![warn(missing_docs)]

//! A crate for reading data from ELF files quickly and simply
//! 
//! Currently Elfy is focused on reading data important to statically compiled ARM executables, in the future it will support more architectures
//! and ELF features

use std::io::{ Read, Seek, SeekFrom };
use std::collections::HashMap;

mod error;
use crate::error::ParseElfError;

#[macro_use]
mod macros;

mod constants;
use crate::constants::*;

mod primitives;
use crate::primitives::*;

/// Represents an ELF file header
/// 
/// This header is used to identify and process the rest of an Elf file, it includes offsets to
/// the program header table and the section header table
#[derive(Debug)]
pub struct Header {
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
            Class::Elf32 => DataClass::Elf32,
            Class::Elf64 => DataClass::Elf64,
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

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum Class {
    Elf32,
    Elf64,
    Invalid(u8)
}

impl Parslet for Class {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        match read_byte!(reader) {
            0x01 => Ok(Class::Elf32),
            0x02 => Ok(Class::Elf64),
            b => Ok(Class::Invalid(b))
        }
    }
}

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

#[derive(Debug, PartialEq, Eq, Clone)]
enum OsAbi {
    UnixSystemV,
    Invalid(u8)
}

impl Parslet for OsAbi {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        match read_byte!(reader) {
            0x00 => Ok(OsAbi::UnixSystemV),
            b => Ok(OsAbi::Invalid(b))
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[derive(Debug, PartialEq, Eq, Clone)]
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

#[derive(Debug, PartialEq, Eq, Clone)]
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


#[derive(Debug, PartialEq, Eq, Clone)]
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
 * This structure contains both a sections as well as the parsed data which that header points to
 */
#[derive(Debug)]
pub struct Section {
    header: SectionHeader,
    data: SectionData,
}

impl Section {
    /// Returns a reference to a 'SectionData' instance which contains the parsed data contained by the section
    pub fn data(&self) -> &SectionData {
        &self.data
    }

    /// Returns a reference to the sections header
    pub fn header(&self) -> &SectionHeader {
        &self.header
    }
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


 
/// A 'SectionHeader' describes the location and the contents of an Elf section
#[derive(Debug)]
pub struct SectionHeader {
    name_index: Size,

    /// Describes the type of information contained within a section
    pub ty: SectionType,

    /// The flags used to mark this section
    pub flags: SectionFlags,

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

/// Describes the type of information contained within a section
#[derive(Debug, PartialEq, Eq)]
pub enum SectionType {
    /// Marks a section as inactive
    /// 
    /// Section headers with the type 'Null' do not have a corresponding section in the file
    Null,

    /// Marks a section as containing data whose meaning is defined entirely by the program
    ProgramData,

    /// Marks a section as containing a symbol table
    SymbolTable,

    /// Marks a section as containing a string table, there may be multiple string tables in a given ELF file
    StringTable,

    /// Marks a section as containing relocation data with explicit addends
    RelocationWithAddends,

    /// Marks a section as containing a symbol hash table
    SymbolHashTable,

    /// Marks a section as containing information for dynamic linking
    DynamicInfo,

    /// Marks a section as containing arbitrary information used to mark the section in some way
    /// 
    /// This information is usually generated by some part of the toolchain used to produce the ELF file
    Note,

    /// Marks a section as containing no data, but otherwise resembles a 'ProgramData' section
    NoBits,

    /// Marks a section as containing relocation data without explicit addends
    Relocation,

    /// This section type is reserved and should not be used. ELF files which contain a section of this type do not conform to the ABI
    ShLib,

    /// Marks a section as containing a minimal symbol table used for dynamic linking
    DynamicSymbolTable,

    /// Marks a section as containing constructors
    InitArray,

    /// Marks a section as containing destructors
    FiniArray,

    /// Marks a section as containing pre-constructors
    PreInitArray,

    #[allow(missing_docs)]
    Group,
    #[allow(missing_docs)]
    ExtendedSectionIndices,

    /// Section contains information defined by and specific to the operating system
    OSSpecific(u32),
}

/// Describes the contents of an individual section which is used to determine how a section should be processed
impl Parslet for SectionType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {

        use SectionType::*;
        use constants::section_types::*;

        match read_u32!(reader, descriptor) {
            NULL => Ok(Null),
            PROG_DATA => Ok(ProgramData),
            SYM_TABLE => Ok(SymbolTable),
            STR_TABLE => Ok(StringTable),
            REL_A => Ok(RelocationWithAddends),
            SYM_HASH => Ok(SymbolHashTable),
            DYN_INFO => Ok(DynamicInfo),
            NOTE => Ok(Note),
            NO_BITS => Ok(NoBits),
            RELOCATION => Ok(Relocation),
            SHLIB => Ok(ShLib),
            DYN_SYM_TAB => Ok(DynamicSymbolTable),
            INIT => Ok(InitArray),
            FINI => Ok(FiniArray),
            PRE_INIT => Ok(PreInitArray),
            GROUP => Ok(Group),
            EXT_IDX => Ok(ExtendedSectionIndices),

            v @ 0x6000_0000 ..= 0xFFFF_FFFF => Ok(SectionType::OSSpecific(v)),
            v => Err(ParseElfError::InvalidSectionType{ section_type: v })
        }
    }
}

/// Section flags describe the allowable access patterns of an Elf section
#[derive(Debug, PartialEq, Eq)]
pub enum SectionFlags {
    /// No section flags
    None,

    /// Section is writable at runtime
    Write,
    
    /// Section occupies space in memory at runtime
    Alloc,
    
    /// Section contains executable code
    Execute,

    #[allow(missing_docs)]    
    WriteAlloc,
    #[allow(missing_docs)]    
    WriteExecute,
    #[allow(missing_docs)]    
    AllocExecute,
    #[allow(missing_docs)]    
    WriteAllocExecute,

    /// Flags with meaning defined by the target processor
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

/// Represents the parsed data contained in one section
#[derive(Debug)]
pub enum SectionData {
    /// Section contains no data
    Null,

    /// Section contains binary data, such as executable code
    Bytes(Vec<u8>),

    /// Section contains null-terminated Utf8 strings
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
        
        // If this is an Elf64 file, the program flags appear before the 'offset' value
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

        // If this is an Elf32 file, the program flags actually appear after the 'mem_size' value
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
    /// Loads an ELF file from disk and parses it
    /// 
    /// # Errors
    /// 
    /// Returns 'Err' if the file can not be loaded or if parsing fails, with a description of the failure
    /// 
    /// # Examples
    /// ```
    /// # use crate::elfy::*;    
    /// let elf = Elf::load("examples/example-binary").unwrap();
    /// ```
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> ParseElfResult<Elf> {
        let file = std::fs::File::open(path)?;
        let mut buf = std::io::BufReader::new(file);
        let elf = Elf::parse(&mut buf)?;
        Ok(elf)
    }

    /// Parses an ELF file from a reader source
    /// 
    /// 'reader' can be anything that implements both 'Read' and 'Seek'
    /// 
    /// # Errors
    /// 
    /// Returns 'Err' if parsing fails, with a description of what caused the failure
    /// 
    /// # Examples
    /// ```
    /// # use crate::elfy::*;    
    /// # let file = std::fs::File::open("examples/example-binary").unwrap();
    /// let mut buf = std::io::BufReader::new(file);
    /// let elf = Elf::parse(&mut buf).unwrap();
    /// ```
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

    /// Tries to retrieve a section by name, returns 'None' if the section does not exist
    /// 
    /// # Examples
    /// ```
    /// # use crate::elfy::*;
    /// 
    /// let elf = Elf::load("examples/example-binary").unwrap();
    /// let text = elf.try_get_section(".text").unwrap();
    /// 
    /// assert_eq!(SectionFlags::AllocExecute, text.header().flags);
    /// ```
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

    fn load_example_binary() -> Elf {
        let elf = Elf::load("examples/example-binary").unwrap();
        elf
    }

    #[test]
    fn test_parse_elf_header() {
        let elf = load_example_binary();

        let header = &elf.header;
        let ident = &header.ident;
        assert_eq!(Magic::Valid, ident.magic);
        assert_eq!(Class::Elf32, ident.class);
        assert_eq!(ELFData::LittleEndian, ident.data);
        assert_eq!(OsAbi::UnixSystemV, ident.os_abi);
        assert_eq!(AbiVersion::Unspecified, ident.abi_ver);

        assert_eq!(ElfType::Executable, header.ty);
        assert_eq!(Machine::ARM, header.machine);
        assert_eq!(Version::Current, header.version);
        assert_eq!(Address::Elf32Addr(0x11001), header.entry);
        assert_eq!(Size::Elf32Size(52), header.phoff);
        assert_eq!(Size::Elf32Size(8428), header.shoff);
        // TODO: Test flags (Flags type should be rewritten as a more descriptive enum)
        assert_eq!(Short(52), header.ehsize);
        assert_eq!(Short(32), header.phentsize);
        assert_eq!(Short(5), header.phnum);
        assert_eq!(Short(40), header.shentsize);
        assert_eq!(Short(8), header.shnum);
        assert_eq!(Short(6), header.shstrndx);
    }

    #[test]
    fn test_try_get_section() {
        let elf = load_example_binary();
        let text = elf.try_get_section(".text").unwrap();

        assert_eq!(SectionFlags::AllocExecute, text.header.flags);
    }

    #[test]
    fn test_try_get_fake_section() {
        let elf = load_example_binary();        

        // We can be reasonably certain that no section with this name exists
        assert!(elf.try_get_section(".j482a0nflanakfg10enalnflasifbansnfalbf").is_none());
        assert!(elf.try_get_section("_j482a0nflanakfg10enalnflasifbansnfalbf").is_none());
        assert!(elf.try_get_section("j482a0nflanakfg10enalnflasifbansnfalbf").is_none());
    }

    #[test]
    fn test_get_bytes_data() {
        let elf = load_example_binary();        
        let text = elf.try_get_section(".text").unwrap();
        
        if let SectionData::Bytes(bytes) = text.data() {
            // do something with bytes
        }
    }
}
