//! Types which describe the decoded contents of an ELF file

use std::io::{ Read, Seek, SeekFrom };

use crate::{ Parslet, ParseElfResult, ParseElfError, Descriptor };
use crate::numeric::*;
use crate::constants;

/// Represents an ELF file header
/// 
/// This header is used to identify and process the rest of an Elf file, it includes offsets to
/// the program header table and the section header table
#[derive(Debug)]
pub struct ElfHeader {
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

impl ElfHeader {
    /// Returns the address of the programs entry point. This is the point where execution begins
    pub fn entry(&self) -> usize {
        self.entry.as_usize()
    }

    /// Returns the type of the ELF file
    pub fn elf_type(&self) -> ElfType {
        self.ty.clone()
    }

    /// Returns the machine target of the ELF file
    pub fn machine(&self) -> Machine {
        self.machine.clone()
    }

    /// Returns the direct offset of the program header table within an ELF file
    pub (in crate) fn program_headers_offset(&self) -> u64 {
        self.phoff.as_u64()
    }

    /// Returns the number of program headers in the program header table
    pub (in crate) fn program_header_count(&self) -> usize {
        self.phnum.as_usize()
    }

    /// Returns the direct offset of the section header table within an ELF file
    pub (in crate) fn section_headers_offset(&self) -> u64 {
        self.shoff.as_u64()
    }

    /// Returns the number of section headers in the section header table
    pub (in crate) fn section_header_count(&self) -> usize {
        self.shnum.as_usize()
    }

    /// Returns the index into the section header table of the section name string table
    /// 
    /// Not all ELF files contain a section name string table, in this case, `None` is returned
    pub (in crate) fn section_name_table_index(&self) -> Option<usize> {
        if self.shstrndx != constants::SHN_UNDEF {
            Some(self.shstrndx.as_usize())
        } else {
            None
        }
    }
}

impl Parslet for ElfHeader {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        let ident = Identifier::parse(reader, descriptor)?;

        let header = ElfHeader {
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

/// The ELF file identifier
/// 
/// This is the first piece of information decoded when reading an ELF file. It contains critical information
/// necessary for the successful parsing of the rest of the file
#[derive(Debug)]
pub struct Identifier {
    magic: Magic,
    class: DataClass,
    data: DataFormat,
    version: IdentVersion,
    os_abi: OsAbi,
    abi_ver: AbiVersion,
}

impl Parslet for Identifier {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        let parsed = Identifier {
            magic: Magic::parse(reader, descriptor)?,
            class: DataClass::parse(reader, descriptor)?,
            data: DataFormat::parse(reader, descriptor)?,
            version: IdentVersion::parse(reader, descriptor)?,
            os_abi: OsAbi::parse(reader, descriptor)?,
            abi_ver: AbiVersion::parse(reader, descriptor)?,
        };

        *descriptor = Descriptor::Data {
            class: parsed.class,
            format: parsed.data
        };

        // The end of the ident is composed of empty padding bytes, skip over them
        read_n_bytes!(reader, 7);

        Ok(parsed)
    } 
}

/// Indicates whether the file contains valid magic bytes
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Magic {
    Valid,
    Invalid,
}

impl Parslet for Magic {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        let bytes = read_n_bytes!(reader, 4);
        if bytes.as_slice() == &constants::MAGIC_BYTES[..] {
            Ok(Magic::Valid)
        } else {
            Ok(Magic::Invalid)
        }
    }
}

/// Describes the data class of an ELF file
/// 
/// This has implications on how the file is read and parsed, as it changes the size and position of certain items within the file
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DataClass {
    Elf32,
    Elf64,
}

impl Parslet for DataClass {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        use constants::data_classes::*;
        
        match read_byte!(reader) {
            ELF32 => Ok(DataClass::Elf32),
            ELF64 => Ok(DataClass::Elf64),
            v => Err(ParseElfError::InvalidDataClass(v))
        }
    }
}

/// Describes the format of data within an ELF file, either 2's complement little endian or big endian
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum DataFormat {
    LittleEndian,
    BigEndian,
}

impl Parslet for DataFormat {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        use constants::data_formats::*;

        match read_byte!(reader) {
            LITTLE_ENDIAN => Ok(DataFormat::LittleEndian),
            BIG_ENDIAN => Ok(DataFormat::BigEndian),
            v => Err(ParseElfError::InvalidDataFormat(v))
        }
    }
}

/// The ELF identifier version. There is only one version, version one
#[derive(Debug)]
pub enum IdentVersion {
    /// The current ELF version
    Current,
}

impl Parslet for IdentVersion {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        match read_byte!(reader) {
            constants::CURRENT_IDENT_VERSION => Ok(IdentVersion::Current), // Elf only has one version, version one. Nonetheless we parse it as "current"
            v => Err(ParseElfError::InvalidIdentVersion(v))
        }
    }
}

/// The OS ABI
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OsAbi {
    UnixSystemV,
}

impl Parslet for OsAbi {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        use constants::os_abis::*;
        
        match read_byte!(reader) {
            UNIX_SYSTEM_V => Ok(OsAbi::UnixSystemV),
            v => Err(ParseElfError::InvalidOsAbi(v))
        }
    }
}

/// If a specific OS ABI version is required, it will be indicated as `Specified(u8)`
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AbiVersion {
    Unspecified,
    Specified(u8),
}

impl Parslet for AbiVersion {
    fn parse<R: Read + Seek>(reader: &mut R, _: &mut Descriptor) -> ParseElfResult<Self> {
        use constants::abi_versions::*;

        match read_byte!(reader) {
            UNSPECIFIED => Ok(AbiVersion::Unspecified),
            v => Ok(AbiVersion::Specified(v))
        }
    }
}

/// The type of ELF file
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ElfType {
    #[allow(missing_docs)]
    None,

    /// The file is used for linking
    Relocatable,

    /// The file is an executable binary
    Executable,

    /// The file is used for dynamic linking
    Shared,

    /// A core file
    Core,

    /// The files purpose is defined by the host processor
    ProcessorSpecific(u16)
}

impl Parslet for ElfType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        use constants::elf_types::*;

        match read_u16!(reader, descriptor) {
            NONE => Ok(ElfType::None),
            RELOCATABLE => Ok(ElfType::Relocatable),
            EXECUTABLE => Ok(ElfType::Executable),
            SHARED => Ok(ElfType::Shared),
            CORE => Ok(ElfType::Core),

            v @ LO_PROC ..= HI_PROC => Ok(ElfType::ProcessorSpecific(v)),
            v => Err(ParseElfError::InvalidElfType(v))
        }
    }
}

/// The machine which this ELF file targets
#[allow(missing_docs)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Machine {
    None,
    AtmelAvr,
    Amd64,
    Arm,
    St200,
    RiscV,
}

impl Parslet for Machine {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        use constants::machines::*;

        match read_u16!(reader, descriptor) {
            NONE => Ok(Machine::None),
            ARM => Ok(Machine::Arm),
            ATMELAVR => Ok(Machine::AtmelAvr),
            AMD64 => Ok(Machine::Amd64),
            ST200 => Ok(Machine::St200),
            RISCV => Ok(Machine::RiscV),
            v => Err(ParseElfError::InvalidMachine(v))
        }
    }
}

/// The ELF version number. ELF only has one version, version one.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Version {
    /// The current ELF version
    Current,
}

impl Parslet for Version {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        match read_u32!(reader, descriptor) {
            constants::CURRENT_ELF_VERSION => Ok(Version::Current),
            v => Err(ParseElfError::InvalidVersion(v))
        }
    }
}

/// ELF file flags
pub struct Flags(u32);

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



/// Represents one section in a loaded Elf binary
/// 
/// This structure contains both a section header and the parsed
/// data to which that header describes
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


 
/// Describes the location and the contents of an Elf section
#[derive(Debug)]
pub struct SectionHeader {
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

impl SectionHeader {
    /// Returns a `SectionType` describing the purpose of the section
    pub fn section_type(&self) -> SectionType {
        self.ty
    }

    /// Returns the sections flags
    pub fn flags(&self) -> SectionFlags {
        self.flags
    }

    /// Returns the address at which the first byte of the section will appear in a memory image, or zero if it does not
    pub fn address(&self) -> usize {
        self.virtual_address.as_usize()
    }

    /// Returns the sections address alignment, or `None` if it does not require alignment
    pub fn alignment(&self) -> Option<usize> {
        if self.align.as_u64() <= 1u64 {
            None
        } else {
            Some(self.align.as_usize())
        }
    }

    /// If the section contains a table of fixed sized entries, this returns the size in bytes of each entry, or `None` otherwise
    pub fn entry_size(&self) -> Option<usize> {
        if self.entry_size.as_u64() == 0 {
            None
        } else {
            Some(self.entry_size.as_usize())
        }
    }
    
    /// Returns the extra info field of the section. The interpretation of this field is dependent on the sections type
    pub fn info(&self) -> usize {
        self.info.as_usize()
    }
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
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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

    #[allow(missing_docs)]
    Unknown(u32),
}

/// Describes the contents of an individual section which is used to determine how a section should be processed
impl Parslet for SectionType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        use constants::section_types::*;

        match read_u32!(reader, descriptor) {
            NULL => Ok(SectionType::Null),
            PROG_DATA => Ok(SectionType::ProgramData),
            SYM_TABLE => Ok(SectionType::SymbolTable),
            STR_TABLE => Ok(SectionType::StringTable),
            REL_A => Ok(SectionType::RelocationWithAddends),
            SYM_HASH => Ok(SectionType::SymbolHashTable),
            DYN_INFO => Ok(SectionType::DynamicInfo),
            NOTE => Ok(SectionType::Note),
            NO_BITS => Ok(SectionType::NoBits),
            RELOCATION => Ok(SectionType::Relocation),
            SHLIB => Ok(SectionType::ShLib),
            DYN_SYM_TAB => Ok(SectionType::DynamicSymbolTable),
            INIT => Ok(SectionType::InitArray),
            FINI => Ok(SectionType::FiniArray),
            PRE_INIT => Ok(SectionType::PreInitArray),
            GROUP => Ok(SectionType::Group),
            EXT_IDX => Ok(SectionType::ExtendedSectionIndices),

            v @ 0x6000_0000 ..= 0xFFFF_FFFF => Ok(SectionType::OSSpecific(v)),
            v => Ok(SectionType::Unknown(v)),
            //v => Err(ParseElfError::InvalidSectionType(v))
        }
    }
}

/// Section flags describe the allowable access patterns of an Elf section
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
        use constants::section_flags::*;
        
        // We capture flags first as a `Size` and then interpret it as
        // a u64 in order to prevent data loss, while still being able
        // to retain the `Size` variant of the original data in case
        // the flags are `ProcessorSpecific`
        let flags = Size::parse(reader, descriptor)?;
        Ok(match flags.as_u64() {
            NONE => SectionFlags::None,
            WRITE => SectionFlags::Write,
            ALLOC => SectionFlags::Alloc,
            EXEC => SectionFlags::Execute,
            WRITE_ALLOC => SectionFlags::WriteAlloc,
            WRITE_EXEC => SectionFlags::WriteExecute,
            ALLOC_EXEC => SectionFlags::AllocExecute,
            WRITE_ALLOC_EXEC => SectionFlags::WriteAllocExecute,

            _ => SectionFlags::ProcessorSpecific(flags)
        })
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

/// Represents one segment in a loaded Elf binary
/// 
/// This structure contains the program header associate with the segment, as well as a copy of the raw bytes the header describes
pub struct Segment {
    header: ProgramHeader,
    data: Vec<u8>,
}

impl Segment {
    /// Returns a reference to a vector containing the raw data of the segment
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    /// Returns a reference to the segments program header
    pub fn header(&self) -> &ProgramHeader {
        &self.header
    }
}

impl Parslet for Segment {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        let header = ProgramHeader::parse(reader, descriptor)?;
        
        /* Read segment bytes */
        let position = reader.seek(SeekFrom::Current(0)).unwrap(); // Save our position
        
        let segment_offs = header.offset.as_usize() as u64;

        let _ = reader.seek(SeekFrom::Start(segment_offs))?; // Move the readers position to the beginning of the segment
        let data = read_n_bytes!(reader, header.file_size.as_usize()); // Read the segment
        let _ = reader.seek(SeekFrom::Start(position))?; // Reset our position

        let segment = Segment {
            header,
            data
        };

        Ok(segment)
    }
}

impl std::fmt::Debug for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{:#?},", self.header)?;
        write!(f, "data: [raw]")
    }
}


/// Program headers describe segments comprised of zero or more sections which are
/// loaded into memory in order to construct a process image
#[derive(Debug)]
pub struct ProgramHeader {
    ty: ProgramHeaderType,
    flags: ProgramHeaderFlags,
    offset: Address,
    virtual_address: Address,
    physical_address: Address,
    file_size: Size,
    mem_size: Size,
    align: Size
}

impl ProgramHeader {
    /// Returns a `SectionType` describing the purpose of the section
    pub fn program_header_type(&self) -> ProgramHeaderType {
        self.ty
    }

    /// Returns the sections flags
    pub fn flags(&self) -> ProgramHeaderFlags {
        self.flags
    }

    /// Returns the sections alignment
    /// 
    /// If no alignment is required, returns `None`
    pub fn alignment(&self) -> Option<usize> {
        if self.align.as_u64() <= 1u64 {
            None
        } else {
            Some(self.align.as_usize())
        }
    }

    /// Returns the virtual address at which the first byte of the segment resides in memory
    pub fn virtual_address(&self) -> usize {
        self.virtual_address.as_usize()
    }

    /// Returns the segments physical address
    pub fn physical_address(&self) -> usize {
        self.physical_address.as_usize()
    }

    /// Returns the number of bytes the segment occupies in the file image
    pub fn file_size(&self) -> usize {
        self.file_size.as_usize()
    }

    /// Returns the number of bytes the segment occupies in the memory image
    pub fn memory_size(&self) -> usize {
        self.mem_size.as_usize()
    }
}

impl Parslet for ProgramHeader {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {

        let ty = ProgramHeaderType::parse(reader, descriptor)?;
        let mut flags = ProgramHeaderFlags::None;

        let data_class = descriptor.data_class()?;

        // If this is an Elf64 file, the program flags appear before the 'offset' value
        if data_class == DataClass::Elf64 {
            flags = ProgramHeaderFlags::parse(reader, descriptor)?;
        }
        
        let offset = Address::parse(reader, descriptor)?;
        let virtual_address = Address::parse(reader, descriptor)?;
        let physical_address = Address::parse(reader, descriptor)?;
        let file_size = Size::parse(reader, descriptor)?;
        let mem_size = Size::parse(reader, descriptor)?;

        // If this is an Elf32 file, the program flags actually appear after the 'mem_size' value
        if data_class == DataClass::Elf32 {
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

/// Describes the way in which the section pointed to by a program header is to be processed
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramHeaderType {
    Null,
    Loadable,
    DynamicInfo,
    InterpreterInfo,
    AuxiliaryInfo,
    ShLib,
    Phdr,

    // Known OS specific
    GnuStack,

    // Known processor specific
    ArmExidx,

    OSSpecific(u32),
    ProcessorSpecific(u32),
}

impl Parslet for ProgramHeaderType {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        
        use constants::os_specific_header_types::*;
        use constants::processor_specific_header_types::*;

        use ProgramHeaderType::*;
        match read_u32!(reader, descriptor) {
            0x00 => Ok(Null),
            0x01 => Ok(Loadable),
            0x02 => Ok(DynamicInfo),
            0x03 => Ok(InterpreterInfo),
            0x04 => Ok(AuxiliaryInfo),
            0x05 => Ok(ShLib),
            0x06 => Ok(Phdr),

            // Known OS specific
            GNU_STACK => Ok(GnuStack),

            // Known processor specific
            ARM_EXIDX => Ok(ArmExidx),

            v @ 0x6000_0000 ..= 0x6FFF_FFFF => Ok(ProgramHeaderType::OSSpecific(v)),
            v @ 0x7000_0000 ..= 0x7FFF_FFFF => Ok(ProgramHeaderType::ProcessorSpecific(v)),
            v => Err(ParseElfError::InvalidProgramHeader(v))
        }
    }
}

/// Flags which describe the allowable access patterns of a given section described by a `ProgramHeader`
#[allow(missing_docs)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramHeaderFlags {
    None,
    Read,
    Write,
    Execute,
    ReadWrite,
    ReadExecute,
    ReadWriteExecute,
}

impl Parslet for ProgramHeaderFlags {
    fn parse<R: Read + Seek>(reader: &mut R, descriptor: &mut Descriptor) -> ParseElfResult<Self> {
        
        use ProgramHeaderFlags::*;
        use constants::program_flags::*;

        match read_u32!(reader, descriptor) {
            READ => Ok(Read),
            WRITE => Ok(Write),
            EXEC => Ok(Execute),
            READ_WRITE => Ok(ReadWrite),
            READ_EXEC => Ok(ReadExecute),
            READ_WRITE_EXEC => Ok(ReadWriteExecute),
            v => Err(ParseElfError::InvalidProgramFlags(v))
        }
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use super::*;

    fn _load_example_binary() -> Elf {
        let elf = Elf::load("examples/example-binary").unwrap();
        elf
    }

    #[test]
    fn parse_elf_header() {
        let elf = _load_example_binary();

        let header = &elf.header;
        let ident = &header.ident;

        // Assert some known values in the test binary were parsed correctly
        assert_eq!(Magic::Valid, ident.magic);
        assert_eq!(DataClass::Elf32, ident.class);
        assert_eq!(DataFormat::LittleEndian, ident.data);
        assert_eq!(OsAbi::UnixSystemV, ident.os_abi);
        assert_eq!(AbiVersion::Unspecified, ident.abi_ver);

        assert_eq!(ElfType::Executable, header.ty);
        assert_eq!(Machine::Arm, header.machine);
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
    fn try_get_section() {
        let elf = _load_example_binary();
        let text = elf.try_get_section(".text").unwrap();

        assert_eq!(SectionFlags::AllocExecute, text.header.flags);
    }

    #[test]
    fn try_get_fake_section() {
        let elf = _load_example_binary();        

        // We know before hand that this section does not exist in the example binary
        assert!(elf.try_get_section(".aaaabbbbcccc").is_none());
        assert!(elf.try_get_section("_aaaabbbbcccc").is_none());
        assert!(elf.try_get_section("aaaabbbbcccc").is_none());
    }
}
